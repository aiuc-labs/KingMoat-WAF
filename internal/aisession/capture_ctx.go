package aisession

// Request/response capture wiring helpers. The proxy side-channel stores a
// *CaptureCtx in the request context before forwarding; ModifyResponse picks
// it up and (for identified sessions) wraps or taps the response body, then
// finalizes the record into the async queue.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// CaptureCtx carries one identified LLM transaction across the request →
// response hop via the request context.
const streamHangTimeout = 15 * time.Minute

type CaptureCtx struct {
	rec        *Record
	reqPayload RequestPayload
	finalOnce  sync.Once
	hangTimer  *time.Timer
	reqBytes   int64
	truncIn    bool
	start      time.Time
	maxResp    int
	redact     bool
	stream     bool
	agg        bytes.Buffer // SSE/JSON-array aggregation buffer
	aggOpen    bool
	truncOut   bool
	pipeline   *Pipeline
}

// CaptureRequest identifies the request and (on hit) builds the capture
// context. Returns nil when the AI-audit pipeline is off or the request does
// not match the protocol matrix.
func (p *Pipeline) CaptureRequest(rc *pipeline.RequestContext, r *http.Request, site, traceID string) *CaptureCtx {
	cfg := p.cfg.Load()
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	var body []byte
	if rc != nil {
		body = rc.Body
	}
	m, ok := Identify(r.Method, r.URL.Path, body, cfg.IncludeEmbeddings, cfg.IncludeUnknown)
	if !ok {
		return nil
	}
	maxIn := cfg.MaxRequestBytesOrDefault()
	rec := &Record{
		TS:        time.Now().UTC().Format(time.RFC3339Nano),
		TraceID:   traceID,
		Site:      site,
		ClientIP:  clientIPOf(r),
		NodeID:    p.nodeID,
		Method:    r.Method,
		Path:      r.URL.Path,
		URL:       r.Host + r.URL.RequestURI(),
		UserAgent: r.UserAgent(),
		Provider:  m.Provider,
		Operation: m.Operation,
		Model:     m.Model,
		Stream:    m.Stream,
		ReqBytes:  int64(len(body)),
	}
	cc := &CaptureCtx{
		rec:      rec,
		reqBytes: int64(len(body)),
		truncIn:  body == nil, // unbuffered = content not captured
		start:    time.Now(),
		maxResp:  cfg.MaxResponseBytesOrDefault(),
		redact:   cfg.RedactContentOrDefault(),
		stream:   m.Stream,
		pipeline: p,
	}
	if len(body) > 0 {
		cc.reqPayload = NormalizeRequest(m.Provider, m.Operation, body, maxIn)
		if len(body) > maxIn {
			cc.truncIn = true
		}
	} else {
		cc.truncIn = true
	}
	if cfg.SamplePctOrDefault() < 100 {
		// deterministic sampling on the same counter semantics as accesslog
		// (per-pipeline counter, no lock needed for audit-grade fairness)
		if n := p.sampleCtr.Add(1); int(n%100) >= cfg.SamplePctOrDefault() {
			return nil
		}
	}
	// Hang guard: a stalled upstream (or a client that never drains a stream)
	// would otherwise hold the record forever; finalize as interrupted after
	// the grace window. Normal completions race-safe no-op via finalOnce.
	cc.hangTimer = time.AfterFunc(streamHangTimeout, func() { p.finalize(cc, true) })
	return cc
}

// HandleResponse taps the upstream response for an identified session. It
// returns the (possibly body-wrapped) response; callers must assign it back
// so the modified body reaches the client.
func (p *Pipeline) HandleResponse(resp *http.Response, cc *CaptureCtx) *http.Response {
	if cc == nil {
		return resp
	}
	cc.rec.Status = resp.StatusCode
	ct := resp.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	cc.rec.RespBytes = resp.ContentLength
	if resp.StatusCode >= 400 {
		// upstream error: the JSON error body still flows through the tee
		// path below (error.message is audit-relevant); just flag it.
		cc.rec.Err = "upstream status " + http.StatusText(resp.StatusCode)
	}
	isSSE := ct == "text/event-stream"
	if isSSE {
		// stream semantics follow the actual response: some providers signal
		// streaming via headers only (DashScope X-DashScope-SSE) so the body
		// prediction in Identify may be false — flip it for parsing.
		cc.stream = true
	}
	isJSON := ct == "application/json" || strings.HasSuffix(ct, "+json")
	// A compressed body (gzip/br/...) cannot be parsed into text — do not
	// tee compressed bytes into response.text (would store garbage); record
	// metadata only and finalize immediately.
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		cc.rec.Err = "response compressed (" + enc + "); content not captured"
		p.finalize(cc, false)
		return resp
	}
	if !isSSE && !isJSON {
		p.finalize(cc, false)
		return resp
	}
	if !isSSE {
		// non-streaming: wrap the body to tee bytes while forwarding
		resp.Body = &teeBody{
			ctx:   cc,
			src:   resp.Body,
			pipe:  p,
			limit: cc.maxResp,
		}
		return resp
	}
	// streaming: swap in an SSE-aware body that forwards chunks verbatim and
	// feeds the aggregator; EOF finalizes the record.
	resp.Body = &sseBody{
		ctx:   cc,
		src:   resp.Body,
		pipe:  p,
		limit: cc.maxResp,
		sc:    bufio.NewScanner(resp.Body),
	}
	resp.Body.(*sseBody).sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return resp
}

// finalize assembles and enqueues the record (idempotent per CaptureCtx).
func (p *Pipeline) finalize(cc *CaptureCtx, interrupted bool) {
	cc.finalOnce.Do(func() {
		if cc.hangTimer != nil {
			cc.hangTimer.Stop()
		}
		cc.rec.DurationMS = time.Since(cc.start).Milliseconds()
		cc.rec.Interrupted = interrupted
		cc.rec.TruncIn = cc.truncIn
		cc.rec.TruncOut = cc.truncOut
		if cc.stream {
			cc.rec.Stream = true
		}
		cc.rec.Request = cc.reqPayload
		if cc.agg.Len() > 0 {
			text, usage := parseAggregated(cc.rec.Provider, cc.agg.Bytes(), cc.stream)
			if text == "" && cc.stream {
				// identified as stream but the upstream answered non-streamed
				// (proxy stripped SSE, error JSON, ...): fall back so the
				// model output is still captured for the audit trail.
				text, usage = parseNonStream(cc.rec.Provider, cc.agg.Bytes())
			}
			cc.rec.Response.Text = text
			cc.rec.Usage = usage
			if cc.truncOut {
				cc.rec.TruncOut = true
			}
		}
		if cc.redact {
			SanitizeRecord(cc.rec)
		}
		if cc.rec.ID == "" {
			cc.rec.ID = newID()
		}
		p.Enqueue(*cc.rec)
	})
}

// teeBody tees a non-streaming response body: forwards bytes to the client
// unchanged while aggregating up to the cap; EOF finalizes.
type teeBody struct {
	ctx    *CaptureCtx
	src    io.ReadCloser
	pipe   *Pipeline
	limit  int
	closed bool
}

func (t *teeBody) Read(b []byte) (int, error) {
	n, err := t.src.Read(b)
	if n > 0 {
		ctx := t.ctx
		room := t.limit - ctx.agg.Len()
		if room > 0 {
			w := n
			if w > room {
				w = room
				ctx.truncOut = true
			}
			ctx.agg.Write(b[:w])
		} else if n > 0 {
			ctx.truncOut = true
		}
	}
	if err == io.EOF {
		t.pipe.finalize(t.ctx, false)
	}
	return n, err
}

func (t *teeBody) Close() error {
	t.pipe.finalize(t.ctx, false)
	if !t.closed {
		t.closed = true
		return t.src.Close()
	}
	return nil
}

// sseBody forwards an SSE stream line by line (flush behavior preserved by
// the reverse proxy) while feeding the aggregator; scanner EOF finalizes.
// The remainder buffer keeps the un-consumed tail of the current line so
// Read honors the io.Reader contract when the caller's buffer is smaller
// than one SSE line (otherwise the reverse proxy would corrupt the stream).
type sseBody struct {
	ctx       *CaptureCtx
	src       io.ReadCloser
	pipe      *Pipeline
	limit     int
	sc        *bufio.Scanner
	remainder []byte
	done      bool
}

func (s *sseBody) Read(b []byte) (int, error) {
	if len(s.remainder) > 0 {
		n := copy(b, s.remainder)
		s.remainder = s.remainder[n:]
		return n, nil
	}
	if s.done {
		return 0, io.EOF
	}
	if !s.sc.Scan() {
		s.done = true
		err := s.sc.Err()
		s.pipe.finalize(s.ctx, err != nil && err != io.EOF)
		if err == nil {
			return 0, io.EOF
		}
		return 0, err
	}
	line := s.sc.Text() + "\n"
	s.pipe.feedSSE(s.ctx, line)
	if int64(s.ctx.agg.Len()) > int64(s.limit) {
		s.ctx.truncOut = true
	}
	n := copy(b, line)
	if n < len(line) {
		s.remainder = []byte(line[n:])
	}
	return n, nil
}

func (s *sseBody) Close() error {
	if !s.done {
		s.done = true
		s.pipe.finalize(s.ctx, true)
	}
	return s.src.Close()
}

// feedSSE ingests one SSE line into the aggregation buffer (openai-shaped
// data lines by default; anthropic/gemini handled by parseAggregated).
func (p *Pipeline) feedSSE(cc *CaptureCtx, line string) {
	trimmed := strings.TrimRight(line, "\n")
	if trimmed == "" || strings.HasPrefix(trimmed, ":") {
		return // keep-alive comment
	}
	if strings.HasPrefix(trimmed, "data:") {
		payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
		if payload == "[DONE]" {
			return
		}
		if cc.agg.Len() < cc.maxResp {
			cc.agg.WriteString(payload)
			cc.agg.WriteByte('\n')
		} else {
			cc.truncOut = true
		}
	}
	// event: lines are folded into the data payload handling in parseAggregated
	_ = trimmed
}

// parseAggregated extracts the model output text and usage from the
// aggregated stream/JSON payload per provider.
func parseAggregated(provider string, agg []byte, streamed bool) (string, *Usage) {
	if !streamed {
		return parseNonStream(provider, agg)
	}
	var b strings.Builder
	var usage *Usage
	lines := strings.Split(string(agg), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var frame map[string]any
		if err := json.Unmarshal([]byte(line), &frame); err != nil {
			continue
		}
		switch provider {
		case "openai":
			if ch, ok := frame["choices"].([]any); ok && len(ch) > 0 {
				if c, ok := ch[0].(map[string]any); ok {
					if d, ok := c["delta"].(map[string]any); ok {
						if txt, ok := d["content"].(string); ok {
							b.WriteString(txt)
						}
					}
				}
			}
			if u := usageFrom(frame["usage"]); u != nil {
				usage = u
			}
		case "anthropic":
			if frame["type"] == "content_block_delta" {
				if d, ok := frame["delta"].(map[string]any); ok {
					if txt, ok := d["text"].(string); ok {
						b.WriteString(txt)
					}
				}
			}
			if u := usageFrom(frame["usage"]); u != nil {
				usage = u
			}
		case "gemini":
			if cands, ok := frame["candidates"].([]any); ok && len(cands) > 0 {
				if c, ok := cands[0].(map[string]any); ok {
					if cont, ok := c["content"].(map[string]any); ok {
						b.WriteString(partsText(cont["parts"], 1<<20))
					}
				}
			}
			if u := usageFrom(frame["usageMetadata"]); u != nil {
				usage = u
			}
		case "baidu":
			// ERNIE stream frames carry the incremental text in "result";
			// there is no [DONE] sentinel (is_end marks the final frame).
			if txt, ok := frame["result"].(string); ok {
				b.WriteString(txt)
			}
			if u := usageFrom(frame["usage"]); u != nil {
				usage = u
			}
		case "dashscope":
			// message format: output.choices[0].delta.text (omni, incremental);
			// result_format=message frames carry output.choices[0].message.content:
			// incremental_output=true appends deltas, false/absent resends the
			// cumulative text each frame (detected by prefix and replaced).
			// text format: output.text.
			if out, ok := frame["output"].(map[string]any); ok {
				if ch, ok := out["choices"].([]any); ok && len(ch) > 0 {
					if c, ok := ch[0].(map[string]any); ok {
						wrote := false
						if d, ok := c["delta"].(map[string]any); ok {
							if txt, ok := d["text"].(string); ok {
								b.WriteString(txt)
								wrote = true
							}
						}
						if !wrote {
							if m, ok := c["message"].(map[string]any); ok {
								if content, ok := m["content"].(string); ok && content != "" {
									cur := b.String()
									if len(content) > len(cur) && strings.HasPrefix(content, cur) {
										// cumulative frame: replay of the full text
										b.Reset()
										b.WriteString(content)
									} else if !strings.HasPrefix(cur, content) {
										// true incremental delta fragment
										b.WriteString(content)
									}
									// else: stale/duplicate cumulative frame — ignore
								}
							}
						}
					}
				}
				if txt, ok := out["text"].(string); ok {
					b.WriteString(txt)
				}
			}
			if u := usageFrom(frame["usage"]); u != nil {
				usage = u
			}
		case "sensenova":
			// native stream frames: choices[0].delta is a plain string
			if ch, ok := frame["choices"].([]any); ok && len(ch) > 0 {
				if c, ok := ch[0].(map[string]any); ok {
					if txt, ok := c["delta"].(string); ok {
						b.WriteString(txt)
					}
				}
			}
			if u := usageFrom(frame["usage"]); u != nil {
				usage = u
			}
		case "minimax":
			// openai-shaped stream frames (choices[0].delta.content) plus a
			// base_resp status envelope that carries no content
			if ch, ok := frame["choices"].([]any); ok && len(ch) > 0 {
				if c, ok := ch[0].(map[string]any); ok {
					if d, ok := c["delta"].(map[string]any); ok {
						if txt, ok := d["content"].(string); ok {
							b.WriteString(txt)
						}
					}
				}
			}
			if u := usageFrom(frame["usage"]); u != nil {
				usage = u
			}
		}
	}
	return b.String(), usage
}

func parseNonStream(provider string, agg []byte) (string, *Usage) {
	var frame map[string]any
	if err := json.Unmarshal(agg, &frame); err != nil {
		return truncate(string(agg), 4096), nil
	}
	switch provider {
	case "openai":
		if ch, ok := frame["choices"].([]any); ok && len(ch) > 0 {
			if c, ok := ch[0].(map[string]any); ok {
				if msg, ok := c["message"].(map[string]any); ok {
					if txt, ok := msg["content"].(string); ok {
						return txt, usageFrom(frame["usage"])
					}
				}
			}
		}
	case "anthropic":
		if content, ok := frame["content"].([]any); ok {
			var b strings.Builder
			for _, blk := range content {
				if bm, ok := blk.(map[string]any); ok {
					if txt, ok := bm["text"].(string); ok {
						b.WriteString(txt)
					}
				}
			}
			return b.String(), usageFrom(frame["usage"])
		}
	case "gemini":
		if cands, ok := frame["candidates"].([]any); ok && len(cands) > 0 {
			if c, ok := cands[0].(map[string]any); ok {
				if cont, ok := c["content"].(map[string]any); ok {
					return partsText(cont["parts"], 1<<20), usageFrom(frame["usageMetadata"])
				}
			}
		}
	case "baidu":
		if txt, ok := frame["result"].(string); ok {
			return txt, usageFrom(frame["usage"])
		}
	case "dashscope":
		// message format: output.choices[0].message.content; text format: output.text
		if out, ok := frame["output"].(map[string]any); ok {
			if ch, ok := out["choices"].([]any); ok && len(ch) > 0 {
				if c, ok := ch[0].(map[string]any); ok {
					if msg, ok := c["message"].(map[string]any); ok {
						if txt, ok := msg["content"].(string); ok {
							return txt, usageFrom(frame["usage"])
						}
					}
				}
			}
			if txt, ok := out["text"].(string); ok {
				return txt, usageFrom(frame["usage"])
			}
		}
	case "minimax":
		if ch, ok := frame["choices"].([]any); ok && len(ch) > 0 {
			if c, ok := ch[0].(map[string]any); ok {
				if msg, ok := c["message"].(map[string]any); ok {
					if txt, ok := msg["content"].(string); ok {
						return txt, usageFrom(frame["usage"])
					}
				}
			}
		}
	case "sensenova":
		// native shape: choices[0].message is a plain string
		if ch, ok := frame["choices"].([]any); ok && len(ch) > 0 {
			if c, ok := ch[0].(map[string]any); ok {
				if txt, ok := c["message"].(string); ok {
					return txt, usageFrom(frame["usage"])
				}
			}
		}
	}
	if txt, ok := frame["text"].(string); ok {
		return txt, usageFrom(frame["usage"])
	}
	return "", nil
}

func usageFrom(v any) *Usage {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	u := &Usage{}
	u.PromptTokens = intOf(m["prompt_tokens"], m["input_token_count"], m["input_tokens"], m["promptTokenCount"])
	u.CompletionTokens = intOf(m["completion_tokens"], m["output_token_count"], m["output_tokens"], m["candidatesTokenCount"])
	u.TotalTokens = intOf(m["total_tokens"], m["totalTokenCount"])
	if u.PromptTokens == 0 && u.CompletionTokens == 0 && u.TotalTokens == 0 {
		return nil
	}
	return u
}

func intOf(vals ...any) int {
	for _, v := range vals {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return 0
}

func clientIPOf(r *http.Request) string {
	if ip := pipeline.ClientIPFromContext(r.Context()); ip != nil {
		return ip.String()
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}
