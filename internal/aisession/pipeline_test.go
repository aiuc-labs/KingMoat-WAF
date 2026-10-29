package aisession

// Unit tests for the node-side pipeline (queue/ring/drop) and the request/
// response capture path (normalize, sanitize, tee + SSE aggregation).

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

func testCfg() *config.AIAuditSettings {
	return &config.AIAuditSettings{Enabled: true, MaxRequestBytes: 0, MaxResponseBytes: 0}
}

func TestPipelineEnqueueFanout(t *testing.T) {
	p := NewPipeline("node-1", testCfg(), 4)
	defer p.Close()
	var got []Record
	var mu sync.Mutex
	p.SetSink(sinkFunc(func(r Record) {
		mu.Lock()
		got = append(got, r)
		mu.Unlock()
	}))
	for i := 0; i < 10; i++ {
		p.Enqueue(Record{ID: "r", TraceID: string(rune('a' + i))})
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 10 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 10 {
		t.Fatalf("fanout got %d records, want 10", len(got))
	}
	if p.Dropped() != 0 {
		t.Fatalf("dropped = %d, want 0", p.Dropped())
	}
	if c := p.Ring().Count(); c != 4 {
		t.Fatalf("ring count = %d, want 4 (ring capacity cap)", c)
	}
}

func TestPipelineDropUnderBackpressure(t *testing.T) {
	p := NewPipeline("node-1", testCfg(), 4)
	defer p.Close()
	// blocked consumer keeps the queue full; wait until it has picked up one
	// record and parked in the sink before injecting the overflow record,
	// otherwise the freed slot can swallow it (scheduling race).
	release := make(chan struct{})
	blocked := make(chan struct{})
	var once sync.Once
	p.SetSink(sinkFunc(func(r Record) {
		once.Do(func() { close(blocked) })
		<-release
	}))
	for i := 0; i < 1024; i++ {
		p.Enqueue(Record{ID: "x"})
	}
	<-blocked
	// the parked record freed one slot (queue now holds 1023 of 1024); keep
	// sending until the bounded queue actually rejects one.
	sent := 0
	for p.Dropped() == 0 && sent < 4096 {
		p.Enqueue(Record{ID: "x"})
		sent++
	}
	if p.Dropped() == 0 {
		t.Fatal("no record was dropped under backpressure")
	}
	close(release)
}

func TestPipelineCloseIdempotentAndSafeAfterClose(t *testing.T) {
	p := NewPipeline("node-1", testCfg(), 4)
	if err := p.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	p.Enqueue(Record{ID: "after-close"}) // must not panic
	if p.Dropped() != 1 {
		t.Fatalf("dropped after close = %d, want 1", p.Dropped())
	}
}

func TestPipelineDisabledByDefault(t *testing.T) {
	p := NewPipeline("n", nil, 0)
	defer p.Close()
	if p.Enabled() {
		t.Fatal("pipeline with nil cfg must be disabled")
	}
}

func TestRingRecentFilter(t *testing.T) {
	r := NewRing(3)
	r.Write(Record{Site: "a", Path: "/v1/chat", ClientIP: "1.1.1.1", Provider: "openai"})
	r.Write(Record{Site: "b", Path: "/v1/messages", ClientIP: "2.2.2.2", Provider: "anthropic"})
	r.Write(Record{Site: "a", Path: "/v1/embeddings", ClientIP: "3.3.3.3", Provider: "openai"})
	if got := r.Recent(10, "", "", ""); len(got) != 3 {
		t.Fatalf("all = %d, want 3", len(got))
	}
	if got := r.Recent(10, "a", "", ""); len(got) != 2 {
		t.Fatalf("site filter = %d, want 2", len(got))
	}
	if got := r.Recent(10, "", "2.2.2.2", ""); len(got) != 1 || got[0].Provider != "anthropic" {
		t.Fatalf("free-text filter mismatch: %+v", got)
	}
	if got := r.Recent(10, "", "", "openai"); len(got) != 2 {
		t.Fatalf("provider filter = %d, want 2", len(got))
	}
	// newest-first ordering
	got := r.Recent(1, "", "", "")
	if len(got) != 1 || got[0].ClientIP != "3.3.3.3" {
		t.Fatalf("newest-first violated: %+v", got)
	}
	// ring overwrite keeps capacity
	r.Write(Record{Site: "c"})
	if got := r.Count(); got != 3 {
		t.Fatalf("ring count = %d, want 3 (capped)", got)
	}
}

func TestNormalizeRequestOpenAI(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"system","content":"be nice"},{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}]}`)
	p := NormalizeRequest("openai", "chat", body, 4096)
	if p.System != "" {
		t.Fatalf("openai has no system field, got %q", p.System)
	}
	var msgs []Message
	if err := json.Unmarshal(p.Messages, &msgs); err != nil {
		t.Fatalf("messages unmarshal: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].Content != "be nice" {
		t.Fatalf("system message content = %q", msgs[0].Content)
	}
	want := "hi[IMG image len=26]"
	if msgs[1].Content != want {
		t.Fatalf("multipart flatten = %q, want %q", msgs[1].Content, want)
	}
}

func TestNormalizeRequestAnthropic(t *testing.T) {
	body := []byte(`{"model":"claude-3","system":"you are terse","messages":[{"role":"user","content":"hello"}]}`)
	p := NormalizeRequest("anthropic", "messages", body, 4096)
	if p.System != "you are terse" {
		t.Fatalf("system = %q", p.System)
	}
	var msgs []Message
	if err := json.Unmarshal(p.Messages, &msgs); err != nil {
		t.Fatalf("messages unmarshal: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Content != "hello" {
		t.Fatalf("messages = %+v", msgs)
	}
}

func TestNormalizeRequestGemini(t *testing.T) {
	body := []byte(`{"contents":[{"role":"user","parts":[{"text":"hi"},{"inline_data":{"mime_type":"image/png","data":"BBBB"}}]}],"systemInstruction":{"parts":[{"text":"sys"}]}}`)
	p := NormalizeRequest("gemini", "generate", body, 4096)
	if p.System != "sys" {
		t.Fatalf("system = %q", p.System)
	}
	var msgs []Message
	if err := json.Unmarshal(p.Messages, &msgs); err != nil {
		t.Fatalf("messages unmarshal: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if !strings.Contains(msgs[0].Content, "hi") || !strings.Contains(msgs[0].Content, "[IMAGE/PNG base64 len=4]") {
		t.Fatalf("gemini flatten = %q", msgs[0].Content)
	}
}

func TestNormalizeRequestRawFallback(t *testing.T) {
	p := NormalizeRequest("unknown", "", []byte(`not json`), 4096)
	if p.Raw != "not json" {
		t.Fatalf("raw = %q", p.Raw)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 3); got != "hel" {
		t.Fatalf("ascii truncate = %q", got)
	}
	s := "你好世界" // 12 bytes
	if got := truncate(s, 5); got != "你" {
		t.Fatalf("utf8 boundary truncate = %q", got)
	}
	if got := truncate(s, 0); got != s {
		t.Fatalf("unbounded truncate = %q", got)
	}
}

func TestSanitize(t *testing.T) {
	cases := [][2]string{
		{"key is sk-abc123DEF456ghi789JKL0 here", "key is [REDACTED] here"},
		{"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "Authorization: [REDACTED]"},
		{`{"api_key": "supersecret123"}`, `{"api_key": "[REDACTED]"}`},
		{"token aabbccddeeff00112233445566778899 done", "token [REDACTED] done"},
	}
	for _, c := range cases {
		if got := Sanitize(c[0]); got != c[1] {
			t.Errorf("sanitize(%q) = %q, want %q", c[0], got, c[1])
		}
	}
	// conversational text must survive untouched
	plain := "请帮我写一封周报，重点介绍本周的发布进展。"
	if got := Sanitize(plain); got != plain {
		t.Fatalf("plain text mutated: %q", got)
	}
}

func TestSanitizeRecord(t *testing.T) {
	r := &Record{
		Request: RequestPayload{
			System:    "sk-abcdefghijklmnop1234",
			Messages:  json.RawMessage(`[{"role":"user","content":"password=hunter2000"}]`),
			Raw:       "AKIAIOSFODNN7EXAMPLE",
		},
		Response: ResponsePayload{Text: "bearer aaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	SanitizeRecord(r)
	if !strings.Contains(r.Request.System, "[REDACTED]") {
		t.Fatalf("system not sanitized: %q", r.Request.System)
	}
	if strings.Contains(string(r.Request.Messages), "hunter2000") {
		t.Fatalf("messages not sanitized: %s", r.Request.Messages)
	}
	if !strings.Contains(r.Request.Raw, "[REDACTED]") {
		t.Fatalf("raw not sanitized: %q", r.Request.Raw)
	}
	if !strings.Contains(r.Response.Text, "[REDACTED]") {
		t.Fatalf("response not sanitized: %q", r.Response.Text)
	}
}

func respHeader(ct string) http.Header {
	h := http.Header{}
	h.Set("Content-Type", ct)
	return h
}

func TestHandleResponseNonStreamTee(t *testing.T) {
	p := NewPipeline("n", testCfg(), 10)
	defer p.Close()
	cfg := testCfg()
	cc := &CaptureCtx{
		rec:      &Record{Provider: "openai"},
		start:    time.Now(),
		maxResp:  cfg.MaxResponseBytesOrDefault(),
		redact:   false,
		pipeline: p,
	}
	src := io.NopCloser(bytes.NewReader([]byte(`{"choices":[{"message":{"content":"hi there"}}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)))
	resp := &http.Response{StatusCode: 200, Header: respHeader("application/json"), Body: src, ContentLength: -1}
	out := p.HandleResponse(resp, cc)
	b, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out.Body.Close()
	if !bytes.Contains(b, []byte("hi there")) {
		t.Fatalf("client body altered: %s", b)
	}
	rec := waitRing(p, 1, 2*time.Second)
	if len(rec) != 1 {
		t.Fatalf("record not finalized; ring=%d", len(rec))
	}
	if rec[0].Response.Text != "hi there" {
		t.Fatalf("captured text = %q", rec[0].Response.Text)
	}
	if rec[0].Usage == nil || rec[0].Usage.TotalTokens != 5 {
		t.Fatalf("usage = %+v", rec[0].Usage)
	}
}

func TestHandleResponseSSEOpenAI(t *testing.T) {
	p := NewPipeline("n", testCfg(), 10)
	defer p.Close()
	cc := &CaptureCtx{
		rec:      &Record{Provider: "openai"},
		start:    time.Now(),
		maxResp:  4096,
		redact:   false,
		stream:   true,
		pipeline: p,
	}
	stream := "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{}}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2,\"total_tokens\":3}}\n\n" +
		"data: [DONE]\n\n"
	src := io.NopCloser(bytes.NewReader([]byte(stream)))
	resp := &http.Response{StatusCode: 200, Header: respHeader("text/event-stream"), Body: src, ContentLength: -1}
	out := p.HandleResponse(resp, cc)
	b, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out.Body.Close()
	if !bytes.Contains(b, []byte("[DONE]")) {
		t.Fatalf("client stream altered: %s", b)
	}
	rec := waitRing(p, 1, 2*time.Second)
	if len(rec) != 1 {
		t.Fatalf("record not finalized; ring=%d", len(rec))
	}
	if rec[0].Response.Text != "Hello" {
		t.Fatalf("aggregated text = %q", rec[0].Response.Text)
	}
	if !rec[0].Stream {
		t.Fatal("stream flag not set")
	}
	if rec[0].Usage == nil || rec[0].Usage.TotalTokens != 3 {
		t.Fatalf("usage = %+v", rec[0].Usage)
	}
}

func TestHandleResponseSSEAnthropic(t *testing.T) {
	p := NewPipeline("n", testCfg(), 10)
	defer p.Close()
	cc := &CaptureCtx{
		rec:      &Record{Provider: "anthropic"},
		start:    time.Now(),
		maxResp:  4096,
		redact:   false,
		stream:   true,
		pipeline: p,
	}
	stream := "event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"你\"}}\n\n" +
		"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"好\"}}\n\n" +
		"data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}\n\n"
	src := io.NopCloser(bytes.NewReader([]byte(stream)))
	resp := &http.Response{StatusCode: 200, Header: respHeader("text/event-stream"), Body: src, ContentLength: -1}
	out := p.HandleResponse(resp, cc)
	_, _ = io.ReadAll(out.Body)
	out.Body.Close()
	rec := waitRing(p, 1, 2*time.Second)
	if len(rec) != 1 || rec[0].Response.Text != "你好" {
		t.Fatalf("anthropic aggregate = %+v", rec)
	}
}

func TestHandleResponsePassthroughUnknownCT(t *testing.T) {
	p := NewPipeline("n", testCfg(), 10)
	defer p.Close()
	cc := &CaptureCtx{rec: &Record{}, start: time.Now(), maxResp: 4096, pipeline: p}
	src := io.NopCloser(bytes.NewReader([]byte("binary-ish")))
	resp := &http.Response{StatusCode: 200, Header: respHeader("application/octet-stream"), Body: src, ContentLength: -1}
	out := p.HandleResponse(resp, cc)
	b, _ := io.ReadAll(out.Body)
	out.Body.Close()
	if string(b) != "binary-ish" {
		t.Fatalf("passthrough altered: %s", b)
	}
	// finalized with empty response text
	rec := waitRing(p, 1, 2*time.Second)
	if len(rec) != 1 || rec[0].Response.Text != "" {
		t.Fatalf("unknown-ct record = %+v", rec)
	}
}

func TestCaptureRequestIdentifiesAndStamps(t *testing.T) {
	p := NewPipeline("node-x", testCfg(), 10)
	defer p.Close()
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	r, _ := http.NewRequest("POST", "http://srv.example/v1/chat/completions", bytes.NewReader(body))
	r.RemoteAddr = "9.9.9.9:5555"
	r.Header.Set("User-Agent", "unit")
	r.Header.Set("X-KingMoat-Trace-Id", "tr-1")
	rc := &pipeline.RequestContext{Body: body}
	cc := p.CaptureRequest(rc, r, "srv.example", "tr-1")
	if cc == nil {
		t.Fatal("expected capture ctx for openai chat request")
	}
	if cc.rec.Provider != "openai" || cc.rec.Model != "gpt-4o" || cc.rec.NodeID != "node-x" {
		t.Fatalf("record stamp = %+v", cc.rec)
	}
	if cc.rec.ClientIP != "9.9.9.9" || cc.rec.Site != "srv.example" || cc.rec.TraceID != "tr-1" {
		t.Fatalf("record ctx = %+v", cc.rec)
	}
	// non-LLM request → nil
	r2, _ := http.NewRequest("GET", "http://srv.example/index.html", nil)
	if cc := p.CaptureRequest(nil, r2, "srv.example", ""); cc != nil {
		t.Fatalf("static request captured: %+v", cc.rec)
	}
	// disabled pipeline → nil
	p.Configure(nil)
	r3, _ := http.NewRequest("POST", "http://srv.example/v1/chat/completions", bytes.NewReader(body))
	if cc := p.CaptureRequest(nil, r3, "srv.example", ""); cc != nil {
		t.Fatal("disabled pipeline still captured")
	}
}

func TestHandleResponseStreamFallbackToNonStream(t *testing.T) {
	p := NewPipeline("n", testCfg(), 10)
	defer p.Close()
	cc := &CaptureCtx{
		rec:      &Record{Provider: "openai"},
		start:    time.Now(),
		maxResp:  4096,
		redact:   false,
		stream:   true, // identified as stream
		pipeline: p,
	}
	// but the upstream answered a plain non-stream JSON body (SSE stripped)
	src := io.NopCloser(bytes.NewReader([]byte(`{"choices":[{"message":{"content":"plain answer"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)))
	resp := &http.Response{StatusCode: 200, Header: respHeader("application/json"), Body: src, ContentLength: -1}
	out := p.HandleResponse(resp, cc)
	_, _ = io.ReadAll(out.Body)
	out.Body.Close()
	rec := waitRing(p, 1, 2*time.Second)
	if len(rec) != 1 || rec[0].Response.Text != "plain answer" {
		t.Fatalf("stream→non-stream fallback text = %+v", rec)
	}
}

type sinkFunc func(Record)

func (f sinkFunc) WriteAI(r Record) { f(r) }

// waitRing polls the pipeline ring until count records are visible (the
// finalize→Enqueue→loop fan-out is asynchronous) or the deadline passes.
func waitRing(p *Pipeline, count int, d time.Duration) []Record {
	deadline := time.Now().Add(d)
	for {
		rec := p.Ring().Recent(count, "", "", "")
		if len(rec) >= count {
			return rec
		}
		if time.Now().After(deadline) {
			return rec
		}
		time.Sleep(2 * time.Millisecond)
	}
}


func TestParseDomesticProviders(t *testing.T) {
	// baidu non-stream: result field
	txt, usage := parseNonStream("baidu", []byte(`{"id":"1","result":"你好，世界","usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`))
	if txt != "你好，世界" || usage == nil || usage.TotalTokens != 7 {
		t.Fatalf("baidu non-stream = %q %+v", txt, usage)
	}
	// baidu stream aggregation (no [DONE]; is_end final frame)
	frames := "{\"result\":\"你\"}\n{\"result\":\"好\"}\n{\"result\":\"！\",\"is_end\":true,\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2,\"total_tokens\":3}}\n"
	txt2, usage2 := parseAggregated("baidu", []byte(frames), true)
	if txt2 != "你好！" || usage2 == nil || usage2.TotalTokens != 3 {
		t.Fatalf("baidu stream = %q %+v", txt2, usage2)
	}
	// dashscope non-stream: output.choices[0].message.content + input/output_tokens
	txt3, usage3 := parseNonStream("dashscope", []byte(`{"output":{"choices":[{"message":{"content":"dash 答"},"finish_reason":"stop"}]},"usage":{"input_tokens":5,"output_tokens":6,"total_tokens":11}}`))
	if txt3 != "dash 答" || usage3 == nil || usage3.PromptTokens != 5 || usage3.CompletionTokens != 6 {
		t.Fatalf("dashscope non-stream = %q %+v", txt3, usage3)
	}
	// dashscope non-stream text format
	if txt4, _ := parseNonStream("dashscope", []byte(`{"output":{"text":"plain"},"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)); txt4 != "plain" {
		t.Fatalf("dashscope text-format = %q", txt4)
	}
	// dashscope stream: delta in output.choices[0].delta.text
	dsFrames := "{\"output\":{\"choices\":[{\"delta\":{\"text\":\"A\"}}]}}\n{\"output\":{\"choices\":[{\"delta\":{\"text\":\"B\"}}],\"finish_reason\":\"stop\"}}\n{\"output\":{},\"usage\":{\"input_tokens\":2,\"output_tokens\":2,\"total_tokens\":4}}\n"
	txt5, usage5 := parseAggregated("dashscope", []byte(dsFrames), true)
	if txt5 != "AB" || usage5 == nil || usage5.TotalTokens != 4 {
		t.Fatalf("dashscope stream = %q %+v", txt5, usage5)
	}
	// dashscope message stream, incremental_output=true: message.content deltas append
	dsMsgIncr := "{\"output\":{\"choices\":[{\"message\":{\"content\":\"你\"}}]}}\n{\"output\":{\"choices\":[{\"message\":{\"content\":\"好\"}}],\"finish_reason\":\"stop\"}}\n"
	if txtD1, _ := parseAggregated("dashscope", []byte(dsMsgIncr), true); txtD1 != "你好" {
		t.Fatalf("dashscope message-incremental stream = %q", txtD1)
	}
	// dashscope message stream, incremental_output=false: each frame replays the cumulative text
	dsMsgCum := "{\"output\":{\"choices\":[{\"message\":{\"content\":\"你\"}}]}}\n{\"output\":{\"choices\":[{\"message\":{\"content\":\"你好\"}}]}}\n{\"output\":{\"choices\":[{\"message\":{\"content\":\"你好！\"}}],\"finish_reason\":\"stop\"}}\n"
	if txtD2, _ := parseAggregated("dashscope", []byte(dsMsgCum), true); txtD2 != "你好！" {
		t.Fatalf("dashscope message-cumulative stream = %q", txtD2)
	}
	// minimax non-stream: openai-shaped
	txt6, usage6 := parseNonStream("minimax", []byte(`{"id":"x","choices":[{"finish_reason":"stop","index":0,"message":{"content":"mm 答","role":"assistant"}}],"usage":{"total_tokens":9,"prompt_tokens":2,"completion_tokens":7}}`))
	if txt6 != "mm 答" || usage6 == nil || usage6.TotalTokens != 9 {
		t.Fatalf("minimax non-stream = %q %+v", txt6, usage6)
	}
	// minimax stream: delta.content
	mmFrames := "{\"choices\":[{\"delta\":{\"content\":\"he\"}}],\"base_resp\":{\"status_code\":0}}\n{\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n"
	if txt7, _ := parseAggregated("minimax", []byte(mmFrames), true); txt7 != "hello" {
		t.Fatalf("minimax stream = %q", txt7)
	}
	// sensenova native non-stream: choices[0].message is a plain string
	txt8, usage8 := parseNonStream("sensenova", []byte(`{"id":"y","data":null,"choices":[{"message":"sn 答","index":0,"role":"assistant","finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	if txt8 != "sn 答" || usage8 == nil {
		t.Fatalf("sensenova non-stream = %q %+v", txt8, usage8)
	}
	// sensenova stream: choices[0].delta is a plain string
	snFrames := "{\"choices\":[{\"delta\":\"sn\",\"index\":0}]}\n{\"choices\":[{\"delta\":\" 流\",\"index\":0}]}\n"
	if txt9, _ := parseAggregated("sensenova", []byte(snFrames), true); txt9 != "sn 流" {
		t.Fatalf("sensenova stream = %q", txt9)
	}
}
