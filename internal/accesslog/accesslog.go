// Package accesslog implements the full access-log pipeline: one entry per
// forwarded (or blocked/challenged/redirected) request, batched and pushed
// asynchronously to ClickHouse, Elasticsearch, Loki, S3, syslog or kafka,
// and — when the access_log_record config section enables it — written to a
// standalone local SQLite store (sqlite.go) with its own retention and
// capacity policies. The request hot path only pays a bounded-queue send;
// drops under backpressure are counted. The shipper is generic
// (GenericShipper[T]) so other record families (e.g. AI sessions) reuse the
// same batcher, sinks and drop accounting behind a thin per-record encoder.
package accesslog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/redact"
	"github.com/kingmoat/kingmoat/internal/s3sink"
	"github.com/kingmoat/kingmoat/internal/syslogsink"
)

// Entry is one access-log record (JSON fields are the storage schema).
type Entry struct {
	TS         string `json:"ts"`
	TraceID    string `json:"trace_id,omitempty"`
	Site       string `json:"site,omitempty"`
	ClientIP   string `json:"client_ip,omitempty"`
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	Query      string `json:"query,omitempty"`
	Status     int    `json:"status,omitempty"`
	Bytes      int    `json:"bytes,omitempty"`
	LatencyMS  int64  `json:"latency_ms,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	Outcome    string `json:"outcome,omitempty"` // forwarded/blocked/challenged/monitor_forwarded/redirected
	Rule       string `json:"rule,omitempty"`    // last deny rule, when blocked
	AttackType string `json:"attack_type,omitempty"`
	// BodySkip marks requests whose body passed the WAF WITHOUT full
	// inspection because the site body limit was exceeded: "bypass" (not
	// inspected at all, header-phase detection only) or "prefix" (only the
	// first body_limit_bytes were inspected). Empty = fully inspected (or
	// not inspected because the request never reached the buffering stage).
	BodySkip string `json:"body_skip,omitempty"`
}

// Sink consumes access entries; implementations must be safe for concurrent
// use and never block the hot path.
type Sink interface {
	Write(e *Entry)
	Close() error
}

// doc is a pre-encoded log document: the JSON payload plus the per-record
// metadata the sinks need (primary timestamp, syslog event kind, kafka
// partition key). Records are encoded once by the stream-specific encoder;
// every sink consumes the same document form.
type doc struct {
	ts   string // RFC3339Nano; ES daily routing, Loki and syslog timestamps
	line []byte // pre-encoded JSON payload
	kind string // event kind (syslog MSGID / severity source, e.g. the outcome)
	key  string // kafka partition key (e.g. the trace id)
}

// Doc is the exported name of the pre-encoded document: out-of-package
// encoders (the AI-session adapter) declare their toDoc against this alias.
// It is a true alias, so Doc and doc are the same type everywhere.
type Doc = doc

// NewDoc builds one pre-encoded document for an out-of-package encoder: ts
// is the record timestamp (RFC3339Nano; ES daily routing and the Loki/syslog
// timestamps), line the pre-encoded JSON payload, kind the event kind (syslog
// MSGID / severity source) and key the kafka partition key.
func NewDoc(ts string, line []byte, kind, key string) Doc {
	return doc{ts: ts, line: line, kind: kind, key: key}
}

// GenericShipper batches pre-encoded documents and pushes them to the
// configured platform. The record type T is encoded once per entry by the
// caller-provided toDoc; the batcher, the backpressure drop counter, the
// sampling and the idempotent Close are shared by every stream (access log,
// AI sessions), as are all sink implementations.
type GenericShipper[T any] struct {
	kind    string // clickhouse | elasticsearch | loki | s3 | syslog | kafka
	stream  string // access | ai: parameterizes the sink-side identity labels
	url     string
	index   string
	s3cfg   *config.S3Settings
	syslog  *syslogsink.Client
	kafka   *kafkaSink
	client  *http.Client
	ch      chan doc
	dropped atomic.Int64
	done    chan struct{}
	logger  *slog.Logger

	// mu guards closed so Write never sends into a closed channel, and keeps
	// Close idempotent (repeat calls are a no-op).
	mu     sync.Mutex
	closed bool

	batchSize int
	flush     time.Duration
	samplePct int
	sampleCtr atomic.Uint64
	// basic-auth credentials for the HTTP sinks (ch / es / loki).
	username string
	password string

	// per-stream sink labels resolved at construction from the stream kind.
	s3Kind  string // s3 object kind segment (access / ai)
	lokiJob string // loki stream job label (kingmoat-access / kingmoat-ai)

	// toDoc encodes one record into the pre-encoded document consumed by the
	// sinks; nil is rejected by NewGeneric.
	toDoc func(*T) doc
}

// Shipper is the historical access-log pipeline shipper: the generic shipper
// instantiated for Entry. The alias keeps every existing call site (the
// main.go shipper pointer, the Tee type assertions, tests) compiling and
// behaving unchanged; the AI-session outbound instantiates the generic form
// directly.
type Shipper = GenericShipper[Entry]

// Stream kinds selecting the sink-side identity labels: the s3 object kind
// segment, the loki job label and the syslog default APP-NAME stay
// per-stream constants so access and AI-session traffic can never merge
// under one identity (each keeps its own index/prefix/app-name). The
// exported aliases are the construction surface for out-of-package encoders
// (the AI-session adapter); the unexported names keep every in-package use
// (and the existing tests) unchanged.
const (
	streamAccess = "access"
	streamAI     = "ai"

	// StreamAccess / StreamAI select the per-stream identity labels for
	// NewGeneric from outside this package.
	StreamAccess = streamAccess
	StreamAI     = streamAI
)

// streamIdentity returns the per-stream sink labels: the s3 object kind
// segment, the loki job label, the default index and the syslog default
// APP-NAME (the AI-session defaults mirror the access ones).
func streamIdentity(stream string) (s3Kind, lokiJob, defaultIndex, syslogApp string, ok bool) {
	switch stream {
	case streamAccess:
		return "access", "kingmoat-access", "kingmoat_access", "kingmoat_access", true
	case streamAI:
		return "ai", "kingmoat-ai", "kingmoat_ai_sessions", "kingmoat_ai_sessions", true
	default:
		return "", "", "", "", false
	}
}

// entryDoc encodes one access entry into the pre-encoded document form: the
// JSON payload, the record timestamp, the outcome (syslog MSGID / severity
// source) and the trace id (kafka partition key).
func entryDoc(e *Entry) doc {
	b, _ := json.Marshal(e)
	return doc{ts: e.TS, line: b, kind: e.Outcome, key: e.TraceID}
}

// New validates settings and starts the batcher. It keeps the historical
// signature: the access pipeline shipper over Entry.
func New(cfg config.AccessLogSettings, logger *slog.Logger) (*Shipper, error) {
	return NewGeneric[Entry](cfg, streamAccess, entryDoc, logger)
}

// NewGeneric validates settings and starts the batcher for any record type.
// stream selects the sink-side identity labels (StreamAccess or StreamAI);
// toDoc converts one record into the pre-encoded document pushed to the
// sinks (build it with NewDoc; out-of-package encoders declare the callback
// as func(*T) accesslog.Doc).
func NewGeneric[T any](cfg config.AccessLogSettings, stream string, toDoc func(*T) doc, logger *slog.Logger) (*GenericShipper[T], error) {
	if toDoc == nil {
		return nil, fmt.Errorf("accesslog: record encoder (toDoc) is required")
	}
	s3Kind, lokiJob, defaultIndex, syslogApp, sok := streamIdentity(stream)
	if !sok {
		return nil, fmt.Errorf("accesslog: unsupported stream %q", stream)
	}
	switch cfg.Type {
	case "clickhouse", "elasticsearch", "loki", "s3", "syslog", "kafka":
	default:
		return nil, fmt.Errorf("accesslog: unsupported type %q", cfg.Type)
	}
	if cfg.Type == "s3" {
		if err := cfg.S3.Validate(); err != nil {
			return nil, err
		}
	} else if cfg.Type != "kafka" && cfg.URL == "" {
		return nil, fmt.Errorf("accesslog: url is required")
	}
	if cfg.Type == "syslog" {
		if err := cfg.Syslog.Validate(); err != nil {
			return nil, fmt.Errorf("accesslog: syslog: %w", err)
		}
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &GenericShipper[T]{
		kind:     cfg.Type,
		stream:   stream,
		url:      cfg.URL,
		index:    cfg.Index,
		s3cfg:    cfg.S3,
		client:   &http.Client{Timeout: durationSec(cfg.TimeoutSec, 5)},
		ch:       make(chan doc, queueSize),
		done:     make(chan struct{}),
		logger:   logger,
		username: cfg.Username,
		password: cfg.Password,

		batchSize: cfg.BatchSize,
		flush:     durationSec(cfg.FlushSec, 5),
		samplePct: cfg.SamplePctOrDefault(),

		s3Kind:  s3Kind,
		lokiJob: lokiJob,
		toDoc:   toDoc,
	}
	if cfg.Type == "syslog" {
		sys, serr := syslogsink.New(config.ShipperSettings{
			Type:   "syslog",
			URL:    cfg.URL,
			Index:  cfg.Index,
			Syslog: cfg.Syslog,
		}, syslogApp)
		if serr != nil {
			return nil, serr
		}
		s.syslog = sys
	}
	if cfg.Type == "kafka" {
		tgt, terr := newKafkaSink(cfg, logger)
		if terr != nil {
			return nil, terr
		}
		s.kafka = tgt
	}
	if s.index == "" {
		s.index = defaultIndex
	}
	if s.batchSize <= 0 {
		s.batchSize = 200
	}
	go s.loop()
	return s, nil
}

const queueSize = 8192

// Write implements Sink (non-blocking; sampling applies here).
func (s *GenericShipper[T]) Write(e *T) {
	if e == nil || s.samplePct < 100 {
		// deterministic 1..N sampling without a lock
		if s.samplePct < 100 {
			n := s.sampleCtr.Add(1)
			if int(n%100) >= s.samplePct {
				return
			}
		}
	}
	if e == nil {
		return
	}
	d := s.toDoc(e)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- d:
	default:
		s.dropped.Add(1)
	}
}

// Dropped returns the number of entries dropped under backpressure.
func (s *GenericShipper[T]) Dropped() int64 { return s.dropped.Load() }

// Depth returns the current queue length (observability gauge).
func (s *GenericShipper[T]) Depth() int { return len(s.ch) }

// Close flushes pending entries and stops the batcher. It is idempotent:
// a repeated call returns without closing the channel a second time. The
// kafka writer and the syslog client close only after the batcher loop has
// exited (<-s.done), so an in-flight push can never race the close.
func (s *GenericShipper[T]) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.ch)
	s.mu.Unlock()
	<-s.done
	if s.kafka != nil {
		_ = s.kafka.close()
	}
	if s.syslog != nil {
		_ = s.syslog.Close()
	}
	return nil
}

func (s *GenericShipper[T]) loop() {
	defer close(s.done)
	batch := make([]doc, 0, s.batchSize)
	ticker := time.NewTicker(s.flush)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.push(batch)
		batch = batch[:0]
	}
	for {
		select {
		case ev, ok := <-s.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ev)
			if len(batch) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *GenericShipper[T]) push(batch []doc) {
	if s.kind == "kafka" {
		if err := s.kafka.pushBatch(batch); err != nil {
			s.logger.Warn("accesslog kafka push failed", "err", redact.String(err.Error()))
		}
		return
	}
	if s.kind == "syslog" {
		for i := range batch {
			d := &batch[i]
			ts := syslogsink.ParseEventTS(d.ts)
			sev := syslogsink.SeverityFor(d.kind)
			if err := s.syslog.Send(ts, d.kind, string(d.line), sev); err != nil {
				s.logger.Warn("accesslog syslog send failed", "err", redact.String(err.Error()))
			}
		}
		return
	}
	var body []byte
	var contentType string
	var target string
	switch s.kind {
	case "s3":
		c, err := s3sink.New(s.s3cfg)
		if err != nil {
			s.logger.Warn("accesslog s3 client failed", "err", err)
			return
		}
		var buf bytes.Buffer
		for _, d := range batch {
			buf.Write(d.line)
			buf.WriteByte('\n')
		}
		if err := c.PutJSONL(context.Background(), s.s3Kind, buf.Bytes()); err != nil {
			s.logger.Warn("accesslog s3 put failed", "err", err)
		}
		return
	case "clickhouse":
		// JSONEachRow: one JSON object per line into a fixed table.
		var buf bytes.Buffer
		for _, d := range batch {
			buf.Write(d.line)
			buf.WriteByte('\n')
		}
		body = buf.Bytes()
		contentType = "text/plain; charset=utf-8"
		q := "INSERT INTO " + s.index + " FORMAT JSONEachRow"
		target = joinURL(s.url, "/?query="+url.QueryEscape(q))
	case "elasticsearch":
		var buf bytes.Buffer
		for _, d := range batch {
			// Daily index routing follows the record's own timestamp (the
			// current day only as the fallback for an unparseable ts), so a
			// batch spanning midnight lands each record on its own day.
			buf.WriteString(fmt.Sprintf(`{"index":{"_index":"%s-%s"}}`+"\n", s.index, docDay(d.ts)))
			buf.Write(d.line)
			buf.WriteByte('\n')
		}
		body = buf.Bytes()
		contentType = "application/x-ndjson"
		target = joinURL(s.url, "/_bulk")
	case "loki":
		vals := make([][]string, 0, len(batch))
		for _, d := range batch {
			ts := d.ts
			if t, err := time.Parse(time.RFC3339Nano, d.ts); err == nil {
				ts = fmt.Sprint(t.UnixNano())
			}
			vals = append(vals, []string{ts, string(d.line)})
		}
		payload, _ := json.Marshal(map[string]any{
			"streams": []map[string]any{
				{"stream": map[string]string{"app": s.index, "job": s.lokiJob}, "values": vals},
			},
		})
		body = payload
		contentType = "application/json"
		target = joinURL(s.url, "/loki/api/v1/push")
	default:
		return
	}

	req, rerr := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if rerr != nil {
		s.logger.Warn("accesslog push request build failed", "type", s.kind, "err", redact.String(rerr.Error()))
		return
	}
	req.Header.Set("Content-Type", contentType)
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Warn("accesslog push failed", "type", s.kind, "err", redact.String(err.Error()))
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		s.logger.Warn("accesslog push rejected", "type", s.kind, "status", resp.StatusCode)
	}
}

// docDay returns the UTC day of a record timestamp (RFC3339Nano), falling
// back to the current day when the timestamp is empty or malformed.
func docDay(ts string) string {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.UTC().Format("2006.01.02")
	}
	return time.Now().UTC().Format("2006.01.02")
}

// Recorder wraps a ResponseWriter to capture the outgoing status and byte
// count while transparently preserving Flush/Hijack for WebSocket and
// streaming responses, ReadFrom for io.Copy fast paths, and Unwrap so
// http.ResponseController reaches the wrapped writer's control surface.
type Recorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

// NewRecorder wraps w.
func NewRecorder(w http.ResponseWriter) *Recorder { return &Recorder{ResponseWriter: w} }

// Status returns the captured status code (0 = none written yet).
func (r *Recorder) Status() int { return r.status }

// BytesWritten returns the captured body byte count.
func (r *Recorder) BytesWritten() int { return r.bytes }

// WriteHeader captures the status and delegates.
func (r *Recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

// Write captures the byte count and delegates.
func (r *Recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// Flush forwards to the underlying flusher when available.
func (r *Recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the underlying hijacker when available so WebSocket
// upgrades keep working.
func (r *Recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// recorderCopyTarget hides Recorder.ReadFrom from the io.Copy fallback
// below so the slow path delegates through Write (counted) instead of
// recursing into ReadFrom.
type recorderCopyTarget struct{ io.Writer }

// ReadFrom keeps the io.Copy fast path reachable through the recorder: when
// the wrapped writer implements io.ReaderFrom (net/http's does), the copy
// is forwarded there and the bytes it moved are accounted, so down-byte
// counting stays exact even when a handler streams via io.Copy directly
// into the recorder. Without an inner fast path the call degrades to plain
// io.Copy semantics (chunked Write through this recorder, still counted).
// Writes arrive from the single goroutine serving the request, matching
// Write's non-atomic counter contract.
func (r *Recorder) ReadFrom(src io.Reader) (int64, error) {
	if rf, ok := r.ResponseWriter.(io.ReaderFrom); ok {
		if r.status == 0 {
			r.status = http.StatusOK
		}
		n, err := rf.ReadFrom(src)
		r.bytes += int(n)
		return n, err
	}
	return io.Copy(recorderCopyTarget{r}, src)
}

// Unwrap exposes the wrapped ResponseWriter so http.ResponseController and
// the net/http unwrapping convention reach the underlying writer's control
// surface (SetWriteDeadline and friends; Flush/Hijack are covered by the
// explicit forwards above).
func (r *Recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func durationSec(n int, def int) time.Duration {
	if n <= 0 {
		n = def
	}
	return time.Duration(n) * time.Second
}

// joinURL concatenates a base URL and a path/query.
func joinURL(base, suffix string) string {
	for len(base) > 0 && base[len(base)-1] == '/' {
		base = base[:len(base)-1]
	}
	return base + suffix
}
