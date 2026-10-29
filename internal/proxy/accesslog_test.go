package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/accesslog"
	"github.com/kingmoat/kingmoat/internal/config"
)

// compile-time: the recorder must keep the io.Copy fast path and the
// ResponseController unwrapping convention reachable (S-2).
var (
	_ io.ReaderFrom         = (*accesslog.Recorder)(nil)
	_ interface{ Unwrap() http.ResponseWriter } = (*accesslog.Recorder)(nil)
)

// memSink collects access entries for assertions.
type memSink struct {
	mu      sync.Mutex
	entries []*accesslog.Entry
}

// compile-time interface check
var _ accesslog.Sink = (*memSink)(nil)

func (m *memSink) Close() error { return nil }

func (m *memSink) Write(e *accesslog.Entry) {
	m.mu.Lock()
	m.entries = append(m.entries, e)
	m.mu.Unlock()
}

func (m *memSink) snapshot() []*accesslog.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*accesslog.Entry(nil), m.entries...)
}

func TestAccessLogEmitsForwardedAndBlocked(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF:      wafOff(),
			Security: &config.SecuritySettings{Semantic: &config.SemanticSettings{Enabled: true}},
		}},
	}

	sink := &memSink{}
	h, err := NewReloadableObserved(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	h.SetAccessSink(sink)

	// forwarded: status + bytes captured through the recorder
	if rec := do(t, h, "GET", "http://t.local/a?x=1"); rec.Code != 200 {
		t.Fatalf("forward failed: %d", rec.Code)
	}
	// blocked: deny page status captured
	if rec := do(t, h, "GET", `http://t.local/p?id=1%27%20or%20%271%27=%271`); rec.Code != 403 {
		t.Fatalf("expected block, got %d", rec.Code)
	}

	entries := sink.snapshot()
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	fwd, blocked := entries[0], entries[1]
	if fwd.Outcome != "forwarded" || fwd.Status != 200 || fwd.Bytes == 0 || fwd.LatencyMS < 0 {
		t.Fatalf("forwarded entry wrong: %+v", fwd)
	}
	if fwd.Site != "t.local" || fwd.Path != "/a" || fwd.Query != "x=1" {
		t.Fatalf("forwarded fields wrong: %+v", fwd)
	}
	if blocked.Outcome != "blocked" || blocked.Status != 403 || blocked.Rule != "semantic/sqli" {
		t.Fatalf("blocked entry wrong: %+v", blocked)
	}
}

func TestAccessLogDisabledByDefault(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
		}},
	}
	h, err := NewReloadable(cfg, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	do(t, h, "GET", "http://t.local/") // must not panic with a nil sink
}

// deadlineRecorder implements the write-deadline control surface so the
// ResponseController penetration assertion has an inner capability to reach
// through the recorder (httptest.ResponseRecorder has none).
type deadlineRecorder struct {
	http.ResponseWriter
	wd time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error { d.wd = t; return nil }

// TestRecorderUnwrapRestoresControlPlane pins the S-2 control-surface fix:
// ResponseController must reach the wrapped writer's capabilities through
// Unwrap (deadline set succeeds and lands on the inner), while an inner
// without the capability still reports ErrNotSupported — penetration must
// delegate to the inner, not blanket-accept.
func TestRecorderUnwrapRestoresControlPlane(t *testing.T) {
	inner := &deadlineRecorder{ResponseWriter: httptest.NewRecorder()}
	rec := accesslog.NewRecorder(inner)

	if got := rec.Unwrap(); got != inner {
		t.Fatalf("Unwrap must return the wrapped writer: got %T", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	if err := http.NewResponseController(rec).SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline through recorder failed: %v", err)
	}
	if inner.wd.IsZero() {
		t.Fatal("deadline never reached the inner writer")
	}

	// Inner without the capability: the controller must report unsupported
	// (proof the unwrap chain terminates at the inner's real surface).
	plain := accesslog.NewRecorder(httptest.NewRecorder())
	if err := http.NewResponseController(plain).SetWriteDeadline(deadline); err == nil {
		t.Fatal("SetWriteDeadline must fail when the inner writer does not support it")
	}
}

// rfRecorder implements io.ReaderFrom so the recorder's fast-path
// forwarding (and its byte accounting) is observable.
type rfRecorder struct {
	http.ResponseWriter
	copied int64
}

func (f *rfRecorder) ReadFrom(src io.Reader) (int64, error) {
	n, err := io.Copy(f.ResponseWriter, src)
	f.copied = n
	return n, err
}

// TestRecorderReadFromCounting pins the ReadFrom accounting contract: bytes
// moved by the inner fast path are added to the down-byte count (they never
// pass through Write), and the fallback (inner without ReadFrom) degrades to
// io.Copy semantics through Write without recursing — same total either way.
func TestRecorderReadFromCounting(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 7<<10)

	fast := &rfRecorder{ResponseWriter: httptest.NewRecorder()}
	rec := accesslog.NewRecorder(fast)
	n, err := rec.ReadFrom(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(body)) || fast.copied != int64(len(body)) {
		t.Fatalf("fast-path copy lost bytes: n=%d inner=%d want %d", n, fast.copied, len(body))
	}
	if rec.BytesWritten() != len(body) {
		t.Fatalf("fast-path bytes not accounted: got %d, want %d", rec.BytesWritten(), len(body))
	}
	if rec.Status() != http.StatusOK {
		t.Fatalf("ReadFrom must default the captured status to 200, got %d", rec.Status())
	}

	slow := httptest.NewRecorder()
	rec2 := accesslog.NewRecorder(slow)
	n2, err := rec2.ReadFrom(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if n2 != int64(len(body)) || rec2.BytesWritten() != len(body) || slow.Body.Len() != len(body) {
		t.Fatalf("fallback path wrong: n=%d counted=%d written=%d want %d", n2, rec2.BytesWritten(), slow.Body.Len(), len(body))
	}
}

// TestForwardedBodyBytesCountedExact is the end-to-end regression for the
// unconditional recorder wrap: a 1 MiB proxied body must arrive at the
// client byte-for-byte AND the access-log down-byte count must equal the
// body length the client actually received.
func TestForwardedBodyBytesCountedExact(t *testing.T) {
	const size = 1 << 20
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(bytes.Repeat([]byte("z"), size))
	}))
	defer up.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF:      wafOff(),
		}},
	}
	sink := &memSink{}
	h, err := NewReloadableObserved(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	h.SetAccessSink(sink)

	rec := do(t, h, "GET", "http://t.local/big")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != size {
		t.Fatalf("client received %d bytes, want %d", rec.Body.Len(), size)
	}
	entries := sink.snapshot()
	if len(entries) != 1 {
		t.Fatalf("access entries = %d, want 1", len(entries))
	}
	if entries[0].Bytes != size {
		t.Fatalf("down-byte count lost bytes: recorded %d, client got %d", entries[0].Bytes, rec.Body.Len())
	}
}
