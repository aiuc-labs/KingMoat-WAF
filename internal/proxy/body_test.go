package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

func finishBody(bo bodyOutcome, r *http.Request) {
	if bo.pool != nil {
		recycle(bo.pool)
	}
	if bo.release != nil {
		bo.release()
	}
}

func TestBufferBodySmall(t *testing.T) {
	r := httptest.NewRequest("POST", "http://x.local/", strings.NewReader("hello world"))
	site := &config.Site{WAF: &config.WAFSettings{BodyLimitBytes: 100}}

	bo := bufferBody(r, site, nil)
	defer finishBody(bo, r)
	if bo.err != nil {
		t.Fatalf("bufferBody: %v", bo.err)
	}
	if bo.over {
		t.Fatal("small body must not be flagged over limit")
	}
	if bo.skip != "" {
		t.Fatalf("fully-inspected body must not carry a skip marker, got %q", bo.skip)
	}
	if string(bo.data) != "hello world" {
		t.Fatalf("data = %q", bo.data)
	}

	// Body must be rewound for forwarding / the pipeline.
	rest, _ := io.ReadAll(r.Body)
	if string(rest) != "hello world" {
		t.Fatalf("rewound body = %q", rest)
	}
}

func TestBufferBodyOverLimitWithKnownLength(t *testing.T) {
	r := httptest.NewRequest("POST", "http://x.local/", strings.NewReader("1234567890"))
	site := &config.Site{WAF: &config.WAFSettings{BodyLimitBytes: 5}}

	bo := bufferBody(r, site, nil)
	defer finishBody(bo, r)
	if bo.err != nil || !bo.over {
		t.Fatalf("over=%v err=%v, want over=true", bo.over, bo.err)
	}
	// Default policy is reject: no pass marker (the caller answers 413).
	if bo.skip != "" {
		t.Fatalf("reject policy must not carry a skip marker, got %q", bo.skip)
	}

	// The untouched body must still forward completely (bypass path).
	rest, _ := io.ReadAll(r.Body)
	if string(rest) != "1234567890" {
		t.Fatalf("bypassed body = %q, want intact", rest)
	}
}

func TestBufferBodyOverLimitChunkedRewinds(t *testing.T) {
	r := httptest.NewRequest("POST", "http://x.local/", strings.NewReader("abcdefghij"))
	r.ContentLength = -1 // simulate chunked / unknown length
	r.TransferEncoding = []string{"chunked"}
	site := &config.Site{WAF: &config.WAFSettings{BodyLimitBytes: 5}}

	bo := bufferBody(r, site, nil)
	defer finishBody(bo, r)
	if bo.err != nil || !bo.over {
		t.Fatalf("over=%v err=%v, want over=true", bo.over, bo.err)
	}

	// Consumed bytes (limit+1) must be glued back to the remaining stream.
	rest, _ := io.ReadAll(r.Body)
	if string(rest) != "abcdefghij" {
		t.Fatalf("rewound chunked body = %q, want intact", rest)
	}
}

func TestBufferBodyStreamPolicyReturnsPrefix(t *testing.T) {
	body := strings.Repeat("a", 100)
	r := httptest.NewRequest("POST", "http://x.local/", strings.NewReader(body))
	r.ContentLength = -1
	r.TransferEncoding = []string{"chunked"}
	site := &config.Site{WAF: &config.WAFSettings{BodyLimitBytes: 40, BodyOverLimit: "stream"}}

	bo := bufferBody(r, site, nil)
	defer finishBody(bo, r)
	if bo.err != nil || !bo.over {
		t.Fatalf("over=%v err=%v, want over=true", bo.over, bo.err)
	}
	if len(bo.data) != 40 {
		t.Fatalf("stream prefix = %d bytes, want 40", len(bo.data))
	}
	if string(bo.data) != strings.Repeat("a", 40) {
		t.Fatal("stream prefix content mismatch")
	}
	if bo.skip != "prefix" {
		t.Fatalf("stream pass marker = %q, want prefix", bo.skip)
	}

	// The full stream must still forward untouched.
	rest, _ := io.ReadAll(r.Body)
	if string(rest) != body {
		t.Fatalf("streamed body = %d bytes, want intact %d", len(rest), len(body))
	}
}

// TestBufferBodyStreamKnownLengthInspectsPrefix pins the fast-path fix: a
// stream-policy site with a KNOWN over-limit Content-Length must still have
// the first body_limit_bytes inspected — the historical fast path skipped
// prefix inspection entirely for exactly the shape real uploads use.
func TestBufferBodyStreamKnownLengthInspectsPrefix(t *testing.T) {
	r := httptest.NewRequest("POST", "http://x.local/", strings.NewReader(strings.Repeat("a", 100)))
	site := &config.Site{WAF: &config.WAFSettings{BodyLimitBytes: 40, BodyOverLimit: "stream"}}

	bo := bufferBody(r, site, nil)
	defer finishBody(bo, r)
	if bo.err != nil || !bo.over {
		t.Fatalf("over=%v err=%v, want over=true", bo.over, bo.err)
	}
	if len(bo.data) != 40 {
		t.Fatalf("known-length stream prefix = %d bytes, want 40 (fast path skipped inspection)", len(bo.data))
	}
	if bo.skip != "prefix" {
		t.Fatalf("skip marker = %q, want prefix", bo.skip)
	}
	rest, _ := io.ReadAll(r.Body)
	if len(rest) != 100 {
		t.Fatalf("rewound body = %d bytes, want intact 100", len(rest))
	}
}

// TestBufferBodyRejectFastPathReservesNothing pins the budget contract for
// the Content-Length fast path: a known over-limit reject reads nothing,
// so it reserves no aggregate-buffer credit.
func TestBufferBodyRejectFastPathReservesNothing(t *testing.T) {
	r := httptest.NewRequest("POST", "http://x.local/", strings.NewReader(strings.Repeat("x", 200)))
	site := &config.Site{WAF: &config.WAFSettings{BodyLimitBytes: 64}}

	before := bodyMem.inUseBytes()
	bo := bufferBody(r, site, nil)
	defer finishBody(bo, r)
	if !bo.over {
		t.Fatal("known over-limit must flag over")
	}
	if after := bodyMem.inUseBytes(); after != before {
		t.Fatalf("fast path reserved %d bytes, want 0", after-before)
	}
}

// slowBody delivers data slowly: every Read sleeps past the (test-shrunk)
// idle window, forcing the watchdog to fire mid-stream.
type slowBody struct {
	chunk    []byte
	delay    time.Duration
	served   int
}

func (s *slowBody) Read(p []byte) (int, error) {
	if s.served >= 2 {
		return 0, io.EOF
	}
	time.Sleep(s.delay)
	n := copy(p, s.chunk)
	s.served++
	return n, nil
}

func (s *slowBody) Close() error { return nil }

// TestBodyIdleWatchdogAborts pins the slow-body guard: a request body that
// makes no read progress within the idle window is answered 408 (rule
// proxy/body_idle) with truthful access-log semantics and an audit event —
// previously nothing bounded a slow-drip body (slowloris-on-body).
func TestBodyIdleWatchdogAborts(t *testing.T) {
	oldIdle := bodyIdleTimeout
	bodyIdleTimeout = 100 * time.Millisecond
	defer func() { bodyIdleTimeout = oldIdle }()

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
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
	audit := &captureStore{}
	sink := &memSink{}
	h, err := NewReloadableObserved(cfg, audit, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	h.SetAccessSink(sink)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://t.local/push", &slowBody{chunk: []byte("0123456789"), delay: 400 * time.Millisecond})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestTimeout {
		t.Fatalf("stalled body status = %d, want 408", rec.Code)
	}
	entries := sink.snapshot()
	if len(entries) != 1 {
		t.Fatalf("access entries = %d, want 1", len(entries))
	}
	if e := entries[0]; e.Outcome != "blocked" || e.Rule != "proxy/body_idle" {
		t.Fatalf("access log semantics wrong: outcome=%q rule=%q, want blocked/proxy/body_idle", e.Outcome, e.Rule)
	}
	found := false
	for _, ev := range audit.snapshot() {
		if ev.Rule == "proxy/body_idle" && ev.Action == "blocked" && ev.Status == http.StatusRequestTimeout {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("audit event missing: %+v", audit.snapshot())
	}
}

// TestBodyBudgetExhaustionFailsClosed pins the aggregate memory guard: with
// the budget shrunk below one read chunk, a body request is answered 503
// (rule proxy/body_buffer_exhausted) — fail-closed, so memory pressure can
// never silently downgrade body inspection.
func TestBodyBudgetExhaustionFailsClosed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer up.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF:      &config.WAFSettings{BodyLimitBytes: 16 << 20},
		}},
	}
	audit := &captureStore{}
	sink := &memSink{}
	h, err := NewReloadableObserved(cfg, audit, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	h.SetAccessSink(sink)
	// Shrink the budget AFTER the handler build: buildState refreshes the
	// budget from the config (default 256 MB) and would overwrite an
	// earlier shrink.
	oldBudget := bodyMem.budgetBytes()
	bodyMem.setBudgetMB(1) // 1 MiB: smaller than the 12 MiB body below
	defer func() { bodyMem.setBudgetBytes(oldBudget) }()

	body := strings.Repeat("x", 12<<20)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://t.local/push", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("budget-exhausted status = %d, want 503", rec.Code)
	}
	entries := sink.snapshot()
	if len(entries) != 1 {
		t.Fatalf("access entries = %d, want 1", len(entries))
	}
	if e := entries[0]; e.Outcome != "blocked" || e.Rule != "proxy/body_buffer_exhausted" {
		t.Fatalf("access log semantics wrong: outcome=%q rule=%q, want blocked/proxy/body_buffer_exhausted", e.Outcome, e.Rule)
	}
	found := false
	for _, ev := range audit.snapshot() {
		if ev.Rule == "proxy/body_buffer_exhausted" && ev.Status == http.StatusServiceUnavailable {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("audit event missing: %+v", audit.snapshot())
	}
	if left := bodyMem.inUseBytes(); left != 0 {
		t.Fatalf("budget leak: %d bytes still reserved after the failed request", left)
	}
}

// TestBodyReadErrorSemantics pins the client-abort branch: a body read that
// fails mid-stream (client abort / I/O) answers 400 AND records a truthful
// access-log line (previously outcome=forwarded with no rule).
func TestBodyReadErrorSemantics(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
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
	audit := &captureStore{}
	sink := &memSink{}
	h, err := NewReloadableObserved(cfg, audit, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	h.SetAccessSink(sink)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://t.local/push", errReader{})
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("aborted body status = %d, want 400", rec.Code)
	}
	entries := sink.snapshot()
	if len(entries) != 1 {
		t.Fatalf("access entries = %d, want 1", len(entries))
	}
	if e := entries[0]; e.Outcome != "blocked" || e.Rule != "proxy/body_read" {
		t.Fatalf("access log semantics wrong: outcome=%q rule=%q, want blocked/proxy/body_read", e.Outcome, e.Rule)
	}
	for _, ev := range audit.snapshot() {
		if ev.Rule == "proxy/body_read" {
			t.Fatal("client aborts must not write attack-log events")
		}
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error)  { return 0, errors.New("client went away") }
func (errReader) Close() error              { return nil }

var _ io.ReadCloser = errReader{}

// TestBufferBodyDisarmsWatchdog pins the 502 fix: once the body is fully
// buffered (or the request is about to end in a reject) the idle watchdog
// must disarm — a long detection pipeline (>60s CRS scan of a large body)
// makes no body reads and must never be mistaken for a stalled client (the
// abort rewinds the connection read deadline, which cancels the request
// context and kills the in-flight upstream round trip).
func TestBufferBodyDisarmsWatchdog(t *testing.T) {
	oldIdle := bodyIdleTimeout
	bodyIdleTimeout = 100 * time.Millisecond
	defer func() { bodyIdleTimeout = oldIdle }()

	site := &config.Site{WAF: &config.WAFSettings{BodyLimitBytes: 1 << 20}}

	// Fully buffered: disarmed.
	r := httptest.NewRequest("POST", "http://x.local/", strings.NewReader("hello"))
	wd := newBodyWatchdog(httptest.NewRecorder())
	bo := bufferBody(r, site, wd)
	defer finishBody(bo, r)
	if bo.err != nil || bo.over {
		t.Fatalf("over=%v err=%v, want buffered", bo.over, bo.err)
	}
	time.Sleep(250 * time.Millisecond)
	if wd.aborted.Load() {
		t.Fatal("watchdog fired after the body was fully buffered (long pipelines would be killed)")
	}

	// Stream over-limit: stays armed (the remainder is still read from the
	// client during the forward).
	site2 := &config.Site{WAF: &config.WAFSettings{BodyLimitBytes: 40, BodyOverLimit: "stream"}}
	r2 := httptest.NewRequest("POST", "http://x.local/", strings.NewReader(strings.Repeat("a", 100)))
	wd2 := newBodyWatchdog(httptest.NewRecorder())
	bo2 := bufferBody(r2, site2, wd2)
	defer finishBody(bo2, r2)
	if !bo2.over || bo2.skip != "prefix" {
		t.Fatalf("over=%v skip=%q, want over/prefix", bo2.over, bo2.skip)
	}
	wd2.abort()
	if !wd2.aborted.Load() {
		t.Fatal("armed watchdog must still abort")
	}
}