package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/metrics"
)

// TestBodyLimitRejectSemantics pins the over-limit reject contract: the
// request must be answered 413 (the documented status 鈥?the generic Deny
// verdict used to render a 403 block page), the access log must record a
// real rejection (outcome=blocked with the proxy/body_limit rule 鈥?it used
// to say outcome=forwarded with no rule, which read as "no interception
// happened" during triage), and the attack log must carry the event so the
// rejection is visible in the console.
func TestBodyLimitRejectSemantics(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer up.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF:      &config.WAFSettings{BodyLimitBytes: 128},
		}},
	}
	audit := &captureStore{}
	sink := &memSink{}
	h, err := NewReloadableObserved(cfg, audit, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	h.SetAccessSink(sink)

	body := bytes.Repeat([]byte("x"), 256)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "http://t.local/push", bytes.NewReader(body)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit status = %d, want 413", rec.Code)
	}
	if rule := rec.Header().Get("X-KingMoat-Rule"); rule != "proxy/body_limit" {
		t.Fatalf("X-KingMoat-Rule = %q, want proxy/body_limit", rule)
	}

	entries := sink.snapshot()
	if len(entries) != 1 {
		t.Fatalf("access entries = %d, want 1", len(entries))
	}
	if e := entries[0]; e.Outcome != "blocked" || e.Rule != "proxy/body_limit" {
		t.Fatalf("access log semantics wrong: outcome=%q rule=%q, want blocked/proxy/body_limit", e.Outcome, e.Rule)
	}

	found := false
	for _, ev := range audit.snapshot() {
		if ev.Rule == "proxy/body_limit" && ev.Action == "blocked" && ev.Status == http.StatusRequestEntityTooLarge {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("attack log event missing or wrong: %+v", audit.snapshot())
	}
}

// TestBodyLimitBypassStreamsThrough pins the escape hatch: a site with
// body_over_limit=bypass forwards arbitrarily large bodies untouched
// (header-phase detection only) 鈥?the git-hosting / large-upload story.
func TestBodyLimitBypassStreamsThrough(t *testing.T) {
	const size = 256
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		if int64(len(got)) != size {
			t.Errorf("upstream got %d bytes, want %d", len(got), size)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer up.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF:      &config.WAFSettings{BodyLimitBytes: 128, BodyOverLimit: "bypass"},
		}},
	}
	h, err := NewReloadableObserved(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	body := bytes.Repeat([]byte("y"), size)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://t.local/push", bytes.NewReader(body))
	// git push / real upload traffic always carries a content type; without
	// one CRS 920340 (protocol enforcement) would deny before the bypass
	// semantics under test even matter. Use a type CRS 920420 accepts 鈥?	// octet-stream is NOT in the default allowlist.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bypass status = %d, rule=%q, want 200", rec.Code, rec.Header().Get("X-KingMoat-Rule"))
	}

	// The skipped traffic must stay auditable: access-log marker + counter.
	sink := &memSink{}
	h.SetAccessSink(sink)
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "http://t.local/push", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second bypass status = %d", rec2.Code)
	}
	entries := sink.snapshot()
	if len(entries) != 1 {
		t.Fatalf("access entries = %d, want 1", len(entries))
	}
	if e := entries[0]; e.BodySkip != "bypass" {
		t.Fatalf("body_skip = %q, want bypass (skipped traffic must be auditable)", e.BodySkip)
	}
	if got := metrics.BodyBypassTotal.Snapshot()["t.local\x00bypass"]; got != 2 {
		t.Fatalf("kingmoat_body_bypass_total{t.local,bypass} = %d, want 2", got)
	}
}

// TestBodyMemGuardBasics pins the guard's own semantics: incremental
// reserve, fail at the budget edge, release, and the unlimited escape.
func TestBodyMemGuardBasics(t *testing.T) {
	g := &bodyMemGuard{}
	g.setBudget(1) // 1 MiB
	if !g.reserve(100) || !g.reserve(1<<20 - 100) {
		t.Fatal("reserving up to the budget must succeed")
	}
	if g.reserve(1) {
		t.Fatal("reserve past the budget must fail (fail-closed)")
	}
	g.release(1 << 20)
	if !g.reserve(1) {
		t.Fatal("release must return credit")
	}
	if g.inUseBytes() != 1 {
		t.Fatalf("inUse = %d, want 1", g.inUseBytes())
	}
	g.release(99) // over-release must clamp, never go negative
	if g.inUseBytes() != 0 {
		t.Fatalf("inUse after over-release = %d, want 0", g.inUseBytes())
	}
	g.setBudget(-1) // unlimited
	if !g.reserve(1 << 40) {
		t.Fatal("unlimited budget must accept any reservation")
	}
	g.release(1 << 40)
}
// TestBufferBodyLargeLimitLargeBodyForwards is the regression for large site
// limits (32 MiB) with a body under that limit: the body must be buffered,
// inspected and forwarded intact (the unified read loop replaced the old
// direct-alloc fast path). Body size is kept at 2 MiB 鈥?the CRS scan of a
// urlencoded body dominates the runtime (~6 MB/s through coraza's URLENC
// processor, pre-existing engine characteristic) and a full 12 MiB would
// make the suite pay ~70s.
func TestBufferBodyLargeLimitLargeBodyForwards(t *testing.T) {
	const size = 2 << 20
	var got int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		got = n
		_, _ = w.Write([]byte("ok"))
	}))
	defer up.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF:      &config.WAFSettings{BodyLimitBytes: 32 << 20},
		}},
	}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	h, err := NewReloadableObserved(cfg, nil, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("x", size)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://t.local/push", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (server log: %s)", rec.Code, logBuf.String())
	}
	if got != size {
		t.Fatalf("upstream received %d bytes, want %d (truncated body)", got, size)
	}
}
// TestBufferBodyLargeBodyTimingNoWAF isolates the forwarding cost: with the
// WAF stage off, buffering + forwarding a 12 MiB body must be fast (the
// 70s observed with the WAF on points at full-CRS scanning of the buffered
// body, not at the proxy path).
func TestBufferBodyLargeBodyTimingNoWAF(t *testing.T) {
	const size = 12 << 20
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte("ok"))
	}))
	defer up.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF:      &config.WAFSettings{Enabled: wafOff().Enabled, BodyLimitBytes: 32 << 20},
		}},
	}
	h, err := NewReloadableObserved(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("x", size)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://t.local/push", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	start := time.Now()
	h.ServeHTTP(rec, req)
	t.Logf("no-waf 12MiB: status=%d elapsed=%v", rec.Code, time.Since(start))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("no-waf large-body path took %v, want < 5s", d)
	}
}
// TestBodyInspectWindowBoundsCPU pins the engine inspection window: a body
// under the site limit but larger than the window is only engine-scanned up
// to body_inspect_bytes (default 1 MiB) 鈥?full-CRS scanning of urlencoded
// bodies costs ~170 KB/s, so without the window a 2 MiB request burns ~12
// CPU-seconds. The full body must still forward intact and the partial
// inspection must be marked (body_skip=prefix).
func TestBodyInspectWindowBoundsCPU(t *testing.T) {
	const size = 2 << 20
	var got int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		got = n
		_, _ = w.Write([]byte("ok"))
	}))
	defer up.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF:      &config.WAFSettings{BodyLimitBytes: 32 << 20}, // inspect window = default 1 MiB
		}},
	}
	audit := &captureStore{}
	sink := &memSink{}
	h, err := NewReloadableObserved(cfg, audit, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	h.SetAccessSink(sink)

	body := strings.Repeat("x", size)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://t.local/push", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	start := time.Now()
	h.ServeHTTP(rec, req)
	elapsed := time.Since(start)
	t.Logf("windowed 2MiB scan: status=%d elapsed=%v", rec.Code, elapsed)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if elapsed > 4*time.Second {
		if raceDetectorEnabled {
			// The correctness assertions above still ran; only the CPU budget
			// is unmeasurable under -race (the detector serialises the CRS
			// engine and inflates this scan by an order of magnitude).
			t.Logf("skipping CPU budget under -race: elapsed=%v", elapsed)
		} else {
			t.Fatalf("windowed scan took %v, want < 4s (window must bound engine CPU)", elapsed)
		}
	}
	if got != size {
		t.Fatalf("upstream received %d bytes, want %d (window must not truncate forwarding)", got, size)
	}
	entries := sink.snapshot()
	if len(entries) != 1 {
		t.Fatalf("access entries = %d, want 1", len(entries))
	}
	if e := entries[0]; e.BodySkip != "prefix" {
		t.Fatalf("body_skip = %q, want prefix (partial inspection must be marked)", e.BodySkip)
	}
}

// TestBodyInspectWindowStillDetectsPrefixSQLi pins that windowing does not
// blind the engine to attacks inside the inspected prefix: a SQLi payload
// at the head of a window-exceeding urlencoded body is still blocked.
func TestBodyInspectWindowStillDetectsPrefixSQLi(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer up.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF:      &config.WAFSettings{BodyLimitBytes: 32 << 20},
		}},
	}
	h, err := NewReloadableObserved(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	body := "uname=admin%27+or+%271%27%3D%271&pad=" + strings.Repeat("x", 2<<20)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://t.local/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("prefix SQLi status = %d, want 403 (window must not blind the engine)", rec.Code)
	}
}

// TestBodyInspectWindowFullScanEscape pins the escape hatch: with
// body_inspect_bytes >= the body size the body is fully inspected and no
// skip marker is recorded (legacy full-scan behavior).
func TestBodyInspectWindowFullScanEscape(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte("ok"))
	}))
	defer up.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF:      &config.WAFSettings{BodyLimitBytes: 32 << 20, BodyInspectBytes: 4 << 20},
		}},
	}
	sink := &memSink{}
	h, err := NewReloadableObserved(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	h.SetAccessSink(sink)

	body := strings.Repeat("x", 2<<20)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://t.local/push", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	entries := sink.snapshot()
	if len(entries) != 1 {
		t.Fatalf("access entries = %d, want 1", len(entries))
	}
	if e := entries[0]; e.BodySkip != "" {
		t.Fatalf("body_skip = %q, want empty (full inspection, no marker)", e.BodySkip)
	}
}
// TestBodyStreamPathsOverrideReject pins the two-state upload policy end to
// end: a declared body_stream_paths prefix streams an over-limit body through
// to the upstream after a prefix inspection (access log body_skip=prefix)
// instead of answering 413, while an undeclared path on the same site still
// rejects with 413.
func TestBodyStreamPathsOverrideReject(t *testing.T) {
	const size = 4096
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		if int64(len(got)) != size {
			t.Errorf("upstream got %d bytes, want %d", len(got), size)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer up.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF: &config.WAFSettings{
				BodyLimitBytes:   128,
				BodyInspectBytes: 128,
				BodyStreamPaths:  []string{"/v1/upload"},
			},
		}},
	}
	audit := &captureStore{}
	sink := &memSink{}
	h, err := NewReloadableObserved(cfg, audit, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	h.SetAccessSink(sink)

	body := bytes.Repeat([]byte("x"), size)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://t.local/v1/upload/file", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("declared stream path must not be rejected: status = %d body=%q", rec.Code, rec.Body.String())
	}
	entries := sink.snapshot()
	if len(entries) != 1 {
		t.Fatalf("access entries = %d, want 1", len(entries))
	}
	if e := entries[0]; e.Outcome != "forwarded" || e.BodySkip != "prefix" {
		t.Fatalf("access log wrong: outcome=%q body_skip=%q, want forwarded/prefix", e.Outcome, e.BodySkip)
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "http://t.local/other", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("undeclared path status = %d, want 413", rec2.Code)
	}
}
