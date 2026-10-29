package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/accesslog"
	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/store"
)

// accessHistorySinkPtr mirrors the main.go wiring shape (an atomic sink
// pointer read through the Options.AccessLocalFn closure) so the tests can
// hot-swap instances exactly like rebuildLocalAccess does on publish.
func accessHistorySinkPtr() *atomic.Pointer[accesslog.SQLiteSink] {
	return &atomic.Pointer[accesslog.SQLiteSink]{}
}

// accessHistoryServer builds an auth-enabled console server seeded with
// admin + auditor accounts, with the local-recorder accessor reading the
// given pointer (nil pointer arg = no AccessLocalFn wired at all, the
// static-assembly shape) and an optional live-tail ring.
func accessHistoryServer(t *testing.T, cfg *config.Config, sinkPtr *atomic.Pointer[accesslog.SQLiteSink], ring *accesslog.Ring) (*httptest.Server, *configcenter.Center) {
	t.Helper()
	hash := probeTestHash("hunter2")
	center, err := configcenter.Open(t.TempDir()+"/access-history-test.db", cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	seedStoreAdmin(t, center, hash)
	if _, err := center.Store().CreateUser("aud", probeTestHash("aud-pass"), store.RoleAuditor); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		SkipBootstrap: true,
		Center:        center,
		Auth:          NewAuth(hash),
		AccessRing:    ring,
	}
	if sinkPtr != nil {
		opts.AccessLocalFn = func() *accesslog.SQLiteSink { return sinkPtr.Load() }
	}
	srv := New(opts)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, center
}

// accessHistoryLogin returns a cookie-authenticated client (admin unless
// stated otherwise).
func accessHistoryLogin(t *testing.T, ts *httptest.Server, user, pass string) *http.Client {
	t.Helper()
	resp, err := http.Post(ts.URL+"/api/login", "application/json",
		bytes.NewReader(mustJSON(t, map[string]string{"username": user, "password": pass})))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %s = %d", user, resp.StatusCode)
	}
	return &http.Client{Transport: roundTripperWithCookie{cookie: resp.Cookies()[0]}}
}

// accessHistoryGet fetches a JSON object endpoint with the given client.
func accessHistoryGet(t *testing.T, client *http.Client, url string) (int, map[string]any) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return resp.StatusCode, body
}

// accessRecordOf extracts the record object from a response body.
func accessRecordOf(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	rec, ok := body["record"].(map[string]any)
	if !ok {
		t.Fatalf("record object missing from response: %v", body)
	}
	return rec
}

// newAccessHistorySink builds a real SQLite recorder in a temp dir.
func newAccessHistorySink(t *testing.T, rec config.AccessLogRecordSettings) *accesslog.SQLiteSink {
	t.Helper()
	sink, err := accesslog.NewSQLiteSink(filepath.Join(t.TempDir(), "access-logs.db"), rec, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	return sink
}

// writeAccessEntries queues entries and waits until they are committed.
// The flush window is deliberately generous: the batch writer commits on a
// 1s ticker (access_log_record flush_sec default) and single entries never
// fill the 256-entry batch, so every write waits out one full tick — and
// under a fully loaded machine (the whole suite running in parallel)
// goroutine scheduling plus the WAL commit can eat into that budget. The
// previous tight 2s window left only ~1s of slack and was observed as a
// load-dependent flaky failure ("flush timeout with pending entries").
// A Flush timeout is NOT a lost-batch signal (the writer keeps draining
// the queue), so one long bounded window is enough. The Dropped baseline
// pins the silent-drop paths (queue overflow / close race / disk guard):
// without it a dropped entry would surface later as a meaningless
// "total = 0" assertion failure instead of the root cause.
func writeAccessEntries(t *testing.T, sink *accesslog.SQLiteSink, entries []accesslog.Entry) {
	t.Helper()
	for i := range entries {
		sink.Write(&entries[i])
	}
	if err := sink.Flush(15 * time.Second); err != nil {
		t.Fatalf("access-log entries not committed within 15s: %v (dropped=%d pending=%d)",
			err, sink.Dropped(), sink.Pending())
	}
	if n := sink.Dropped(); n != 0 {
		t.Fatalf("access-log sink dropped %d entries before commit (queue overflow/close race/disk guard)", n)
	}
}

// accessEntry builds an entry with an RFC3339Nano timestamp offset from now.
func accessEntry(offset time.Duration, site, path, outcome, ip string) accesslog.Entry {
	return accesslog.Entry{
		TS:       time.Now().Add(offset).UTC().Format(time.RFC3339Nano),
		Site:     site,
		Path:     path,
		Outcome:  outcome,
		ClientIP: ip,
		Method:   "GET",
		Status:   200,
	}
}

// TestAccessHistoryPagingAndFilters covers the paged-mode response shape
// (items/total/page/page_size) and every filter parameter of
// GET /api/access_logs/history against a real SQLite recorder.
func TestAccessHistoryPagingAndFilters(t *testing.T) {
	sink := newAccessHistorySink(t, config.AccessLogRecordSettings{Mode: "all"})
	writeAccessEntries(t, sink, []accesslog.Entry{
		accessEntry(-time.Hour, "a.local", "/pay/confirm", "blocked", "10.1.1.1"),
		accessEntry(-30*time.Minute, "a.local", "/health", "forwarded", "10.1.1.2"),
		accessEntry(0, "a.local", "/pay/confirm", "blocked", "10.2.2.2"),
		accessEntry(0, "shop.example.com", "/pay/confirm", "forwarded", "203.0.113.5"),
		accessEntry(0, "shop.example.com", "/other", "blocked", "10.1.1.1"),
	})
	sinkPtr := accessHistorySinkPtr()
	sinkPtr.Store(sink)
	cfg := seedCfg()
	cfg.AccessLogRecord = &config.AccessLogRecordSettings{Mode: "all"}
	ts, center := accessHistoryServer(t, seedCfg(), sinkPtr, nil)
	if _, err := center.Publish(cfg, "test", "record on"); err != nil {
		t.Fatal(err)
	}
	client := accessHistoryLogin(t, ts, "admin", "hunter2")

	get := func(query string) (int, map[string]any) {
		return accessHistoryGet(t, client, ts.URL+"/api/access_logs/history"+query)
	}
	items := func(body map[string]any) []any {
		arr, ok := body["items"].([]any)
		if !ok {
			t.Fatalf("items missing or not a list: %v", body)
		}
		return arr
	}

	// Unpaged query: full result set, default page shape present.
	code, body := get("")
	if code != http.StatusOK {
		t.Fatalf("history = %d, want 200", code)
	}
	if body["total"].(float64) != 5 || len(items(body)) != 5 {
		t.Fatalf("total/items = %v/%d, want 5/5", body["total"], len(items(body)))
	}
	if body["page"].(float64) != 1 || body["page_size"].(float64) != 100 {
		t.Fatalf("page/page_size = %v/%v, want 1/100", body["page"], body["page_size"])
	}

	// Paging windows.
	_, body = get("?page=1&page_size=2")
	if body["total"].(float64) != 5 || len(items(body)) != 2 ||
		body["page"].(float64) != 1 || body["page_size"].(float64) != 2 {
		t.Fatalf("page 1 = %v", body)
	}
	_, body = get("?page=3&page_size=2")
	if body["total"].(float64) != 5 || len(items(body)) != 1 {
		t.Fatalf("page 3 = %v", body)
	}
	// Newest first: page 3 (5th row) is the oldest entry.
	first := items(body)[0].(map[string]any)
	if first["path"] != "/pay/confirm" || first["site"] != "a.local" {
		t.Fatalf("last page first row = %v, want the oldest /pay/confirm entry", first)
	}

	// Filters.
	_, body = get("?outcome=blocked")
	if body["total"].(float64) != 3 {
		t.Fatalf("outcome=blocked total = %v, want 3", body["total"])
	}
	_, body = get("?site=shop")
	if body["total"].(float64) != 2 {
		t.Fatalf("site=shop total = %v, want 2", body["total"])
	}
	_, body = get("?ip=10.2.")
	if body["total"].(float64) != 1 {
		t.Fatalf("ip prefix total = %v, want 1", body["total"])
	}
	_, body = get("?q=/pay")
	if body["total"].(float64) != 3 {
		t.Fatalf("q=/pay total = %v, want 3", body["total"])
	}
	_, body = get("?site=a.local&outcome=blocked")
	if body["total"].(float64) != 2 {
		t.Fatalf("combined filter total = %v, want 2", body["total"])
	}

	// RFC3339 time window: mid-point between the oldest and newest rows.
	mid := time.Now().Add(-15 * time.Minute).UTC().Format(time.RFC3339)
	_, body = get("?since=" + mid)
	if body["total"].(float64) != 3 {
		t.Fatalf("since total = %v, want 3", body["total"])
	}
	_, body = get("?until=" + mid)
	if body["total"].(float64) != 2 {
		t.Fatalf("until total = %v, want 2", body["total"])
	}

	// The record object is always present and reflects the live sink.
	rec := accessRecordOf(t, body)
	if rec["enabled"] != true {
		t.Fatalf("record.enabled = %v, want true", rec["enabled"])
	}
	if rec["mode"] != "all" {
		t.Fatalf("record.mode = %v, want all", rec["mode"])
	}
}

// TestAccessHistoryRecordingOffSafe proves the never-500 contract: without
// the accessor wired, with the accessor returning nil, and with the config
// section present but the recorder missing (failed rebuild degradation), the
// endpoint answers 200 with an empty page and record.enabled=false.
func TestAccessHistoryRecordingOffSafe(t *testing.T) {
	cases := []struct {
		name    string
		sinkPtr *atomic.Pointer[accesslog.SQLiteSink]
		record  *config.AccessLogRecordSettings
	}{
		{"no accessor wired (static assembly)", nil, nil},
		{"accessor returns nil (recording off)", accessHistorySinkPtr(), nil},
		{"section published but sink missing (failed rebuild)", accessHistorySinkPtr(),
			&config.AccessLogRecordSettings{Mode: "all"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Open with a plain seed (no section); the record case publishes
			// the section afterwards (the seed import would otherwise make
			// the publish a no-change error).
			ts, center := accessHistoryServer(t, seedCfg(), tc.sinkPtr, nil)
			if tc.record != nil {
				cfg := seedCfg()
				cfg.AccessLogRecord = tc.record
				if _, err := center.Publish(cfg, "test", "record section"); err != nil {
					t.Fatal(err)
				}
			}
			client := accessHistoryLogin(t, ts, "admin", "hunter2")
			code, body := accessHistoryGet(t, client, ts.URL+"/api/access_logs/history")
			if code != http.StatusOK {
				t.Fatalf("history = %d, want 200", code)
			}
			arr, ok := body["items"].([]any)
			if !ok || len(arr) != 0 {
				t.Fatalf("items = %v, want empty list", body["items"])
			}
			if body["total"].(float64) != 0 {
				t.Fatalf("total = %v, want 0", body["total"])
			}
			rec := accessRecordOf(t, body)
			if rec["enabled"] != false {
				t.Fatalf("record.enabled = %v, want false", rec["enabled"])
			}
			if rec["size_bytes"].(float64) != 0 || rec["evicted"].(float64) != 0 {
				t.Fatalf("record usage counters = %v/%v, want 0/0", rec["size_bytes"], rec["evicted"])
			}
			// mode reflects the published section ("all" in the degraded
			// case — the config is honest even though the recorder is off).
			wantMode := "off"
			if tc.record != nil {
				wantMode = "all"
			}
			if rec["mode"] != wantMode {
				t.Fatalf("record.mode = %v, want %q", rec["mode"], wantMode)
			}
		})
	}
}

// TestAccessHistoryRBAC pins the access level: console authentication is
// required (unauthenticated → 401) and the auditor role — the read-only
// floor — is accepted, matching GET /api/access_logs (no elevated gate).
func TestAccessHistoryRBAC(t *testing.T) {
	sink := newAccessHistorySink(t, config.AccessLogRecordSettings{Mode: "all"})
	sinkPtr := accessHistorySinkPtr()
	sinkPtr.Store(sink)
	ts, _ := accessHistoryServer(t, seedCfg(), sinkPtr, nil)

	// Unauthenticated → 401 (console auth middleware; plain-text body).
	resp, err := http.Get(ts.URL + "/api/access_logs/history")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated history = %d, want 401", resp.StatusCode)
	}
	// Auditor (lowest role) is accepted — same level as /api/access_logs.
	aud := accessHistoryLogin(t, ts, "aud", "aud-pass")
	code, _ := accessHistoryGet(t, aud, ts.URL+"/api/access_logs/history")
	if code != http.StatusOK {
		t.Fatalf("auditor history = %d, want 200 (same RBAC level as /api/access_logs)", code)
	}
	code, _ = accessHistoryGet(t, aud, ts.URL+"/api/access_logs")
	if code != http.StatusOK {
		t.Fatalf("auditor tail = %d, want 200", code)
	}
}

// TestAccessRecordStatusTruth verifies the record object reports the live
// sink truth: size_bytes/evicted come from the sink instance itself, and the
// config-derived fields (mode/retention_days/max_disk_mb) mirror the
// published access_log_record section. Both access-log endpoints carry it.
func TestAccessRecordStatusTruth(t *testing.T) {
	cfg := seedCfg()
	cfg.AccessLogRecord = &config.AccessLogRecordSettings{
		Mode:          "sites",
		Sites:         []string{"a.local"},
		RetentionDays: 30,
		MaxDiskMB:     512,
	}
	sink := newAccessHistorySink(t, *cfg.AccessLogRecord)
	writeAccessEntries(t, sink, []accesslog.Entry{
		accessEntry(0, "a.local", "/truth", "blocked", "10.1.1.9"),
	})
	sinkPtr := accessHistorySinkPtr()
	sinkPtr.Store(sink)
	ts, center := accessHistoryServer(t, seedCfg(), sinkPtr, nil)
	if _, err := center.Publish(cfg, "test", "record section"); err != nil {
		t.Fatal(err)
	}
	client := accessHistoryLogin(t, ts, "admin", "hunter2")

	code, body := accessHistoryGet(t, client, ts.URL+"/api/access_logs/history")
	if code != http.StatusOK {
		t.Fatalf("history = %d, want 200", code)
	}
	rec := accessRecordOf(t, body)
	if rec["enabled"] != true || rec["mode"] != "sites" {
		t.Fatalf("record enabled/mode = %v/%v, want true/sites", rec["enabled"], rec["mode"])
	}
	if rec["retention_days"].(float64) != 30 || rec["max_disk_mb"].(float64) != 512 {
		t.Fatalf("record retention/max_disk = %v/%v, want 30/512", rec["retention_days"], rec["max_disk_mb"])
	}
	if sb := rec["size_bytes"].(float64); sb <= 0 || int64(sb) != sink.SizeBytes() {
		t.Fatalf("record.size_bytes = %v, want the live sink value %d", rec["size_bytes"], sink.SizeBytes())
	}
	if ev := rec["evicted"].(float64); int64(ev) != sink.Evicted() {
		t.Fatalf("record.evicted = %v, want the live sink value %d", rec["evicted"], sink.Evicted())
	}

	// The memory-tail endpoint carries the same record object even when the
	// live-tail ring is not wired (the two features are independent).
	code, body = accessHistoryGet(t, client, ts.URL+"/api/access_logs")
	if code != http.StatusOK {
		t.Fatalf("tail = %d, want 200", code)
	}
	if body["enabled"] != false {
		t.Fatalf("tail enabled = %v, want false (ring not wired)", body["enabled"])
	}
	if _, ok := body["hint"].(string); !ok {
		t.Fatalf("tail hint missing: %v", body)
	}
	rec = accessRecordOf(t, body)
	if rec["enabled"] != true {
		t.Fatalf("tail record.enabled = %v, want true (recorder running)", rec["enabled"])
	}
}

// TestAccessHistoryLazyAccessorHotSwap proves the accessor is resolved per
// request: after the hot swap (the publish path replaces the sink instance
// behind the atomic pointer), the same server serves the NEW instance's data
// and never the detached one.
func TestAccessHistoryLazyAccessorHotSwap(t *testing.T) {
	sinkPtr := accessHistorySinkPtr()
	ts, _ := accessHistoryServer(t, seedCfg(), sinkPtr, nil)
	client := accessHistoryLogin(t, ts, "admin", "hunter2")
	// get queries the history endpoint with a bounded retry for TRANSIENT
	// 5xx only: one handler call runs up to four 5s-deadline SQLite reads
	// (history count + rows, record rows/oldest_ts) on the sink's shared
	// read pool, and a fully loaded machine can starve one past its context
	// deadline — that is environment load, not the hot-swap contract under
	// test. Semantic failures (a 200 carrying the wrong/stale instance's
	// data) are never retried: they fail the assertions below directly.
	get := func() (int, map[string]any) {
		deadline := time.Now().Add(15 * time.Second)
		for {
			code, body := accessHistoryGet(t, client, ts.URL+"/api/access_logs/history")
			if code == http.StatusOK || time.Now().After(deadline) {
				return code, body
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Instance A.
	sinkA := newAccessHistorySink(t, config.AccessLogRecordSettings{Mode: "all"})
	writeAccessEntries(t, sinkA, []accesslog.Entry{
		accessEntry(0, "a.local", "/swap-a", "forwarded", "10.1.1.1"),
	})
	sinkPtr.Store(sinkA)
	code, body := get()
	if code != http.StatusOK || body["total"].(float64) != 1 {
		t.Fatalf("before swap: code=%d body=%v", code, body)
	}
	if first := body["items"].([]any)[0].(map[string]any); first["path"] != "/swap-a" {
		t.Fatalf("before swap items[0] = %v, want /swap-a", first)
	}

	// Hot swap to instance B (what rebuildLocalAccess does on publish).
	sinkB := newAccessHistorySink(t, config.AccessLogRecordSettings{Mode: "all"})
	writeAccessEntries(t, sinkB, []accesslog.Entry{
		accessEntry(0, "a.local", "/swap-b", "forwarded", "10.1.1.2"),
	})
	sinkPtr.Store(sinkB)
	_ = sinkA.Close()
	code, body = get()
	if code != http.StatusOK || body["total"].(float64) != 1 {
		t.Fatalf("after swap: code=%d body=%v", code, body)
	}
	if first := body["items"].([]any)[0].(map[string]any); first["path"] != "/swap-b" {
		t.Fatalf("after swap items[0] = %v, want /swap-b (stale instance served)", first)
	}

	// Detach (the off path): safe empty answer, no error.
	sinkPtr.Store(nil)
	_ = sinkB.Close()
	code, body = get()
	if code != http.StatusOK {
		t.Fatalf("after detach: code=%d, want 200", code)
	}
	if arr := body["items"].([]any); len(arr) != 0 {
		t.Fatalf("after detach items = %v, want empty", body["items"])
	}
	if rec := accessRecordOf(t, body); rec["enabled"] != false {
		t.Fatalf("after detach record.enabled = %v, want false", rec["enabled"])
	}
}

// TestAccessLogsTailRecordField pins the backward-compat contract of
// GET /api/access_logs: legacy fields (enabled/count/items/hint) unchanged,
// the new record object added alongside.
func TestAccessLogsTailRecordField(t *testing.T) {
	ring := accesslog.NewRing(10)
	ring.Write(&accesslog.Entry{TS: time.Now().UTC().Format(time.RFC3339Nano), Site: "a.local", Path: "/tail-1"})
	ring.Write(&accesslog.Entry{TS: time.Now().UTC().Format(time.RFC3339Nano), Site: "a.local", Path: "/tail-2"})
	sink := newAccessHistorySink(t, config.AccessLogRecordSettings{Mode: "all"})
	sinkPtr := accessHistorySinkPtr()
	sinkPtr.Store(sink)
	ts, _ := accessHistoryServer(t, seedCfg(), sinkPtr, ring)
	client := accessHistoryLogin(t, ts, "admin", "hunter2")

	// Ring + recorder: legacy shape intact, record reflects the sink.
	code, body := accessHistoryGet(t, client, ts.URL+"/api/access_logs")
	if code != http.StatusOK {
		t.Fatalf("tail = %d, want 200", code)
	}
	if body["enabled"] != true || body["count"].(float64) != 2 {
		t.Fatalf("tail enabled/count = %v/%v, want true/2", body["enabled"], body["count"])
	}
	if arr := body["items"].([]any); len(arr) != 2 {
		t.Fatalf("tail items = %d, want 2", len(arr))
	}
	if rec := accessRecordOf(t, body); rec["enabled"] != true {
		t.Fatalf("tail record.enabled = %v, want true", rec["enabled"])
	}

	// Recorder detached: legacy fields unchanged, record flips to disabled.
	sinkPtr.Store(nil)
	_ = sink.Close()
	code, body = accessHistoryGet(t, client, ts.URL+"/api/access_logs")
	if code != http.StatusOK {
		t.Fatalf("tail after detach = %d, want 200", code)
	}
	if body["enabled"] != true || body["count"].(float64) != 2 {
		t.Fatalf("tail legacy fields changed after detach: %v", body)
	}
	if rec := accessRecordOf(t, body); rec["enabled"] != false {
		t.Fatalf("tail record.enabled = %v, want false", rec["enabled"])
	}
}

// TestAccessHistoryFallbackAfterRecordingOff pins the residual-retrieval
// contract (关闭记录后残留数据必须可检索): with the sink detached the endpoint
// falls back to a READ-ONLY on-disk query — same parameters, same response
// shape, record.enabled=false with record.residual=true — while a missing or
// corrupt database degrades to a safe empty 200 page (never a 500, never
// error details).
func TestAccessHistoryFallbackAfterRecordingOff(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "access-logs.db")

	// Record residual data (including a sensitive query) with the live sink,
	// then detach it (the off-switch shape).
	sink, err := accesslog.NewSQLiteSink(dbPath, config.AccessLogRecordSettings{Mode: "all"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	entries := []accesslog.Entry{
		accessEntry(-time.Hour, "a.local", "/stale-1", "forwarded", "10.1.1.1"),
		accessEntry(-30*time.Minute, "a.local", "/stale-2", "blocked", "10.1.1.2"),
		accessEntry(0, "b.local", "/stale-3", "blocked", "10.1.1.3"),
	}
	e := accessEntry(0, "b.local", "/stale-4", "forwarded", "10.1.1.4")
	e.Query = "api_key=SECRET&page=2"
	entries = append(entries, e)
	writeAccessEntries(t, sink, entries)
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	// Recorder OFF (accessor returns nil), database path wired: the residual
	// data is fully queryable with the live-shape response.
	sinkPtr := accessHistorySinkPtr() // stays nil
	ts := accessPurgeServer(t, seedCfg(), sinkPtr, dbPath)
	client := accessHistoryLogin(t, ts, "admin", "hunter2")
	get := func(query string) (int, map[string]any) {
		return accessHistoryGet(t, client, ts.URL+"/api/access_logs/history"+query)
	}
	items := func(body map[string]any) []any {
		arr, ok := body["items"].([]any)
		if !ok {
			t.Fatalf("items missing or not a list: %v", body)
		}
		return arr
	}

	code, body := get("")
	if code != http.StatusOK {
		t.Fatalf("residual history = %d, want 200", code)
	}
	if body["total"].(float64) != 4 || len(items(body)) != 4 {
		t.Fatalf("residual total/items = %v/%d, want 4/4", body["total"], len(items(body)))
	}
	rec := accessRecordOf(t, body)
	if rec["enabled"] != false {
		t.Fatalf("record.enabled = %v, want false (recorder off)", rec["enabled"])
	}
	if rec["residual"] != true {
		t.Fatalf("record.residual = %v, want true (已停止记录但残留可检索)", rec["residual"])
	}
	if rec["rows"].(float64) != 4 {
		t.Fatalf("record.rows = %v, want 4", rec["rows"])
	}

	// Paging, filters and masking identical to the live sink.
	_, body = get("?page=2&page_size=3")
	if body["total"].(float64) != 4 || len(items(body)) != 1 {
		t.Fatalf("residual paging = %v", body)
	}
	_, body = get("?outcome=blocked")
	if body["total"].(float64) != 2 {
		t.Fatalf("residual outcome filter = %v, want 2", body["total"])
	}
	_, body = get("?site=b.local")
	if body["total"].(float64) != 2 {
		t.Fatalf("residual site filter = %v, want 2", body["total"])
	}
	first := items(body)[0].(map[string]any)
	if first["query"] != "api_key=***&page=2" {
		t.Fatalf("residual query = %v, want the masked text", first["query"])
	}
	// RFC3339 window works against the on-disk rows too.
	mid := time.Now().Add(-15 * time.Minute).UTC().Format(time.RFC3339)
	_, body = get("?since=" + url.QueryEscape(mid))
	if body["total"].(float64) != 2 {
		t.Fatalf("residual since filter = %v, want 2", body["total"])
	}

	// Missing database: safe empty page, residual=false.
	ts2 := accessPurgeServer(t, seedCfg(), accessHistorySinkPtr(), filepath.Join(dir, "missing.db"))
	client2 := accessHistoryLogin(t, ts2, "admin", "hunter2")
	code, body = accessHistoryGet(t, client2, ts2.URL+"/api/access_logs/history")
	if code != http.StatusOK || body["total"].(float64) != 0 || len(body["items"].([]any)) != 0 {
		t.Fatalf("missing-db history = %d/%v, want 200/empty", code, body)
	}
	if rec := accessRecordOf(t, body); rec["residual"] != false {
		t.Fatalf("missing-db residual = %v, want false", rec["residual"])
	}

	// Corrupt database: still 200 with an empty page (error swallowed into
	// the server log, never leaked to the client).
	corrupt := filepath.Join(dir, "corrupt.db")
	if err := os.WriteFile(corrupt, []byte("this is not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	ts3 := accessPurgeServer(t, seedCfg(), accessHistorySinkPtr(), corrupt)
	client3 := accessHistoryLogin(t, ts3, "admin", "hunter2")
	code, body = accessHistoryGet(t, client3, ts3.URL+"/api/access_logs/history")
	if code != http.StatusOK {
		t.Fatalf("corrupt-db history = %d, want 200 (safe degradation)", code)
	}
	if body["total"].(float64) != 0 || len(body["items"].([]any)) != 0 {
		t.Fatalf("corrupt-db history body = %v, want an empty page", body)
	}
}

// TestAccessHistoryMalformedTimeWindow pins the 400 contract (RC-3):
// malformed since/until values are rejected with 400 and a fixed Chinese
// message that never echoes the user input; a valid window stays 200.
func TestAccessHistoryMalformedTimeWindow(t *testing.T) {
	ts, _ := accessHistoryServer(t, seedCfg(), accessHistorySinkPtr(), nil)
	client := accessHistoryLogin(t, ts, "admin", "hunter2")
	for _, tc := range []struct{ param, value string }{
		{"since", "garbage"},
		{"until", "garbage"},
		{"since", "2026-13-99T00:00:00Z"}, // valid RFC3339 shape, invalid time
		{"until", "2026-10-13 08:00"},     // missing timezone/designator
	} {
		q := "?" + tc.param + "=" + url.QueryEscape(tc.value)
		code, body := accessHistoryGet(t, client, ts.URL+"/api/access_logs/history"+q)
		if code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", q, code)
		}
		raw, _ := json.Marshal(body)
		if strings.Contains(string(raw), tc.value) {
			t.Fatalf("400 body must not echo the user input %q: %s", tc.value, raw)
		}
		msg, _ := body["error"].(string)
		if !strings.Contains(msg, "参数无效") {
			t.Fatalf("400 message must be the fixed Chinese hint, got %q", msg)
		}
	}
	// Valid windows keep the 200 contract.
	valid := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	code, _ := accessHistoryGet(t, client, ts.URL+"/api/access_logs/history?since="+url.QueryEscape(valid))
	if code != http.StatusOK {
		t.Fatalf("valid since = %d, want 200", code)
	}
}

// accessCloseRaceServer is the closure variant of accessHistoryServer with
// the local-database path wired: it lets a test drive the accessor call
// sequence deterministically (the close-race shapes need the early calls to
// return a stale — already closed — sink and the retry call to see the
// detached state, exactly like rebuildLocalAccess nil'ing the pointer
// between an in-flight request's reads).
func accessCloseRaceServer(t *testing.T, cfg *config.Config, fn func() *accesslog.SQLiteSink, dbPath string) *httptest.Server {
	t.Helper()
	hash := probeTestHash("hunter2")
	center, err := configcenter.Open(t.TempDir()+"/access-close-race-test.db", cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	seedStoreAdmin(t, center, hash)
	opts := Options{
		SkipBootstrap: true,
		Center:        center,
		Auth:          NewAuth(hash),
		AccessLocalDB: dbPath,
		AccessLocalFn: fn,
	}
	srv := New(opts)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// TestAccessHistoryCloseRaceFallsBackToLocal pins the close half of the
// hot-swap contract (G-8): an in-flight history query that grabbed a sink
// which the publish path has since closed and detached must answer from the
// residual read-only chain — a 200 with the on-disk data — instead of a
// one-shot 500 that the console history view (no auto-refresh) would keep
// showing until the operator retries manually.
func TestAccessHistoryCloseRaceFallsBackToLocal(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "access-logs.db")
	sinkA, err := accesslog.NewSQLiteSink(dbPath, config.AccessLogRecordSettings{Mode: "all"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeAccessEntries(t, sinkA, []accesslog.Entry{
		accessEntry(0, "a.local", "/close-race", "forwarded", "10.1.1.1"),
	})
	if err := sinkA.Close(); err != nil {
		t.Fatal(err)
	}

	// Publish lands between the handler's sink read and the query: the first
	// two accessor calls (record status + sink grab) still see the stale
	// instance, the retry call sees the detached state.
	var calls atomic.Int32
	fn := func() *accesslog.SQLiteSink {
		if calls.Add(1) <= 2 {
			return sinkA
		}
		return nil
	}
	ts := accessCloseRaceServer(t, seedCfg(), fn, dbPath)
	client := accessHistoryLogin(t, ts, "admin", "hunter2")
	code, body := accessHistoryGet(t, client, ts.URL+"/api/access_logs/history")
	if code != http.StatusOK {
		t.Fatalf("close-race history = %d, want 200 (residual fallback, not a one-shot 500)", code)
	}
	if body["total"].(float64) != 1 {
		t.Fatalf("close-race total = %v, want 1", body["total"])
	}
	arr, ok := body["items"].([]any)
	if !ok || len(arr) != 1 {
		t.Fatalf("close-race items = %v, want one entry", body["items"])
	}
	if first := arr[0].(map[string]any); first["path"] != "/close-race" {
		t.Fatalf("close-race items[0].path = %v, want /close-race (residual data served)", first["path"])
	}
}
