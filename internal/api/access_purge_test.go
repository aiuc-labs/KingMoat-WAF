package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/accesslog"
	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
)

// accessHistoryPost posts a JSON-object endpoint with the given client.
func accessHistoryPost(t *testing.T, client *http.Client, url string) (int, map[string]any) {
	t.Helper()
	resp, err := client.Post(url, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode %s: %v (%s)", url, err, raw)
		}
	}
	return resp.StatusCode, body
}

// accessPurgeServer mirrors accessHistoryServer with the local-database path
// wired (AccessLocalDB), so the recorder-off shapes can exercise the on-disk
// stats/purge path exactly like the all-in-one assembly does.
func accessPurgeServer(t *testing.T, cfg *config.Config, sinkPtr *atomic.Pointer[accesslog.SQLiteSink], dbPath string) *httptest.Server {
	t.Helper()
	hash := probeTestHash("hunter2")
	center, err := configcenter.Open(t.TempDir()+"/access-purge-test.db", cfg, nil)
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
	}
	if sinkPtr != nil {
		opts.AccessLocalFn = func() *accesslog.SQLiteSink { return sinkPtr.Load() }
	}
	srv := New(opts)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// TestAccessPurgeRBACAndEffect pins the destructive endpoint's gate and
// effect: unauthenticated 401, non-admin 403, admin 200 with the purged row
// count, the store actually emptied (record.rows zeroed) and a repeat purge
// answering purged=0.
func TestAccessPurgeRBACAndEffect(t *testing.T) {
	sink := newAccessHistorySink(t, config.AccessLogRecordSettings{Mode: "all"})
	writeAccessEntries(t, sink, []accesslog.Entry{
		accessEntry(0, "a.local", "/p1", "forwarded", "10.1.1.1"),
		accessEntry(0, "a.local", "/p2", "forwarded", "10.1.1.2"),
	})
	sinkPtr := accessHistorySinkPtr()
	sinkPtr.Store(sink)
	ts, _ := accessHistoryServer(t, seedCfg(), sinkPtr, nil)
	client := accessHistoryLogin(t, ts, "admin", "hunter2")

	// Unauthenticated → 401 (console auth middleware).
	resp, err := http.Post(ts.URL+"/api/access_logs/purge", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated purge = %d, want 401", resp.StatusCode)
	}

	// Auditor (read-only floor) → 403.
	aud := accessHistoryLogin(t, ts, "aud", "aud-pass")
	if code, _ := accessHistoryPost(t, aud, ts.URL+"/api/access_logs/purge"); code != http.StatusForbidden {
		t.Fatalf("auditor purge = %d, want 403", code)
	}
	// The rejected attempt must not have deleted anything.
	if rows, err := sink.Rows(); err != nil || rows != 2 {
		t.Fatalf("rejected purge must not delete (rows=%d, err=%v)", rows, err)
	}

	// Admin → 200 with the purged count and a zeroed record.rows.
	code, body := accessHistoryPost(t, client, ts.URL+"/api/access_logs/purge")
	if code != http.StatusOK {
		t.Fatalf("admin purge = %d, want 200", code)
	}
	if body["purged"].(float64) != 2 {
		t.Fatalf("purged = %v, want 2", body["purged"])
	}
	rec := accessRecordOf(t, body)
	if rec["rows"].(float64) != 0 {
		t.Fatalf("record.rows after purge = %v, want 0", rec["rows"])
	}
	if rec["enabled"] != true {
		t.Fatalf("record.enabled after purge = %v, want true (recording stays on)", rec["enabled"])
	}
	// Repeat purge: idempotent zero.
	code, body = accessHistoryPost(t, client, ts.URL+"/api/access_logs/purge")
	if code != http.StatusOK || body["purged"].(float64) != 0 {
		t.Fatalf("repeat purge = %d/%v, want 200/0", code, body["purged"])
	}
}

// TestAccessPurgeRecordingOffSafe: with recording switched off the sink is
// detached, but the on-disk database is still purgeable (and the purged
// count honest); a missing file and an unwired path answer safely.
func TestAccessPurgeRecordingOffSafe(t *testing.T) {
	t.Run("off with data on disk", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "access-logs.db")
		sink, err := accesslog.NewSQLiteSink(dbPath, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, nil)
		if err != nil {
			t.Fatal(err)
		}
		writeAccessEntries(t, sink, []accesslog.Entry{
			accessEntry(0, "a.local", "/kept", "forwarded", "10.1.1.1"),
			accessEntry(0, "a.local", "/kept2", "forwarded", "10.1.1.2"),
			accessEntry(0, "a.local", "/kept3", "forwarded", "10.1.1.3"),
		})
		_ = sink.Close() // recording off: instance detached, data stays

		sinkPtr := accessHistorySinkPtr() // stays nil
		ts := accessPurgeServer(t, seedCfg(), sinkPtr, dbPath)
		client := accessHistoryLogin(t, ts, "admin", "hunter2")

		// The record object still reports the kept rows (visible after off).
		_, body := accessHistoryGet(t, client, ts.URL+"/api/access_logs/history")
		rec := accessRecordOf(t, body)
		if rec["enabled"] != false || rec["rows"].(float64) != 3 {
			t.Fatalf("record after off = %v, want enabled=false rows=3", rec)
		}
		if _, ok := rec["oldest_ts"].(string); !ok {
			t.Fatalf("record.oldest_ts missing after off: %v", rec)
		}

		code, body := accessHistoryPost(t, client, ts.URL+"/api/access_logs/purge")
		if code != http.StatusOK || body["purged"].(float64) != 3 {
			t.Fatalf("off-disk purge = %d/%v, want 200/3", code, body["purged"])
		}
		rec = accessRecordOf(t, body)
		if rec["rows"].(float64) != 0 {
			t.Fatalf("record.rows after off-disk purge = %v, want 0", rec["rows"])
		}
	})
	t.Run("no database file", func(t *testing.T) {
		ts := accessPurgeServer(t, seedCfg(), accessHistorySinkPtr(), filepath.Join(t.TempDir(), "absent.db"))
		client := accessHistoryLogin(t, ts, "admin", "hunter2")
		code, body := accessHistoryPost(t, client, ts.URL+"/api/access_logs/purge")
		if code != http.StatusOK || body["purged"].(float64) != 0 {
			t.Fatalf("purge without a database file = %d/%v, want 200/0", code, body["purged"])
		}
	})
	t.Run("path not wired (static assembly)", func(t *testing.T) {
		ts, _ := accessHistoryServer(t, seedCfg(), accessHistorySinkPtr(), nil)
		client := accessHistoryLogin(t, ts, "admin", "hunter2")
		code, body := accessHistoryPost(t, client, ts.URL+"/api/access_logs/purge")
		if code != http.StatusOK || body["purged"].(float64) != 0 {
			t.Fatalf("purge without a wired path = %d/%v, want 200/0", code, body["purged"])
		}
	})
}

// TestAccessPurgeFailureStaysGeneric pins RC-4: a purge that fails at the
// database level (a directory where the database file should be) answers a
// 500 whose body is the generic Chinese message — never the raw error with
// the absolute database path or the accesslog internals.
func TestAccessPurgeFailureStaysGeneric(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "not-a-database")
	if err := os.Mkdir(dbPath, 0o755); err != nil {
		t.Fatal(err)
	}
	ts := accessPurgeServer(t, seedCfg(), accessHistorySinkPtr(), dbPath)
	client := accessHistoryLogin(t, ts, "admin", "hunter2")

	code, body := accessHistoryPost(t, client, ts.URL+"/api/access_logs/purge")
	if code != http.StatusInternalServerError {
		t.Fatalf("purge on an unusable database = %d, want 500", code)
	}
	msg, _ := body["error"].(string)
	if msg == "" {
		t.Fatal("error body missing")
	}
	if strings.Contains(msg, dbPath) || strings.Contains(msg, dir) || strings.Contains(msg, "accesslog:") {
		t.Fatalf("error must not leak the database path or internals (RC-4): %q", msg)
	}
	if !strings.Contains(msg, "本地访问日志清空失败") {
		t.Fatalf("error must be the generic Chinese message, got %q", msg)
	}
}

// TestAccessRecordStatusRowsOldestDropped pins the record object's new
// fields against the live sink truth: rows/oldest_ts match the stored data
// and dropped mirrors the sink's own drop counter (L3).
func TestAccessRecordStatusRowsOldestDropped(t *testing.T) {
	sink := newAccessHistorySink(t, config.AccessLogRecordSettings{Mode: "all"})
	writeAccessEntries(t, sink, []accesslog.Entry{
		accessEntry(-2*time.Hour, "a.local", "/older", "forwarded", "10.1.1.1"),
		accessEntry(0, "a.local", "/newer", "forwarded", "10.1.1.2"),
	})
	sinkPtr := accessHistorySinkPtr()
	sinkPtr.Store(sink)
	ts, _ := accessHistoryServer(t, seedCfg(), sinkPtr, nil)
	client := accessHistoryLogin(t, ts, "admin", "hunter2")

	_, body := accessHistoryGet(t, client, ts.URL+"/api/access_logs/history")
	rec := accessRecordOf(t, body)
	if rec["rows"].(float64) != 2 {
		t.Fatalf("record.rows = %v, want 2", rec["rows"])
	}
	oldest, ok := rec["oldest_ts"].(string)
	if !ok || oldest == "" {
		t.Fatalf("record.oldest_ts missing: %v", rec)
	}
	ot, err := time.Parse(time.RFC3339, oldest)
	if err != nil {
		t.Fatalf("record.oldest_ts not RFC3339: %q", oldest)
	}
	if want, _ := sink.OldestTS(); want.Sub(ot).Abs() > time.Second {
		t.Fatalf("record.oldest_ts = %v, want the sink value %v", ot, want)
	}
	if rec["dropped"].(float64) != float64(sink.Dropped()) {
		t.Fatalf("record.dropped = %v, want the sink value %d", rec["dropped"], sink.Dropped())
	}
}

// TestAccessPurgeCloseRaceFallsBackToLocal pins the purge half of the same
// close-race class: the admin purge must survive the publish path closing
// the sink between the accessor read and PurgeAll by falling through to the
// on-disk purge instead of answering a one-shot 500.
func TestAccessPurgeCloseRaceFallsBackToLocal(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "access-logs.db")
	sinkA, err := accesslog.NewSQLiteSink(dbPath, config.AccessLogRecordSettings{Mode: "all"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeAccessEntries(t, sinkA, []accesslog.Entry{
		accessEntry(-time.Minute, "a.local", "/purge-race-1", "forwarded", "10.1.1.1"),
		accessEntry(0, "a.local", "/purge-race-2", "blocked", "10.1.1.2"),
	})
	if err := sinkA.Close(); err != nil {
		t.Fatal(err)
	}

	// The handler grabs the stale (already closed) sink, PurgeAll fails on
	// the closed store, and the retry accessor call sees the detached state.
	var calls atomic.Int32
	fn := func() *accesslog.SQLiteSink {
		if calls.Add(1) == 1 {
			return sinkA
		}
		return nil
	}
	ts := accessCloseRaceServer(t, seedCfg(), fn, dbPath)
	client := accessHistoryLogin(t, ts, "admin", "hunter2")
	code, body := accessHistoryPost(t, client, ts.URL+"/api/access_logs/purge")
	if code != http.StatusOK {
		t.Fatalf("close-race purge = %d, want 200 (on-disk purge fallback)", code)
	}
	if body["purged"].(float64) != 2 {
		t.Fatalf("close-race purged = %v, want 2", body["purged"])
	}
}
