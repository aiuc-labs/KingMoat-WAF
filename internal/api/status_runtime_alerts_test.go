package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite" // registered by the sink package too; needed for the BEGIN EXCLUSIVE lock helper

	"github.com/kingmoat/kingmoat/internal/accesslog"
	"github.com/kingmoat/kingmoat/internal/config"
)

// getStatusBody fetches a JSON object endpoint with the given client.
func getStatusBody(t *testing.T, client *http.Client, baseURL string) map[string]any {
	t.Helper()
	resp, err := client.Get(baseURL + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/status = %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// statusRuntimeAlerts extracts the runtime_alerts array from a status body
// (present=false when the key is omitted, the quiet contract).
func statusRuntimeAlerts(t *testing.T, body map[string]any) (arr []any, present bool) {
	t.Helper()
	raw, ok := body["runtime_alerts"]
	if !ok {
		return nil, false
	}
	arr, ok = raw.([]any)
	if !ok {
		t.Fatalf("runtime_alerts must be an array, got %T", raw)
	}
	return arr, true
}

// statusAlertWithCode returns the alert entry with the given code.
func statusAlertWithCode(t *testing.T, arr []any, code string) map[string]any {
	t.Helper()
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if !ok {
			t.Fatalf("runtime_alerts entry must be an object, got %T", it)
		}
		if m["code"] == code {
			return m
		}
	}
	t.Fatalf("runtime_alerts %v has no entry with code %q", arr, code)
	return nil
}

// newRuntimeAlertSink builds a real SQLite recorder (BatchSize=1: every Write
// forms a full batch, so the writer hits the database immediately — no
// ticker wait).
func newRuntimeAlertSink(t *testing.T) *accesslog.SQLiteSink {
	t.Helper()
	sink, err := accesslog.NewSQLiteSink(
		filepath.Join(t.TempDir(), "access-logs.db"),
		config.AccessLogRecordSettings{Mode: "all", BatchSize: 1, FlushSec: 1},
		nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	return sink
}

// newRuntimeAlertSinkBatched builds a recorder with small batches (slow
// drain relative to a flood of writes, for the queue-overflow path).
func newRuntimeAlertSinkBatched(t *testing.T) *accesslog.SQLiteSink {
	t.Helper()
	sink, err := accesslog.NewSQLiteSink(
		filepath.Join(t.TempDir(), "access-logs.db"),
		config.AccessLogRecordSettings{Mode: "all", BatchSize: 64, FlushSec: 1},
		nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	return sink
}

// newRuntimeAlertEntry builds a minimal recordable entry.
func newRuntimeAlertEntry(site, path string) *accesslog.Entry {
	return &accesslog.Entry{
		TS:       time.Now().UTC().Format(time.RFC3339Nano),
		Site:     site,
		Path:     path,
		Method:   "GET",
		Status:   200,
		Outcome:  "forwarded",
		ClientIP: "10.1.1.1",
	}
}

// installFailTrigger opens a SECOND connection on the sink's database and
// installs a BEFORE INSERT trigger that RAISE(ROLLBACK)s every statement: each
// sink insert fails at Exec AND its transaction is already rolled back when
// Commit runs, so the alert lands on the persistent failure path (raise
// without the trailing clear). A plain lock/busy failure only FLASHES the
// alert — the failed statements leave an empty transaction that still commits
// successfully, and the sink's success path clears the alert it just raised
// (registered as an accesslog defect, out of scope for this card). The
// sink's diskFree hook is package-private, so the watermark pause of
// internal/accesslog tests cannot be injected from here.
func installFailTrigger(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	const failTrigger = "access_runtime_alert_fail"
	if _, err := db.Exec("CREATE TRIGGER " + failTrigger + " BEFORE INSERT ON access\n" +
		"BEGIN SELECT RAISE(ROLLBACK, 'test-injected write failure'); END"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// waitForSinkAlert blocks until the given alert code appears in the sink
// snapshot (the writer fails asynchronously — the alert lands on its own
// goroutine).
func waitForSinkAlert(t *testing.T, sink *accesslog.SQLiteSink, code string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, a := range sink.Alerts() {
			if a.Code == code {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("alert %s did not appear within %v (alerts=%v)", code, timeout, sink.Alerts())
}

// waitForSinkAlertGone blocks until the given alert code disappears from the
// sink snapshot.
func waitForSinkAlertGone(t *testing.T, sink *accesslog.SQLiteSink, code string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		found := false
		for _, a := range sink.Alerts() {
			if a.Code == code {
				found = true
				break
			}
		}
		if !found {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("alert %s did not clear within %v (alerts=%v)", code, timeout, sink.Alerts())
}

// TestRuntimeAlertLevelMapping pins the level translation at the mapping
// helper — the ONE place backend vocabulary meets the console banner
// contract: warning stays warning, error becomes critical (the backend has
// no critical tier; the banner does), unknown/empty degrades to warning.
func TestRuntimeAlertLevelMapping(t *testing.T) {
	cases := []struct{ in, want string }{
		{accesslog.AlertLevelWarning, "warning"},
		{accesslog.AlertLevelError, "critical"},
		{"", "warning"},
		{"fatal", "warning"},
	}
	for _, tc := range cases {
		if got := runtimeAlertLevel(tc.in); got != tc.want {
			t.Fatalf("runtimeAlertLevel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestStatusOmitsRuntimeAlertsWithoutSink pins the omitted-when-quiet
// contract: without the accessor wired (static assembly), with the accessor
// returning nil (recording off), and with a healthy sink (empty snapshot),
// the /api/status body carries NO runtime_alerts key — the console banner
// treats a missing key as "no alerts".
func TestStatusOmitsRuntimeAlertsWithoutSink(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Options)
	}{
		{"no accessor wired (static assembly)", nil},
		{"accessor returns nil (recording off)", func(o *Options) {
			o.AccessLocalFn = func() *accesslog.SQLiteSink { return nil }
		}},
		{"healthy sink (empty snapshot)", func(o *Options) {
			sink := newRuntimeAlertSink(t)
			o.AccessLocalFn = func() *accesslog.SQLiteSink { return sink }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, client := statusServer(t, tc.mutate)
			out := getStatusBody(t, client, ts.URL)
			if arr, present := statusRuntimeAlerts(t, out); present {
				t.Fatalf("runtime_alerts must be omitted, got %v", arr)
			}
		})
	}
}

// TestStatusRuntimeAlertsDBWriteFailedCycle pins the critical-tier path end
// to end: an injected always-failing trigger makes every batch insert fail
// at Exec AND Commit (persistent failure shape), the status feed surfaces
// the db_write_failed alert with level "critical" (backend "error" mapped),
// the sink's verbatim Chinese message and a non-zero RFC3339 since; once the
// trigger is dropped and a write lands again, the sink clears the alert and
// the key disappears entirely (condition-driven, never publish-cleared).
func TestStatusRuntimeAlertsDBWriteFailedCycle(t *testing.T) {
	sink := newRuntimeAlertSink(t)
	ts, client := statusServer(t, func(o *Options) {
		o.AccessLocalFn = func() *accesslog.SQLiteSink { return sink }
	})

	// Condition: every INSERT aborts and rolls its transaction back — the
	// batch fails at Exec AND at Commit, so the alert persists.
	triggerDB := installFailTrigger(t, sink.DBPath())
	sink.Write(newRuntimeAlertEntry("a.local", "/locked"))
	waitForSinkAlert(t, sink, accesslog.AlertDBWriteFailed, 20*time.Second)

	out := getStatusBody(t, client, ts.URL)
	arr, present := statusRuntimeAlerts(t, out)
	if !present {
		t.Fatalf("runtime_alerts must appear while writes fail, got %v", out)
	}
	entry := statusAlertWithCode(t, arr, accesslog.AlertDBWriteFailed)
	if entry["level"] != "critical" {
		t.Fatalf("db_write_failed level = %v, want critical (backend error mapped for the banner)", entry["level"])
	}
	msg, _ := entry["message"].(string)
	if msg == "" {
		t.Fatalf("db_write_failed message must pass through, got %v", entry)
	}
	for _, a := range sink.Alerts() {
		if a.Code == accesslog.AlertDBWriteFailed && a.Message != msg {
			t.Fatalf("message must match the sink snapshot verbatim: status %q vs sink %q", msg, a.Message)
		}
	}
	sinceStr, _ := entry["since"].(string)
	since, err := time.Parse(time.RFC3339, sinceStr)
	if err != nil || since.IsZero() {
		t.Fatalf("since must be a non-zero RFC3339 instant, got %q (err=%v)", sinceStr, err)
	}

	// Condition gone: drop the trigger, land a write — the sink clears the
	// alert on the next successful insert and the key disappears.
	if _, err := triggerDB.Exec("DROP TRIGGER access_runtime_alert_fail"); err != nil {
		t.Fatal(err)
	}
	sink.Write(newRuntimeAlertEntry("a.local", "/recovered"))
	waitForSinkAlertGone(t, sink, accesslog.AlertDBWriteFailed, 20*time.Second)
	out = getStatusBody(t, client, ts.URL)
	if arr, present := statusRuntimeAlerts(t, out); present {
		t.Fatalf("runtime_alerts must disappear once the condition clears, got %v", arr)
	}
}

// TestStatusRuntimeAlertsQueueFullCycle pins the warning-tier path: flooding
// the bounded write queue faster than the writer drains raises queue_full,
// surfaced with level "warning" (sink warning stays warning); after the
// queue drains and a fresh Write re-checks the half-capacity rule, the alert
// clears and the key disappears.
func TestStatusRuntimeAlertsQueueFullCycle(t *testing.T) {
	sink := newRuntimeAlertSinkBatched(t)
	ts, client := statusServer(t, func(o *Options) {
		o.AccessLocalFn = func() *accesslog.SQLiteSink { return sink }
	})

	// Condition: 12000 entries against a 4096-slot queue with small batches
	// — the producer outruns the writer, the queue overflows.
	for i := 0; i < 12000; i++ {
		sink.Write(newRuntimeAlertEntry("a.local", "/flood"))
	}
	waitForSinkAlert(t, sink, accesslog.AlertQueueFull, 10*time.Second)

	out := getStatusBody(t, client, ts.URL)
	arr, present := statusRuntimeAlerts(t, out)
	if !present {
		t.Fatalf("runtime_alerts must appear while the queue overflows, got %v", out)
	}
	entry := statusAlertWithCode(t, arr, accesslog.AlertQueueFull)
	if entry["level"] != "warning" {
		t.Fatalf("queue_full level = %v, want warning", entry["level"])
	}
	if msg, _ := entry["message"].(string); msg == "" {
		t.Fatalf("queue_full message must pass through, got %v", entry)
	}

	// Condition gone: drain the queue, then one more Write re-checks the
	// half-capacity rule and clears the alert; the key disappears.
	if err := sink.Flush(30 * time.Second); err != nil {
		t.Fatalf("queue never drained: %v", err)
	}
	sink.Write(newRuntimeAlertEntry("a.local", "/drained"))
	waitForSinkAlertGone(t, sink, accesslog.AlertQueueFull, 10*time.Second)
	out = getStatusBody(t, client, ts.URL)
	if arr, present := statusRuntimeAlerts(t, out); present {
		t.Fatalf("runtime_alerts must disappear once the queue drains, got %v", arr)
	}
}
