package accesslog

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

func sinkLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestSink builds a sink for tests; entries commit immediately
// (batch=1) so tests need no ticker waits.
func newTestSink(t *testing.T, cfg config.AccessLogRecordSettings, queueSize int, workers bool) *SQLiteSink {
	t.Helper()
	s, err := newSQLiteSink(filepath.Join(t.TempDir(), "access-logs.db"), cfg, queueSize, workers, sinkLogger())
	if err != nil {
		t.Fatalf("newSQLiteSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func entryAt(site string, hoursAgo int, path string) *Entry {
	return &Entry{
		TS:        time.Now().Add(-time.Duration(hoursAgo) * time.Hour).UTC().Format(time.RFC3339Nano),
		Site:      site,
		Method:    "GET",
		Path:      path,
		Query:     "a=1",
		Status:    200,
		Bytes:     128,
		ClientIP:  "10.0.0.7",
		Outcome:   "forwarded",
		UserAgent: "ua-test/1.0",
	}
}

// TestSQLiteSinkRoundtripAndPagination: write → flush → query roundtrip,
// newest-first ordering, pagination (limit/offset + total) and every filter
// parameter (site/outcome/ip/q/since/until).
func TestSQLiteSinkRoundtripAndPagination(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 64, true)
	for i := 0; i < 15; i++ {
		e := entryAt("a.local", 0, "/p")
		e.Outcome = "forwarded"
		s.Write(e)
	}
	for i := 0; i < 10; i++ {
		e := entryAt("b.local", 0, "/checkout")
		e.Outcome = "blocked"
		e.ClientIP = "203.0.113.9"
		s.Write(e)
	}
	if err := s.Flush(5 * time.Second); err != nil {
		t.Fatalf("flush: %v", err)
	}

	page, err := s.History(HistoryQuery{Limit: 10})
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if page.Total != 25 {
		t.Fatalf("total = %d, want 25", page.Total)
	}
	if len(page.Items) != 10 {
		t.Fatalf("page items = %d, want 10", len(page.Items))
	}
	if page.Items[0].Site != "b.local" || page.Items[0].Path != "/checkout" {
		t.Fatalf("newest-first violated: %+v", page.Items[0])
	}
	if page.Items[0].TS == "" || page.Items[0].ClientIP != "203.0.113.9" {
		t.Fatalf("row fields not restored: %+v", page.Items[0])
	}

	// Offset pages.
	last, err := s.History(HistoryQuery{Limit: 10, Offset: 20})
	if err != nil {
		t.Fatalf("offset page: %v", err)
	}
	if len(last.Items) != 5 || last.Total != 25 {
		t.Fatalf("offset page = %d items / total %d, want 5/25", len(last.Items), last.Total)
	}
	if last.Items[0].Site != "a.local" {
		t.Fatalf("oldest page must hold a.local rows: %+v", last.Items[0])
	}

	// Site substring filter.
	site, err := s.History(HistoryQuery{Site: "b.local"})
	if err != nil {
		t.Fatal(err)
	}
	if site.Total != 10 {
		t.Fatalf("site filter total = %d, want 10", site.Total)
	}

	// Outcome exact filter.
	out, err := s.History(HistoryQuery{Outcome: "blocked"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Total != 10 {
		t.Fatalf("outcome filter total = %d, want 10", out.Total)
	}

	// IP prefix filter.
	ips, err := s.History(HistoryQuery{IP: "203.0.113"})
	if err != nil {
		t.Fatal(err)
	}
	if ips.Total != 10 {
		t.Fatalf("ip prefix filter total = %d, want 10", ips.Total)
	}

	// Free text over path/ua.
	q, err := s.History(HistoryQuery{Text: "checkout"})
	if err != nil {
		t.Fatal(err)
	}
	if q.Total != 10 {
		t.Fatalf("text filter total = %d, want 10", q.Total)
	}
	ua, err := s.History(HistoryQuery{Text: "ua-test"})
	if err != nil {
		t.Fatal(err)
	}
	if ua.Total != 25 {
		t.Fatalf("ua text filter total = %d, want 25", ua.Total)
	}

	// Time range: only the last hour's rows exist, so since=now-1h matches all.
	since, err := s.History(HistoryQuery{Since: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if since.Total != 25 {
		t.Fatalf("since filter total = %d, want 25", since.Total)
	}
	until, err := s.History(HistoryQuery{Until: time.Now().Add(-2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if until.Total != 0 {
		t.Fatalf("until filter total = %d, want 0", until.Total)
	}
}

// TestSQLiteSinkSiteFilter covers the enqueue-time site filter: mode=sites
// records only the listed first domains; mode=all records every site but
// skips the empty site label (no-site requests, decision D3).
func TestSQLiteSinkSiteFilter(t *testing.T) {
	t.Run("sites mode", func(t *testing.T) {
		s := newTestSink(t, config.AccessLogRecordSettings{Mode: "sites", Sites: []string{"a.local"}, BatchSize: 1}, 64, true)
		s.Write(entryAt("a.local", 0, "/a"))
		s.Write(entryAt("b.local", 0, "/b"))
		s.Write(entryAt("", 0, "/none"))
		if err := s.Flush(5 * time.Second); err != nil {
			t.Fatalf("flush: %v", err)
		}
		page, err := s.History(HistoryQuery{})
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 1 {
			t.Fatalf("sites-mode total = %d, want 1 (only a.local)", page.Total)
		}
		if len(page.Items) == 1 && page.Items[0].Site != "a.local" {
			t.Fatalf("recorded wrong site: %+v", page.Items[0])
		}
	})
	t.Run("all mode skips no-site requests", func(t *testing.T) {
		s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 64, true)
		s.Write(entryAt("a.local", 0, "/a"))
		s.Write(entryAt("b.local", 0, "/b"))
		s.Write(entryAt("", 0, "/none"))
		if err := s.Flush(5 * time.Second); err != nil {
			t.Fatalf("flush: %v", err)
		}
		page, err := s.History(HistoryQuery{})
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 2 {
			t.Fatalf("all-mode total = %d, want 2 (empty site excluded)", page.Total)
		}
		for _, e := range page.Items {
			if e.Site == "" {
				t.Fatalf("empty-site row recorded: %+v", e)
			}
		}
	})
	t.Run("constructor rejects off mode", func(t *testing.T) {
		if _, err := NewSQLiteSink(filepath.Join(t.TempDir(), "x.db"), config.AccessLogRecordSettings{Mode: "off"}, sinkLogger()); err == nil {
			t.Fatal("mode=off construction must be rejected (recording is disabled by not building a sink)")
		}
	})
}

// TestSQLiteSinkRetentionPurge: purgeBefore deletes strictly-older rows and
// enforceRetention applies retention_days. Entry ages stay INSIDE the
// retention window (the L7 startup maintenance pass also runs at
// construction with the same cutoff, and would otherwise purge the oldest
// entries non-deterministically before the test's own purge).
func TestSQLiteSinkRetentionPurge(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1, RetentionDays: 3}, 64, true)
	for _, h := range []int{50, 40, 30, 1} {
		s.Write(entryAt("a.local", h, "/p"))
	}
	if err := s.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	// Direct purge: everything before 36h ago (the 50h and 40h rows;
	// the 30h and 1h rows survive).
	n, err := s.purgeBefore(time.Now().Add(-36 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("purgeBefore removed %d rows, want 2", n)
	}
	page, err := s.History(HistoryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 {
		t.Fatalf("rows after purge = %d, want 2 (the 30h and 1h rows survive)", page.Total)
	}
	// enforceRetention with retention_days=3 deletes nothing further here
	// (all remaining rows are younger than 3 days).
	m, err := s.enforceRetention()
	if err != nil {
		t.Fatal(err)
	}
	if m != 0 {
		t.Fatalf("enforceRetention removed %d rows, want 0", m)
	}
}

// TestSQLiteSinkCapacityEviction: a footprint over the ceiling evicts the
// oldest day batches first (Evicted counter grows), stops at the
// payload-based row target instead of wiping the store (GATE-1 contract)
// and keeps the newest day. The 16KB ceiling is deliberate: the 300 filled
// rows carry ~24KB of live payload, which sits BELOW the 80% target of the
// former 32KB ceiling — a compliant guard would correctly evict nothing
// there, since the file only overflows through index/WAL overhead.
// The queue must hold every written entry (queue ≥ 300): with the default
// 64-slot queue the batch-1 writer cannot keep up under package-parallel
// load, the overflow drops shift the landed set to a non-day-aligned count
// and the eviction stops at a scheduling-dependent row.
func TestSQLiteSinkCapacityEviction(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 512, true)
	s.setDiskFree(func(string) (int64, bool) { return 10 << 30, true }) // hermetic: the disk guard never fires from the host volume
	for d := 2; d >= 0; d-- {
		for i := 0; i < 100; i++ {
			s.Write(entryAt("a.local", d*24, "/filler/"+pathSuffix(d, i)))
		}
	}
	if err := s.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	s.setCapacityCeiling(16 << 10) // 16KB: live payload exceeds the 80% target — the eviction path runs deterministically
	n, err := s.enforceCapacity()
	if err != nil {
		t.Fatalf("enforceCapacity: %v", err)
	}
	if n == 0 || s.Evicted() != n {
		t.Fatalf("evicted = %d (counter %d), want >0 with matching counter", n, s.Evicted())
	}
	cutoff := time.Now().Add(-23 * time.Hour).UnixMilli()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var oldRows int64
	if err := s.rdb.QueryRowContext(ctx, `SELECT COUNT(*) FROM access WHERE ts_ms < ?`, cutoff).Scan(&oldRows); err != nil {
		t.Fatal(err)
	}
	if oldRows != 0 {
		t.Fatalf("%d old rows survived the eviction; oldest-first violated", oldRows)
	}
	page, err := s.History(HistoryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total >= 300 {
		t.Fatalf("eviction must reduce the row count, got %d", page.Total)
	}
	if page.Total == 0 {
		t.Fatal("eviction must stop at the row target, not wipe the store (GATE-1 ratchet)")
	}
}

// TestSQLiteSinkFlushWaitsForEnqueuedBatch (S-1): pending is counted BEFORE
// the queue send, so a burst enqueued while the batch writer is committing
// cannot slip past Flush — every round must land all its entries and leave
// pending at zero.
func TestSQLiteSinkFlushWaitsForEnqueuedBatch(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 512, true)
	for round := 0; round < 25; round++ {
		for i := 0; i < 20; i++ {
			s.Write(entryAt("a.local", 0, "/flush"))
		}
		if err := s.Flush(5 * time.Second); err != nil {
			t.Fatalf("flush round %d: %v", round, err)
		}
		if p := s.Pending(); p != 0 {
			t.Fatalf("round %d: pending = %d, want 0 after Flush", round, p)
		}
		page, err := s.History(HistoryQuery{})
		if err != nil {
			t.Fatal(err)
		}
		if want := (round + 1) * 20; page.Total != want {
			t.Fatalf("round %d: rows = %d, want %d (Flush must wait for every enqueued entry)", round, page.Total, want)
		}
	}
}

// TestNormalizeHistoryWindowLimits (S-10): limits above the 1000 cap clamp
// to 1000 instead of silently falling back to 100; non-positive limits keep
// the 100 default; the offset never goes negative.
func TestNormalizeHistoryWindowLimits(t *testing.T) {
	cases := []struct {
		name         string
		limit, wantL int
	}{
		{"zero defaults", 0, 100},
		{"negative defaults", -7, 100},
		{"in-range pass-through", 500, 500},
		{"cap boundary kept", 1000, 1000},
		{"over-cap clamped", 1001, 1000},
		{"far over-cap clamped", 5000, 1000},
	}
	for _, tc := range cases {
		limit, _ := normalizeHistoryWindow(HistoryQuery{Limit: tc.limit})
		if limit != tc.wantL {
			t.Errorf("%s: limit %d → %d, want %d", tc.name, tc.limit, limit, tc.wantL)
		}
	}
	if _, offset := normalizeHistoryWindow(HistoryQuery{Limit: 10, Offset: -3}); offset != 0 {
		t.Errorf("negative offset = %d, want 0", offset)
	}
}

// TestSQLiteSinkQueueFullDropsWithoutBlocking: a full queue must never block
// the caller (Write is a non-blocking select/default) — overflow is dropped
// and counted. This is the data-plane latency guarantee test: even with a
// stalled writer (no worker loop at all) 5 writes return immediately.
func TestSQLiteSinkQueueFullDropsWithoutBlocking(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all"}, 2, false)
	start := time.Now()
	for i := 0; i < 5; i++ {
		s.Write(entryAt("a.local", 0, "/q"))
	}
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("writes on a full queue took %v — the hot path must never block", elapsed)
	}
	if s.Dropped() != 3 {
		t.Fatalf("dropped = %d, want 3 (queue cap 2)", s.Dropped())
	}
	if s.Pending() != 2 {
		t.Fatalf("pending = %d, want 2", s.Pending())
	}
	if s.Depth() != 2 {
		t.Fatalf("depth = %d, want 2", s.Depth())
	}
}

// TestSQLiteSinkCloseReopenPersists: data survives Close and a fresh open of
// the same file (schema is IF NOT EXISTS; no migration concerns).
func TestSQLiteSinkCloseReopenPersists(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "access-logs.db")
	s, err := newSQLiteSink(dbPath, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 64, true, sinkLogger())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		s.Write(entryAt("a.local", 0, "/keep"))
	}
	if err := s.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close must be idempotent: %v", err)
	}
	s2, err := NewSQLiteSink(dbPath, config.AccessLogRecordSettings{Mode: "all"}, sinkLogger())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	page, err := s2.History(HistoryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 5 {
		t.Fatalf("rows after reopen = %d, want 5", page.Total)
	}
}

func pathSuffix(d, i int) string {
	return string(rune('a'+d)) + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
