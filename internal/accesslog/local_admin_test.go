package accesslog

import (
	"bytes"
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestLocalStatsAndPurgeWithoutSink covers the recorder-off shapes: a missing
// file reports safe zeros, recorded data stays readable through LocalStats
// after the sink is gone, and PurgeLocalAll deletes every row, reclaims the
// file space and keeps the file itself in place.
func TestLocalStatsAndPurgeWithoutSink(t *testing.T) {
	dbPath := "missing-dir-does-not-exist/access-logs.db"
	if rows, oldest, err := LocalStats(dbPath); err != nil || rows != 0 || !oldest.IsZero() {
		t.Fatalf("LocalStats on a missing file = %d/%v/%v, want 0/zero/nil", rows, oldest, err)
	}
	if n, err := PurgeLocalAll(dbPath); err != nil || n != 0 {
		t.Fatalf("PurgeLocalAll on a missing file = %d/%v, want 0/nil", n, err)
	}

	dir := t.TempDir()
	dbPath = filepath.Join(dir, "access-logs.db")
	// Queue 512: the 100 filler writes must all land (no drops) — this test
	// verifies row accounting, not the backpressure path.
	s, err := newSQLiteSink(dbPath, config.AccessLogRecordSettings{Mode: "all", BatchSize: 8}, 512, true, sinkLogger())
	if err != nil {
		t.Fatal(err)
	}
	filler := strings.Repeat("k=zzzz", 700) // ~4KB per row, makes the size reclaim visible
	for i := 0; i < 100; i++ {
		e := entryAt("a.local", 0, "/purge-me")
		e.Query = filler
		e.UserAgent = filler
		s.Write(e)
	}
	if err := s.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	rows, oldest, err := LocalStats(dbPath)
	if err != nil || rows != 100 {
		t.Fatalf("LocalStats = %d rows / %v err, want 100/nil", rows, err)
	}
	if oldest.IsZero() || time.Since(oldest) > time.Hour {
		t.Fatalf("oldest = %v, want a fresh non-zero timestamp", oldest)
	}
	sizeBefore := dbFileSize(t, dbPath)

	n, err := PurgeLocalAll(dbPath)
	if err != nil || n != 100 {
		t.Fatalf("PurgeLocalAll = %d/%v, want 100/nil", n, err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("the database file must survive the purge: %v", err)
	}
	if rows, _, err := LocalStats(dbPath); err != nil || rows != 0 {
		t.Fatalf("rows after purge = %d/%v, want 0/nil", rows, err)
	}
	sizeAfter := dbFileSize(t, dbPath)
	if sizeAfter >= sizeBefore {
		t.Fatalf("purge must reclaim file space (before=%d, after=%d) — DELETE without VACUUM never shrinks", sizeBefore, sizeAfter)
	}
}

// TestPurgeLocalAllLegacyFileWithoutAccessTable (S-16): a pre-feature
// database file without the access table purges as a no-op (0, nil) — the
// same tolerance LocalStats / LocalHistory already apply to the shape —
// instead of a hard error, and the file itself stays in place.
func TestPurgeLocalAllLegacyFileWithoutAccessTable(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pre-feature.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE unrelated (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := PurgeLocalAll(dbPath)
	if err != nil || n != 0 {
		t.Fatalf("PurgeLocalAll on a no-access-table file = %d/%v, want 0/nil (pre-feature tolerance)", n, err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("the database file must survive the no-op purge: %v", err)
	}
}

// TestPurgeLocalAllErrorStaysPathFree pins the RC-4 error contract of the
// recorder-off purge helpers: the error returned by PurgeLocalAll must not
// embed the database path (our own formatting adds none; the wrapped driver
// text goes to the server log via the callers). A directory at the database
// path forces a deterministic statement failure after os.Stat succeeds.
func TestPurgeLocalAllErrorStaysPathFree(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "not-a-database")
	if err := os.Mkdir(dbPath, 0o755); err != nil {
		t.Fatal(err)
	}
	n, err := PurgeLocalAll(dbPath)
	if err == nil || n != 0 {
		t.Fatalf("PurgeLocalAll on a directory = %d/%v, want 0/error", n, err)
	}
	if strings.Contains(err.Error(), dbPath) {
		t.Fatalf("purge error must not carry the database path (RC-4): %q", err)
	}
	if !strings.Contains(err.Error(), "purge rows") {
		t.Fatalf("purge error must keep the statement label, got %q", err)
	}
}

// TestSQLiteSinkPurgeAll: the live-sink purge deletes every row, zeroes the
// history view and is idempotent; queued post-purge entries stay.
func TestSQLiteSinkPurgeAll(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 64, true)
	for i := 0; i < 5; i++ {
		s.Write(entryAt("a.local", 0, "/p"))
	}
	if err := s.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Rows()
	if err != nil || rows != 5 {
		t.Fatalf("Rows = %d/%v, want 5/nil", rows, err)
	}
	if ts, ok := s.OldestTS(); !ok || ts.IsZero() {
		t.Fatalf("OldestTS = %v/%v, want a timestamp", ts, ok)
	}
	n, err := s.PurgeAll()
	if err != nil || n != 5 {
		t.Fatalf("PurgeAll = %d/%v, want 5/nil", n, err)
	}
	rows, err = s.Rows()
	if err != nil || rows != 0 {
		t.Fatalf("Rows after purge = %d/%v, want 0/nil", rows, err)
	}
	page, err := s.History(HistoryQuery{})
	if err != nil || page.Total != 0 {
		t.Fatalf("History after purge = %d/%v, want 0/nil", page.Total, err)
	}
	if _, ok := s.OldestTS(); ok {
		t.Fatal("OldestTS must report empty after the purge")
	}
	if n, err := s.PurgeAll(); err != nil || n != 0 {
		t.Fatalf("repeat PurgeAll = %d/%v, want 0/nil (idempotent)", n, err)
	}
}

// TestSQLiteSinkPurgeAllAfterClose: purging a closed sink fails cleanly
// instead of hitting the closed pool (console/swap race guard).
func TestSQLiteSinkPurgeAllAfterClose(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all"}, 8, true)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PurgeAll(); err == nil || n != 0 {
		t.Fatalf("PurgeAll on a closed sink = %d/%v, want 0/error", n, err)
	}
}

// TestLocalHistoryReadOnlyFallback covers the recorder-off residual query:
// a missing file and an empty path are safe empty pages, recorded rows stay
// queryable through the read-only handle after the sink is gone (with
// filters, paging and masking intact), and a corrupt database surfaces as an
// error with an empty page (the API layer degrades it to a 200 empty list).
func TestLocalHistoryReadOnlyFallback(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "access-logs.db")

	// Missing file: empty page, no error.
	if page, err := LocalHistory(dbPath, HistoryQuery{Limit: 10}); err != nil || len(page.Items) != 0 || page.Total != 0 {
		t.Fatalf("LocalHistory on a missing file = %d items / total %d / %v, want empty/nil", len(page.Items), page.Total, err)
	}
	// Empty path: same.
	if page, err := LocalHistory("", HistoryQuery{}); err != nil || len(page.Items) != 0 {
		t.Fatalf("LocalHistory on an empty path = %v/%v, want empty/nil", page.Items, err)
	}

	// Record two pages of residual data, one with a sensitive query.
	s, err := newSQLiteSink(dbPath, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 64, true, sinkLogger())
	if err != nil {
		t.Fatal(err)
	}
	e1 := entryAt("a.local", -1, "/stale-1")
	e1.Outcome = "forwarded"
	e2 := entryAt("b.local", 0, "/stale-2")
	e2.Outcome = "blocked"
	e2.Query = "api_key=SECRET&page=2"
	s.Write(e1)
	s.Write(e2)
	if err := s.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Full page, newest first.
	page, err := LocalHistory(dbPath, HistoryQuery{Limit: 10})
	if err != nil || page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("LocalHistory = %d/%d/%v, want 2 rows/nil", page.Total, len(page.Items), err)
	}
	if page.Items[0].Path != "/stale-2" {
		t.Fatalf("newest-first violated: %+v", page.Items[0])
	}
	// Filters mirror the live sink semantics.
	if page, err = LocalHistory(dbPath, HistoryQuery{Site: "b.local"}); err != nil || page.Total != 1 {
		t.Fatalf("site filter = %d/%v, want 1/nil", page.Total, err)
	}
	if page, err = LocalHistory(dbPath, HistoryQuery{Outcome: "blocked"}); err != nil || page.Total != 1 {
		t.Fatalf("outcome filter = %d/%v, want 1/nil", page.Total, err)
	}
	// Paging window.
	if page, err = LocalHistory(dbPath, HistoryQuery{Limit: 1, Offset: 1}); err != nil ||
		len(page.Items) != 1 || page.Total != 2 || page.Items[0].Path != "/stale-1" {
		t.Fatalf("offset page = %+v/%d/%v, want /stale-1 with total 2", page.Items, page.Total, err)
	}
	// The sensitive value stayed masked in the stored row.
	if page, err = LocalHistory(dbPath, HistoryQuery{Site: "b.local"}); err != nil || page.Items[0].Query != "api_key=***&page=2" {
		t.Fatalf("residual query = %q/%v, want the masked text", page.Items[0].Query, err)
	}

	// Corrupt database: every read-only candidate fails → degraded empty page
	// with NO error (the API layer would otherwise swallow the error silently);
	// the slog.Warn trail is asserted in TestLocalHistoryWALResidueFallback.
	bad := filepath.Join(dir, "corrupt.db")
	if werr := os.WriteFile(bad, []byte("this is not a database"), 0o644); werr != nil {
		t.Fatal(werr)
	}
	if page, err := LocalHistory(bad, HistoryQuery{}); err != nil || len(page.Items) != 0 {
		t.Fatalf("LocalHistory on a corrupt file = %d items/%v, want a degraded empty page without error", len(page.Items), err)
	}
	if rows, _, err := LocalStats(bad); err != nil || rows != 0 {
		t.Fatalf("LocalStats on a corrupt file = %d/%v, want 0/nil (degraded)", rows, err)
	}
}

// TestLocalHistoryWALResidueFallback pins the immutable=1 degradation chain
// (R3-03): a WAL database whose side files cannot be initialized by a
// read-only connection must fall back to an immutable read of the main
// database file and log a Warn; a database that fails BOTH candidates
// degrades to an empty page with a Warn instead of surfacing an error the
// API layer would silently swallow.
//
// Reproduced residue shape: a DIRECTORY at the -wal path (open fails with
// EISDIR on every platform, deterministically — no way for a read-only
// connection to rebuild the side files). The exact CANTINIT trigger of a
// real crash (-shm missing but -wal present with valid header) is NOT
// reproducible on this Windows host without cgo/driver internals; the
// degradation chain is DSN-level, so any candidate-1 open failure takes the
// same path (coverage boundary noted in the delivery notes).
func TestLocalHistoryWALResidueFallback(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "access-logs.db")

	// Capture the default logger so the Warn trail is assertable; restore at
	// cleanup. Package tests never call t.Parallel, so the swap is safe.
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// Build a WAL database with committed rows, then close it. A normal close
	// checkpoints and removes the -wal/-shm side files, leaving a
	// self-sufficient main file — asserted here as the Close-semantics check
	// (SQLiteSink.Close needs no explicit checkpoint statement).
	s, err := newSQLiteSink(dbPath, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 64, true, sinkLogger())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		s.Write(entryAt("a.local", 0, "/wal-residue"))
	}
	if err := s.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if fi, serr := os.Stat(dbPath + "-wal"); serr == nil && fi.Size() > 0 {
		t.Fatalf("normal close must checkpoint/truncate -wal (main file self-sufficient), got size %d", fi.Size())
	}

	// Candidate 1 fails (unusable -wal), candidate 2 (immutable) serves the
	// checkpointed rows.
	if err := os.Mkdir(dbPath+"-wal", 0o755); err != nil {
		t.Fatal(err)
	}
	page, err := LocalHistory(dbPath, HistoryQuery{Limit: 10})
	if err != nil || page.Total != 3 || len(page.Items) != 3 {
		t.Fatalf("LocalHistory with an unusable -wal = %d items/total %d/%v, want the immutable fallback to serve 3 rows", len(page.Items), page.Total, err)
	}
	rows, oldest, serr := LocalStats(dbPath)
	if serr != nil || rows != 3 || oldest.IsZero() {
		t.Fatalf("LocalStats with an unusable -wal = %d rows/%v oldest zero=%v, want 3 rows via immutable fallback", rows, serr, oldest.IsZero())
	}
	if !strings.Contains(buf.String(), "immutable=1") {
		t.Fatalf("the degradation must be logged as a Warn, got %q", buf.String())
	}

	// Both candidates fail (corrupt main file): degraded empty page + Warn,
	// never an error for the API layer to swallow silently.
	buf.Reset()
	bad := filepath.Join(dir, "corrupt.db")
	if werr := os.WriteFile(bad, []byte("this is not a database"), 0o644); werr != nil {
		t.Fatal(werr)
	}
	page, err = LocalHistory(bad, HistoryQuery{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("LocalHistory on a doubly-failing file = %d items/%v, want empty page + nil err", len(page.Items), err)
	}
	if !strings.Contains(buf.String(), "failed on every fallback") {
		t.Fatalf("the final failure must be logged as a Warn, got %q", buf.String())
	}
}

func dbFileSize(t *testing.T, path string) int64 {
	t.Helper()
	var total int64
	for _, p := range []string{path, path + "-wal"} {
		fi, err := os.Stat(p)
		if err == nil {
			total += fi.Size()
		}
	}
	return total
}
