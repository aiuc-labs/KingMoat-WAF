// Recorder-off administration for the local access-log store: with
// access_log_record switched off the SQLiteSink instance is detached, but the
// recorded data stays on disk (决策：关闭不自动删数据) until retention,
// capacity or an explicit purge. The record status object (rows / oldest_ts),
// the residual-data history query (LocalHistory) and the
// POST /api/access_logs/purge endpoint therefore reach the file directly
// through these short-lived handles when no live sink exists. While a live
// sink IS present, the API uses the sink's own pooled connections instead
// (SQLiteSink.Rows / OldestTS / PurgeAll / History).
package accesslog

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// LocalStats reads the stored row count and the oldest recorded timestamp
// from the local access-log database at dbPath (read-only handle, see
// residualReadOnlyDSNs for the fallback chain). Every "no data" shape —
// missing file, absent table, a database that cannot be opened at all (WAL
// residue, corruption) — reports 0 rows and no error, with the last shape
// logged via slog.Warn; the status endpoint treats the result as
// informational only.
func LocalStats(dbPath string) (rows int64, oldest time.Time, err error) {
	if dbPath == "" {
		return 0, time.Time{}, nil
	}
	if _, serr := os.Stat(dbPath); serr != nil {
		return 0, time.Time{}, nil // no file yet: nothing was ever recorded
	}
	var lastErr error
	for i, dsn := range residualReadOnlyDSNs(dbPath) {
		rows, oldest, err = localStatsOnce(dbPath, dsn)
		if err == nil {
			warnResidualDegraded(i, dbPath)
			return rows, oldest, nil
		}
		if strings.Contains(err.Error(), "no such table") {
			return 0, time.Time{}, nil // pre-feature file shape: nothing recorded
		}
		lastErr = err
	}
	slog.Warn("accesslog: residual local access-log stats failed on every fallback, reporting zero rows",
		"db", dbPath, "err", lastErr)
	return 0, time.Time{}, nil
}

// localStatsOnce runs the LocalStats query over one concrete DSN.
func localStatsOnce(dbPath, dsn string) (rows int64, oldest time.Time, err error) {
	db, oerr := sql.Open("sqlite", dsn)
	if oerr != nil {
		return 0, time.Time{}, fmt.Errorf("accesslog: open residual local store: %w", oerr)
	}
	defer db.Close()
	var ms sql.NullInt64
	if qerr := db.QueryRow(`SELECT COUNT(*), MIN(ts_ms) FROM access`).Scan(&rows, &ms); qerr != nil {
		return 0, time.Time{}, fmt.Errorf("accesslog: residual stats query: %w", qerr)
	}
	if ms.Valid && ms.Int64 != 0 {
		oldest = time.UnixMilli(ms.Int64).UTC()
	}
	return rows, oldest, nil
}

// PurgeLocalAll deletes every row of the local access-log database at dbPath
// and reclaims the file space (DELETE + VACUUM + WAL checkpoint truncate,
// mirroring SQLiteSink.PurgeAll — DELETE alone never shrinks the file). A
// missing database file reports 0 deleted rows and no error: purging an
// installation that never recorded is a no-op, never a failure.
func PurgeLocalAll(dbPath string) (int64, error) {
	if dbPath == "" {
		return 0, nil
	}
	if _, serr := os.Stat(dbPath); serr != nil {
		return 0, nil // nothing recorded (file absent)
	}
	db, err := sql.Open("sqlite", "file:"+dbPath+
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return 0, fmt.Errorf("accesslog: open local store for purge: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1) // serialize with any concurrent writer
	res, derr := db.Exec(`DELETE FROM access`)
	if derr != nil {
		if strings.Contains(derr.Error(), "no such table") {
			// Pre-feature file shape (no access table): nothing was ever
			// recorded here, so the purge is a no-op — same tolerance as
			// LocalStats / LocalHistory for this shape (S-16).
			return 0, nil
		}
		return 0, fmt.Errorf("accesslog: purge rows: %w", derr)
	}
	n, _ := res.RowsAffected()
	if _, verr := db.Exec(`VACUUM`); verr != nil {
		return n, fmt.Errorf("accesslog: vacuum after purge: %w", verr)
	}
	if _, cerr := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); cerr != nil {
		// Space-reclaim nicety; the destructive contract (rows gone) held.
		_ = cerr
	}
	return n, nil
}

// LocalHistory queries the recorded entries at dbPath READ-ONLY for the
// recorder-off shape: the sink is detached but the residual data stays
// searchable (残留可检索), with the exact same parameter semantics and
// response shape as the live sink's History. The handle is strictly
// read-only (see residualReadOnlyDSNs: mode=ro first, immutable=1 fallback
// for WAL residue) — the fallback can never write, checkpoint or lock out a
// future writer. Safe degradations: a missing database file, the
// pre-feature "no such table" shape and a database that fails every
// read-only candidate (WAL residue, corruption) return an empty page with
// no error — the last shape is logged via slog.Warn so it never becomes a
// SILENT empty result in the API layer.
//
// Error-contract note (RC-4): the returned errors never embed dbPath — the
// callers log it server-side and the auditor-facing surfaces answer with
// generic text only.
func LocalHistory(dbPath string, q HistoryQuery) (HistoryPage, error) {
	empty := HistoryPage{Items: []Entry{}}
	if dbPath == "" {
		return empty, nil
	}
	if _, serr := os.Stat(dbPath); serr != nil {
		return empty, nil // no file yet: nothing was ever recorded
	}
	var lastErr error
	for i, dsn := range residualReadOnlyDSNs(dbPath) {
		page, err := localHistoryOnce(dbPath, dsn, q)
		if err == nil {
			warnResidualDegraded(i, dbPath)
			return page, nil
		}
		if strings.Contains(err.Error(), "no such table") {
			return empty, nil // pre-feature file shape: nothing recorded
		}
		lastErr = err
	}
	slog.Warn("accesslog: residual local access-log history failed on every fallback, returning an empty page",
		"db", dbPath, "err", lastErr)
	return empty, nil
}

// residualReadOnlyDSNs returns the candidate DSNs for a recorder-off
// residual query in fallback order. Candidate 1 is the plain read-only open
// (mode=ro + query_only + busy_timeout): it can never write, checkpoint or
// lock out a future writer. Candidate 2 adds immutable=1: SQLite then skips
// the -wal and -shm side files entirely and reads the main database file
// alone.
//
// Why candidate 2 exists: a WAL database left over from a crash (or an
// unclean shutdown of the recorder) can carry side files a read-only
// connection cannot initialize — -shm missing or uninitializable, a -wal
// that cannot be opened (SQLITE_READONLY_CANTINIT / CANTOPEN shapes).
// Without the fallback those errors degraded the whole residual view to a
// silently empty page (the API layer swallows the error).
//
// Semantics boundary (deliberate): immutable reads are only safe in THIS
// residual shape — the sink handle is detached and no concurrent writer
// exists, so the main file is a stable snapshot; the recorder-off API never
// reaches these functions while a live sink exists. Two accepted costs: a
// concurrent writer would invalidate the snapshot assumption, and -wal data
// not yet checkpointed into the main file is invisible, so the result can
// UNDERCOUNT right after a crash — strictly better than an unusable
// database (宁有残缺可读，不整库不可用).
func residualReadOnlyDSNs(dbPath string) []string {
	return []string{
		"file:" + dbPath + "?mode=ro&_pragma=busy_timeout(5000)&_pragma=query_only(true)",
		"file:" + dbPath + "?mode=ro&immutable=1&_pragma=busy_timeout(5000)&_pragma=query_only(true)",
	}
}

// warnResidualDegraded logs the immutable=1 fallback whenever the plain
// read-only open could not serve a residual query (candidate > 0). The
// warning fires even on success — on purpose: the immutable read skips the
// -wal side file, so the reported rows may undercount and operators must
// see why.
func warnResidualDegraded(candidate int, dbPath string) {
	if candidate == 0 {
		return
	}
	slog.Warn("accesslog: residual local access-log read degraded to immutable=1 "+
		"(WAL side files unusable; -wal data not yet checkpointed into the main file is invisible)",
		"db", dbPath)
}

// localHistoryOnce runs the paged history query over one concrete DSN.
func localHistoryOnce(dbPath, dsn string, q HistoryQuery) (HistoryPage, error) {
	empty := HistoryPage{Items: []Entry{}}
	db, oerr := sql.Open("sqlite", dsn)
	if oerr != nil {
		return empty, fmt.Errorf("accesslog: open residual local store: %w", oerr)
	}
	defer db.Close()
	where, args := historyWhere(q)
	var total int
	if qerr := db.QueryRow(`SELECT COUNT(*) FROM access WHERE `+where, args...).Scan(&total); qerr != nil {
		return empty, fmt.Errorf("accesslog: residual history count: %w", qerr)
	}
	limit, offset := normalizeHistoryWindow(q)
	qargs := append(args, limit, offset)
	rows, qerr := db.Query(`SELECT ts, trace_id, site, client_ip, method, path, query, status, bytes, latency_ms, ua, outcome, rule, attack_type, body_skip
		 FROM access WHERE `+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, qargs...)
	if qerr != nil {
		return empty, fmt.Errorf("accesslog: residual history query: %w", qerr)
	}
	defer rows.Close()
	items := make([]Entry, 0, limit)
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.TS, &e.TraceID, &e.Site, &e.ClientIP, &e.Method, &e.Path,
			&e.Query, &e.Status, &e.Bytes, &e.LatencyMS, &e.UserAgent, &e.Outcome,
			&e.Rule, &e.AttackType, &e.BodySkip); err != nil {
			continue
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("accesslog: residual history rows: %w", err)
	}
	return HistoryPage{Items: items, Total: total}, nil
}
