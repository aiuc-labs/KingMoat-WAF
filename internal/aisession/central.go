package aisession

// Central AI session store: the control plane persists ingested node records
// in ai_sessions ((node_id, boot_id, seq) dedup for idempotent replays) and
// fans each accepted record out to the configured outbound sink (ES shipper).
// Retention prunes rows older than the configured days.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// AIWireSession is one record on the wire: local seq + full record JSON.
// (In the CE all-in-one shape it only crosses the in-process boundary
// between CentralSink and the central store; the fleet uplink channel is
// not part of this distribution.)
type AIWireSession struct {
	Seq    int64           `json:"seq"`
	Record json.RawMessage `json:"record"`
}

const centralAISchema = `
CREATE TABLE IF NOT EXISTS ai_sessions (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	ts_ms    INTEGER NOT NULL,
	node_id  TEXT NOT NULL DEFAULT '',
	boot_id  TEXT NOT NULL DEFAULT '',
	seq      INTEGER NOT NULL DEFAULT 0,
	site     TEXT NOT NULL DEFAULT '',
	provider TEXT NOT NULL DEFAULT '',
	model    TEXT NOT NULL DEFAULT '',
	client_ip TEXT NOT NULL DEFAULT '',
	path     TEXT NOT NULL DEFAULT '',
	status   INTEGER NOT NULL DEFAULT 0,
	raw      TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_dedup ON ai_sessions(node_id, boot_id, seq);
CREATE INDEX IF NOT EXISTS idx_ai_ts ON ai_sessions(ts_ms);
CREATE INDEX IF NOT EXISTS idx_ai_site_ts ON ai_sessions(site, ts_ms);
`

// CentralStore persists AI session records on the control plane.
type CentralStore struct {
	db     *sql.DB
	rdb    *sql.DB
	logger *slog.Logger
	out    atomic.Pointer[AISink]

	done chan struct{}
}

// migrateCentralSchema upgrades pre-dedup central databases in place.
// Early v0.8.0-dev deployments created ai_sessions without the
// (node_id, boot_id, seq) columns; CREATE INDEX idx_ai_dedup would then
// fail with "no such column" and the console would crash-loop. Fresh
// databases (table absent) are handled by the schema DDL alone.
func migrateCentralSchema(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(ai_sessions)`)
	if err != nil {
		return fmt.Errorf("aisession: inspect schema: %w", err)
	}
	cols := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("aisession: inspect schema: %w", err)
		}
		cols[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("aisession: inspect schema: %w", err)
	}
	if len(cols) == 0 {
		return nil // table absent: fresh database, nothing to migrate
	}
	if !cols["raw"] {
		// Not an aisession ai_sessions table (e.g. the AI assistant store's
		// chat schema): ALTERing dedup columns onto it would corrupt it and
		// still fail later on ts_ms. Fail loudly with an actionable error.
		return fmt.Errorf("aisession: ai_sessions exists but is not an aisession schema (no raw column) — wrong database file?")
	}
	for _, m := range []struct{ col, ddl string }{
		{"node_id", `ALTER TABLE ai_sessions ADD COLUMN node_id TEXT NOT NULL DEFAULT ''`},
		{"boot_id", `ALTER TABLE ai_sessions ADD COLUMN boot_id TEXT NOT NULL DEFAULT ''`},
		{"seq", `ALTER TABLE ai_sessions ADD COLUMN seq INTEGER NOT NULL DEFAULT 0`},
	} {
		if !cols[m.col] {
			if _, err := db.Exec(m.ddl); err != nil {
				return fmt.Errorf("aisession: migrate add %s: %w", m.col, err)
			}
		}
	}
	return nil
}

// parseTS converts an RFC3339 timestamp to epoch millis (fallback: now).
func parseTS(ts string) int64 {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.UnixMilli()
	}
	return time.Now().UnixMilli()
}

// AISink receives accepted records on the central plane (outbound shipper).
type AISink interface {
	WriteAIRecord(r Record)
}

// NewCentralStore opens (and initializes) the central AI session database.
func NewCentralStore(dbPath string, logger *slog.Logger) (*CentralStore, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("aisession: create dir: %w", err)
	}
	dsn := "file:" + dbPath +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("aisession: open %s: %w", dbPath, err)
	}
	db.SetMaxOpenConns(1)
	if err := migrateCentralSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(centralAISchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("aisession: init schema: %w", err)
	}
	rdsn := "file:" + dbPath + "?_pragma=busy_timeout(5000)&_pragma=query_only(true)"
	rdb, err := sql.Open("sqlite", rdsn)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("aisession: open read pool: %w", err)
	}
	rdb.SetMaxOpenConns(4)
	rdb.SetMaxIdleConns(4)
	return &CentralStore{db: db, rdb: rdb, logger: logger, done: make(chan struct{})}, nil
}

// SetSink wires the outbound shipper (nil disables fan-out).
func (s *CentralStore) SetSink(k AISink) {
	if k == nil {
		s.out.Store(nil)
		return
	}
	s.out.Store(&k)
}

// IngestBulk persists one batch durably (idempotent via the dedup index) and
// fans accepted rows out to the sink. Returns the number of newly inserted
// records.
func (s *CentralStore) IngestBulk(nodeID, bootID string, sessions []AIWireSession) (int, error) {
	if len(sessions) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	accepted := 0
	acceptedRecs := make([]Record, 0, len(sessions))
	for _, ws := range sessions {
		var rec Record
		if err := json.Unmarshal(ws.Record, &rec); err != nil {
			continue // malformed record: skip (ack still advances past it)
		}
		if rec.TS == "" {
			rec.TS = time.Now().UTC().Format(time.RFC3339Nano)
		}
		res, err := tx.Exec(
			`INSERT OR IGNORE INTO ai_sessions
			 (ts_ms, node_id, boot_id, seq, site, provider, model, client_ip, path, status, raw)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			parseTS(rec.TS), nodeID, bootID, ws.Seq,
			rec.Site, rec.Provider, rec.Model, rec.ClientIP, rec.Path, rec.Status,
			string(ws.Record))
		if err != nil {
			tx.Rollback()
			return accepted, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			accepted++
			acceptedRecs = append(acceptedRecs, rec)
		}
	}
	if err := tx.Commit(); err != nil {
		return accepted, err
	}
	// fan-out only after a durable commit: a failed commit must not emit
	// records the outbound sink would ship but the store never kept.
	if k := s.out.Load(); k != nil {
		for _, rec := range acceptedRecs {
			(*k).WriteAIRecord(rec)
		}
	}
	return accepted, nil
}

// CentralSink adapts the central store to the node-side Sink interface for
// all-in-one deployments: the capture pipeline writes directly into the
// central store (same dedup + retention), so the console AI audit page reads
// locally captured sessions without an uplink hop.
type CentralSink struct {
	store  *CentralStore
	nodeID string
	boot   string
	seq    atomic.Int64
}

// NewCentralSink builds the direct-to-central sink (per-process boot id).
func NewCentralSink(store *CentralStore, nodeID string) Sink {
	return &CentralSink{store: store, nodeID: nodeID, boot: "aio-" + newID()}
}

// WriteAI implements Sink: marshal and persist into the central store.
func (c *CentralSink) WriteAI(r Record) {
	if r.NodeID == "" {
		r.NodeID = c.nodeID
	}
	if r.TS == "" {
		r.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	seq := c.seq.Add(1)
	_, _ = c.store.IngestBulk(c.nodeID, c.boot, []AIWireSession{{Seq: seq, Record: b}})
}

// AIQuery filters the central AI session list (all optional).
type AIQuery struct {
	Site     string
	Provider string
	Keyword  string
	Limit    int
	Offset   int
}

// List returns records newest-first for the console API. Full records are
// decoded from the raw column.
func (s *CentralStore) List(q AIQuery) ([]Record, int, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 100
	}
	where := []string{"1=1"}
	args := []any{}
	if q.Site != "" {
		where = append(where, "site = ?")
		args = append(args, q.Site)
	}
	if q.Provider != "" {
		where = append(where, "provider = ?")
		args = append(args, q.Provider)
	}
	if q.Keyword != "" {
		kw := "%" + q.Keyword + "%"
		where = append(where, "(raw LIKE ? OR path LIKE ? OR client_ip LIKE ? OR model LIKE ?)")
		args = append(args, kw, kw, kw, kw)
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := s.rdb.QueryRow("SELECT COUNT(*) FROM ai_sessions WHERE "+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := "SELECT raw FROM ai_sessions WHERE " + cond + " ORDER BY ts_ms DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, q.Limit, q.Offset)
	rows, err := s.rdb.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]Record, 0, q.Limit)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		var rec Record
		if json.Unmarshal([]byte(raw), &rec) == nil {
			out = append(out, rec)
		}
	}
	return out, total, rows.Err()
}

// Prune deletes records older than days (returns rows removed).
func (s *CentralStore) Prune(days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	cut := time.Now().AddDate(0, 0, -days).UnixMilli()
	res, err := s.db.Exec(`DELETE FROM ai_sessions WHERE ts_ms < ?`, cut)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// StartRetention runs the daily prune loop (days <= 0 disables it).
func (s *CentralStore) StartRetention(ctx context.Context, days int) {
	if days <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := s.Prune(days); err == nil && n > 0 {
					s.logger.Info("ai sessions: retention pruned", "rows", n)
				}
			}
		}
	}()
}

// Count returns the number of stored records (observability).
func (s *CentralStore) Count() int64 {
	var n int64
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM ai_sessions`).Scan(&n)
	return n
}

// Close releases the database handles.
func (s *CentralStore) Close() error {
	close(s.done)
	s.rdb.Close()
	return s.db.Close()
}
