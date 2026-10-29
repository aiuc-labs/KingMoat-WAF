// Local access-log recording store: a standalone SQLite database (pure-Go
// modernc driver, no CGO) written by the data plane when the
// access_log_record config section enables recording. The shape mirrors
// internal/logstore.SQLiteStore (WAL, single write connection, non-blocking
// bounded queue, batched inserts, read-only connection pool) with the
// differences the access-log volume requires: no raw JSON column and no FTS
// index (plain column store + b-tree indexes; text filters run as LIKE with
// a 5s read timeout as the backstop), plus per-site filtering at enqueue
// time, a daily retention purge and a 15-minute capacity guard that evicts
// the oldest days when the storage ceiling is exceeded.
//
// Write never blocks the request path: a full queue drops the entry and
// counts it (Dropped), exactly like the outbound shipper and the audit
// store. Sampling deliberately does NOT apply here — the outbound sample_pct
// lives inside the shipper pipeline, so local recording is always full.
package accesslog

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"github.com/shirou/gopsutil/v3/disk"

	"github.com/kingmoat/kingmoat/internal/config"
)

const (
	sqliteSinkQueueSize   = 4096
	sqliteSinkReadTimeout = 5 * time.Second
	// Capacity check every 15 minutes (the FALLBACK trigger; extra passes run
	// when accumulated write volume reaches writeTriggerBytes); retention
	// purge once a day (plan T-02).
	sqliteSinkCapacityEvery  = 15 * time.Minute
	sqliteSinkRetentionEvery = 24 * time.Hour
	// When over the ceiling, evict oldest-first in day-sized batches until the
	// live payload estimate fits 80% of the ceiling.
	sqliteSinkEvictFloorPct = 80
	// Safety bound for the day-batched eviction loop (max retention 90 days).
	sqliteSinkMaxEvictCycles = 365
	// Rows sampled for the live payload average (enforceCapacity / GATE-1):
	// the NEWEST rows are the ones eviction keeps, so they are the
	// representative sample; the bound keeps the guard pass sub-second even
	// on a ceiling-sized database (a backward id scan of 4096 rows, never a
	// full-table scan).
	sqliteSinkPayloadSampleRows = 4096
	// Write-volume capacity trigger (bytes of estimated payload between
	// checks): maxDiskBytes/8 keeps the worst-case overshoot between two
	// checks at ~12.5% of the ceiling — inside the 20% headroom the 80%
	// eviction target leaves — while the 16MB floor keeps tiny ceilings from
	// scheduling sub-second check loops. Each pass costs three os.Stat calls,
	// one COUNT(*) and one statfs (all sub-second, on the maintenance
	// goroutine), so even a sustained full-rate stream stays far below 1% CPU;
	// no extra writes are generated (write amplification: zero — the check
	// only reads). Low-traffic deployments simply fall back to the 15-minute
	// ticker.
	sqliteSinkWriteTriggerFloor = 16 << 20
	// Absolute low-watermark floor for the VOLUME holding the database (bytes):
	// 1.2× the configured ceiling keeps room for SQLite maintenance scratch
	// (WAL checkpoint / VACUUM need space in the order of the database size)
	// when the database momentarily reaches its ceiling; the 512MB absolute
	// floor keeps small ceilings (128MB ⇒ 1.2× = 154MB) from making the guard
	// meaningless on a shared volume.
	sqliteSinkDiskFloorMin = 512 << 20
)

// SQLiteSink persists access entries to a local SQLite database. It
// implements Sink and is safe for concurrent use; Write never blocks.
type SQLiteSink struct {
	db     *sql.DB // single writer connection (serialized, WAL)
	rdb    *sql.DB // read pool (query_only): console queries never starve writes
	dbPath string
	logger *slog.Logger

	ch      chan Entry
	done    chan struct{} // writer loop exit signal
	mstop   chan struct{} // maintenance stop signal
	mdone   chan struct{} // maintenance loop exit signal
	workers bool

	// mu guards closed so Write never sends into a closed channel, and keeps
	// Close idempotent (repeat calls are a no-op) — same guard pattern as
	// GenericShipper: in-flight requests keep a sink reference across their
	// whole lifetime, so every config-switch Close races concurrent Writes
	// (H1). The lock is only held across the flag check and the
	// non-blocking send; DB work never happens under it.
	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once

	batchSize  int
	flushEvery time.Duration

	dropped atomic.Int64
	pending atomic.Int64
	evicted atomic.Int64

	allSites      bool
	sites         map[string]struct{}
	retentionDays int
	maxDiskBytes  int64

	// cfgMu guards the two knobs tests swap at runtime (maxDiskBytes,
	// diskFree). Production sets them once at construction, before the
	// worker/maintenance goroutines start, so this adds no hot-path cost
	// (the request path only reads atomics).
	cfgMu sync.RWMutex

	// Disk guard (数据盘联合感知): pausing is ONE atomic load on the request
	// path; free-space lookup is injectable for tests. writeTriggerBytes
	// drives the write-volume capacity kicks (capKick, buffered 1, consumed
	// by the maintenance loop); writtenSinceCheck accumulates the estimated
	// payload of committed batches on the writer goroutine.
	diskPaused        atomic.Bool
	diskFree          func(path string) (int64, bool)
	writeTriggerBytes int64
	writtenSinceCheck atomic.Int64
	capKick           chan struct{}

	// Active runtime alerts (queue_full / disk_low_paused / ...), surfaced as
	// a snapshot through Alerts() for the console status feed. alertsMu is
	// only ever taken standalone (Alerts) or UNDER s.mu (Write) — never the
	// other way around — so no lock cycle exists.
	alertsMu sync.Mutex
	alerts   map[string]SinkAlert
}

const sqliteSinkSchema = `
CREATE TABLE IF NOT EXISTS access (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts_ms      INTEGER NOT NULL,
	ts         TEXT NOT NULL DEFAULT '',
	trace_id   TEXT NOT NULL DEFAULT '',
	site       TEXT NOT NULL DEFAULT '',
	client_ip  TEXT NOT NULL DEFAULT '',
	method     TEXT NOT NULL DEFAULT '',
	path       TEXT NOT NULL DEFAULT '',
	query      TEXT NOT NULL DEFAULT '',
	status     INTEGER NOT NULL DEFAULT 0,
	bytes      INTEGER NOT NULL DEFAULT 0,
	latency_ms INTEGER NOT NULL DEFAULT 0,
	ua         TEXT NOT NULL DEFAULT '',
	outcome    TEXT NOT NULL DEFAULT '',
	rule       TEXT NOT NULL DEFAULT '',
	attack_type TEXT NOT NULL DEFAULT '',
	body_skip  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_access_ts ON access(ts_ms);
CREATE INDEX IF NOT EXISTS idx_access_site_ts ON access(site, ts_ms);
CREATE INDEX IF NOT EXISTS idx_access_outcome_ts ON access(outcome, ts_ms);
CREATE INDEX IF NOT EXISTS idx_access_ip_ts ON access(client_ip, ts_ms);
`

// ensureAccessColumns upgrades databases created before a column was
// added to the schema: CREATE TABLE IF NOT EXISTS never touches an existing
// table, so every new column needs an explicit, idempotent ALTER. Unknown
// future columns are left alone (additive only, never renamed/dropped).
func ensureAccessColumns(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(access)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return err
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !cols["body_skip"] {
		if _, err := db.Exec(`ALTER TABLE access ADD COLUMN body_skip TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

// NewSQLiteSink opens (and initializes) the local access-log database and
// starts the batch writer plus the maintenance loops (retention + capacity).
// The recording mode must be "all" or "sites" — callers disable recording by
// not constructing a sink at all.
func NewSQLiteSink(dbPath string, cfg config.AccessLogRecordSettings, logger *slog.Logger) (*SQLiteSink, error) {
	return newSQLiteSink(dbPath, cfg, sqliteSinkQueueSize, true, logger)
}

// newSQLiteSink is the testable constructor: queue size and worker start are
// injectable so tests can pin queue-overflow behavior without racing the
// batch writer.
func newSQLiteSink(dbPath string, cfg config.AccessLogRecordSettings, queueSize int, startWorkers bool, logger *slog.Logger) (*SQLiteSink, error) {
	if logger == nil {
		logger = slog.Default()
	}
	switch cfg.ModeOrDefault() {
	case config.AccessRecordModeAll:
	case config.AccessRecordModeSites:
	default:
		return nil, fmt.Errorf("accesslog: access_log_record mode must be %q or %q, got %q",
			config.AccessRecordModeAll, config.AccessRecordModeSites, cfg.ModeOrDefault())
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("accesslog: create dir: %w", err)
	}
	dsn := "file:" + dbPath +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("accesslog: open %s: %w", dbPath, err)
	}
	db.SetMaxOpenConns(1) // sqlite: serialize writers, avoid busy locks
	if _, err := db.Exec(sqliteSinkSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("accesslog: init schema: %w", err)
	}
	if err := ensureAccessColumns(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("accesslog: upgrade schema: %w", err)
	}
	rdsn := "file:" + dbPath + "?_pragma=busy_timeout(5000)&_pragma=query_only(true)"
	rdb, err := sql.Open("sqlite", rdsn)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("accesslog: open read pool: %w", err)
	}
	rdb.SetMaxOpenConns(4)
	rdb.SetMaxIdleConns(4)

	batchSize := cfg.BatchSizeOrDefault()
	if batchSize <= 0 {
		batchSize = 256
	}
	s := &SQLiteSink{
		db:            db,
		rdb:           rdb,
		dbPath:        dbPath,
		logger:        logger,
		ch:            make(chan Entry, queueSize),
		workers:       startWorkers,
		batchSize:     batchSize,
		flushEvery:    time.Duration(cfg.FlushSecOrDefault()) * time.Second,
		retentionDays: cfg.RetentionDaysOrDefault(),
		maxDiskBytes:  int64(cfg.MaxDiskMBOrDefault()) << 20,
		diskFree:      diskFreeBytes,
		alerts:        make(map[string]SinkAlert, 4),
	}
	// Write-volume trigger: see sqliteSinkWriteTriggerFloor.
	s.writeTriggerBytes = s.maxDiskBytes / 8
	if s.writeTriggerBytes < sqliteSinkWriteTriggerFloor {
		s.writeTriggerBytes = sqliteSinkWriteTriggerFloor
	}
	switch cfg.ModeOrDefault() {
	case config.AccessRecordModeAll:
		s.allSites = true
	case config.AccessRecordModeSites:
		s.sites = make(map[string]struct{}, len(cfg.Sites))
		for _, site := range cfg.Sites {
			s.sites[strings.ToLower(strings.TrimSpace(site))] = struct{}{}
		}
	}
	if startWorkers {
		s.done = make(chan struct{})
		s.mstop = make(chan struct{})
		s.mdone = make(chan struct{})
		s.capKick = make(chan struct{}, 1)
		go s.loop()
		go s.maintenanceLoop()
		// Startup maintenance pass (L7): the retention ticker fires after
		// 24h and the capacity guard after 15 minutes, so a frequently
		// restarted instance could otherwise never purge expired rows.
		// Run one full pass now, asynchronously (never blocks boot).
		go s.maintainOnce()
	}
	return s, nil
}

// applies reports whether an entry passes the per-site recording filter:
// mode=all records every site EXCEPT the empty label (requests that matched
// no site — decision D3: they belong to no site), mode=sites records only
// the configured first domains (lowercase compare, matching the runtime
// site identity).
func (s *SQLiteSink) applies(e *Entry) bool {
	if s.allSites {
		return e.Site != ""
	}
	if len(s.sites) == 0 {
		return false
	}
	_, ok := s.sites[strings.ToLower(strings.TrimSpace(e.Site))]
	return ok
}

// Write implements Sink: one non-blocking send on a bounded queue; on
// overflow the entry is dropped and counted (Dropped). Entries not matching
// the recording filter are ignored silently (they were never recorded).
// When the disk guard has paused recording (data-volume low watermark) the
// entry is a counted drop before any copy/masking work happens: the request
// path pays one atomic load, never a blocking call.
// Sensitive query values and credential-shaped path segments are masked and
// long fields truncated on a COPY of the entry (the caller's entry is shared
// with the live-tail ring and the outbound shipper through the Tee and must
// keep its original values).
func (s *SQLiteSink) Write(e *Entry) {
	if e == nil {
		return
	}
	if !s.applies(e) {
		return
	}
	if s.diskPaused.Load() {
		// Disk low-watermark pause: counted drop, no enqueue.
		s.dropped.Add(1)
		return
	}
	ne := maskForStore(e)
	s.mu.Lock()
	if s.closed {
		// Close raced this Write (in-flight request outliving the config
		// switch): silent counted drop — never a send on a closed channel.
		s.mu.Unlock()
		s.dropped.Add(1)
		return
	}
	// Count BEFORE the send (S-1): the writer can commit a batch and
	// decrement pending between this send and a post-send increment, which
	// let Flush observe a transiently non-positive counter and return while
	// entries were still in flight. The failed-send branch rolls it back.
	s.pending.Add(1)
	select {
	case s.ch <- ne:
		if len(s.ch)*2 <= cap(s.ch) {
			s.clearAlert(AlertQueueFull)
		}
	default:
		s.pending.Add(-1)
		s.dropped.Add(1)
		s.raiseAlert(AlertQueueFull, AlertLevelWarning,
			"本地访问日志写入队列已满，正在丢弃入站记录（背压）")
	}
	s.mu.Unlock()
}

// Dropped returns the number of entries dropped before being persisted:
// queue overflow, disk-guard pause, close races, and failed batch writes
// (begin/prepare/commit failures plus statement-level Exec failures inside
// a committed transaction).
func (s *SQLiteSink) Dropped() int64 { return s.dropped.Load() }

// Pending returns the number of queued-but-uncommitted entries.
func (s *SQLiteSink) Pending() int64 { return s.pending.Load() }

// Depth returns the current queue length (observability gauge).
func (s *SQLiteSink) Depth() int { return len(s.ch) }

// Evicted returns the number of rows removed by capacity evictions
// (distinct from the retention purge).
func (s *SQLiteSink) Evicted() int64 { return s.evicted.Load() }

// DBPath returns the local database file path (diagnostics).
func (s *SQLiteSink) DBPath() string { return s.dbPath }

// SizeBytes reports the on-disk footprint: db + wal + shm files.
func (s *SQLiteSink) SizeBytes() int64 {
	var total int64
	for _, p := range []string{s.dbPath, s.dbPath + "-wal", s.dbPath + "-shm"} {
		if fi, err := os.Stat(p); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// Sink alert codes (stable machine strings; consumed by the console status
// feed — the /api/status runtime_alerts aggregation reads Alerts()).
const (
	AlertQueueFull       = "queue_full"
	AlertDiskLowPaused   = "disk_low_paused"
	AlertCapacityEvicted = "capacity_evicted"
	AlertDBWriteFailed   = "db_write_failed"
)

// Sink alert levels (lowercase, severity-ordered: warning < error).
const (
	AlertLevelWarning = "warning"
	AlertLevelError   = "error"
)

// SinkAlert is one active runtime anomaly of the local access-log sink.
// Message is operator-facing Chinese; Since is the UTC instant the anomaly
// was first raised (message refreshes on re-raise, Since does not). Semantics
// per code:
//   - queue_full (warning): the bounded write queue is full and inbound
//     entries are being dropped (backpressure). Clears when the queue drains
//     below half capacity.
//   - disk_low_paused (error): free space on the volume holding the database
//     fell below the safe watermark (max(1.2×max_disk_mb, 512MB)); local
//     recording is PAUSED (inbound entries are counted drops) until the next
//     guard pass sees the headroom restored.
//   - capacity_evicted (warning): the storage ceiling was exceeded and the
//     oldest recorded days were evicted. Clears when a guard pass finds the
//     footprint back within the ceiling.
//   - db_write_failed (error): a batch insert failed (disk/database error);
//     affected entries are dropped. Clears on the next successful insert.
type SinkAlert struct {
	Code    string    `json:"code"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
	Since   time.Time `json:"since"`
}

// Alerts returns a snapshot of the currently active runtime anomalies (no
// lock on the request path is involved; empty when healthy). Intended for
// the /api/status runtime_alerts aggregation — the sink must still be alive
// (a closed sink's snapshot is stale by definition).
func (s *SQLiteSink) Alerts() []SinkAlert {
	s.alertsMu.Lock()
	defer s.alertsMu.Unlock()
	if len(s.alerts) == 0 {
		return nil
	}
	out := make([]SinkAlert, 0, len(s.alerts))
	for _, a := range s.alerts {
		out = append(out, a)
	}
	return out
}

// raiseAlert records an active anomaly; re-raises refresh the message but
// keep the original Since. Callers already hold no ordering guarantee beyond
// alertsMu (taken either standalone or under s.mu — never the reverse).
func (s *SQLiteSink) raiseAlert(code, level, message string) {
	s.alertsMu.Lock()
	defer s.alertsMu.Unlock()
	if a, ok := s.alerts[code]; ok {
		a.Message = message
		s.alerts[code] = a
		return
	}
	s.alerts[code] = SinkAlert{Code: code, Level: level, Message: message, Since: time.Now().UTC()}
}

// clearAlert retires an anomaly.
func (s *SQLiteSink) clearAlert(code string) {
	s.alertsMu.Lock()
	delete(s.alerts, code)
	s.alertsMu.Unlock()
}

// diskFreeBytes reports the free bytes on the volume holding path (the
// gopsutil cross-platform statfs wrapper); ok=false when the volume cannot
// be determined — the disk guard then stays passive (the pre-guard
// behavior of only honoring max_disk_mb).
func diskFreeBytes(path string) (int64, bool) {
	u, err := disk.Usage(filepath.Dir(path))
	if err != nil || u == nil {
		return 0, false
	}
	return int64(u.Free), true
}

// capacityCeiling / diskFreeFn read the guard knobs under cfgMu so the
// maintenance goroutine never races a test that swaps them.
func (s *SQLiteSink) capacityCeiling() int64 {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.maxDiskBytes
}

func (s *SQLiteSink) diskFreeFn() func(path string) (int64, bool) {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.diskFree
}

// setCapacityCeiling / setDiskFree are the test seams for those knobs.
func (s *SQLiteSink) setCapacityCeiling(n int64) {
	s.cfgMu.Lock()
	s.maxDiskBytes = n
	s.cfgMu.Unlock()
}

func (s *SQLiteSink) setDiskFree(fn func(path string) (int64, bool)) {
	s.cfgMu.Lock()
	s.diskFree = fn
	s.cfgMu.Unlock()
}

// diskFloorBytes is the low-watermark for the volume holding the database:
// 1.2× the configured ceiling (maintenance scratch headroom) with a 512MB
// absolute floor for small ceilings (see sqliteSinkDiskFloorMin).
func (s *SQLiteSink) diskFloorBytes() int64 {
	ceiling := s.capacityCeiling()
	floor := ceiling + ceiling/5
	if floor < sqliteSinkDiskFloorMin {
		floor = sqliteSinkDiskFloorMin
	}
	return floor
}

// entryPayloadBytes estimates the stored footprint of one entry (text
// columns + fixed-column overhead) — the write-volume trigger signal.
func entryPayloadBytes(e *Entry) int64 {
	return int64(len(e.TS) + len(e.TraceID) + len(e.Site) + len(e.ClientIP) +
		len(e.Method) + len(e.Path) + len(e.Query) + len(e.UserAgent) +
		len(e.Outcome) + len(e.Rule) + len(e.AttackType) + 96)
}

// markWritten accumulates the estimated payload of a committed batch and,
// once the write-volume threshold is reached, kicks the maintenance loop for
// an extra capacity pass (non-blocking; the 15-minute ticker stays the
// fallback). Runs on the writer goroutine, never on the request path.
func (s *SQLiteSink) markWritten(batch []Entry) {
	if s.writeTriggerBytes <= 0 {
		return
	}
	var n int64
	for i := range batch {
		n += entryPayloadBytes(&batch[i])
	}
	if s.writtenSinceCheck.Add(n) < s.writeTriggerBytes {
		return
	}
	s.writtenSinceCheck.Store(0)
	if s.capKick != nil {
		select {
		case s.capKick <- struct{}{}:
		default:
		}
	}
}

// capacityPass runs one guard round: the storage-ceiling eviction
// (oldest-first, alerting on eviction) followed by the data-volume
// low-watermark check. reason is a short log tag
// ("periodic"/"write-volume"/"startup").
func (s *SQLiteSink) capacityPass(reason string) {
	if s.isClosed() || s.capacityCeiling() <= 0 {
		return
	}
	if n, err := s.enforceCapacity(); err != nil {
		s.logger.Warn("accesslog local: capacity eviction failed", "err", err)
	} else if n > 0 {
		s.logger.Info("accesslog local: capacity eviction", "rows", n, "db", s.dbPath)
		s.raiseAlert(AlertCapacityEvicted, AlertLevelWarning,
			fmt.Sprintf("本地访问日志库超出容量上限，已按最旧优先淘汰 %d 行", n))
	} else if s.SizeBytes() <= s.capacityCeiling() {
		s.clearAlert(AlertCapacityEvicted)
	}
	s.checkDiskHeadroom(reason)
}

// checkDiskHeadroom couples the guard to the VOLUME free space (联合感知):
// below the low-watermark it evicts once more when the database itself is
// over its ceiling and, if the volume stays tight, pauses local recording
// entirely (diskPaused) instead of filling the disk for co-tenants. Free
// space is read here only (maintenance goroutine); the request path pays a
// single atomic load per entry.
func (s *SQLiteSink) checkDiskHeadroom(reason string) {
	df := s.diskFreeFn()
	if df == nil {
		df = diskFreeBytes
	}
	free, ok := df(s.dbPath)
	if !ok {
		return // volume unknown: stay passive
	}
	floor := s.diskFloorBytes()
	if free >= floor {
		if s.diskPaused.CompareAndSwap(true, false) {
			s.logger.Info("accesslog local: disk headroom restored, resuming local recording",
				"free_mb", free>>20, "floor_mb", floor>>20, "reason", reason)
		}
		s.clearAlert(AlertDiskLowPaused)
		return
	}
	// Low watermark: one more eviction chance when the database itself is
	// over its ceiling, then pause recording.
	if s.SizeBytes() > s.capacityCeiling() {
		if n, err := s.enforceCapacity(); err == nil && n > 0 {
			s.logger.Warn("accesslog local: low-disk eviction", "rows", n, "db", s.dbPath)
		}
		if f2, ok2 := df(s.dbPath); ok2 {
			free = f2
			if free >= floor {
				s.clearAlert(AlertDiskLowPaused)
				return
			}
		}
	}
	s.diskPaused.Store(true)
	s.raiseAlert(AlertDiskLowPaused, AlertLevelError,
		fmt.Sprintf("数据盘剩余空间低于安全水位（剩余 %d MB，低于 %d MB），本地访问日志已暂停落盘", free>>20, floor>>20))
	s.logger.Warn("accesslog local: low disk headroom, pausing local recording",
		"free_mb", free>>20, "floor_mb", floor>>20, "reason", reason)
}

// Flush waits until every queued entry is committed (bounded by timeout).
func (s *SQLiteSink) Flush(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for s.pending.Load() > 0 {
		if time.Now().After(deadline) {
			return fmt.Errorf("accesslog: flush timeout with %d pending entries", s.pending.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

// Close flushes pending entries, stops the writer and the maintenance loops
// and closes both connection pools. Idempotent. mu guards closed so Write
// never sends into a closed channel (H1): close(ch) happens under the lock
// after closed is set, so a concurrent Write either lands before the close
// or sees the flag and drops. The lock is never held across the drain or
// the connection shutdowns.
func (s *SQLiteSink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.workers {
		close(s.ch)
	}
	s.mu.Unlock()

	var err error
	s.closeOnce.Do(func() {
		if s.workers {
			<-s.done
			close(s.mstop)
			<-s.mdone
		}
		_ = s.rdb.Close()
		err = s.db.Close()
	})
	return err
}

// isClosed reports whether the sink has been closed (best-effort guard for
// console-side maintenance; a race with Close still fails cleanly at the
// next closed-connection error).
func (s *SQLiteSink) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *SQLiteSink) loop() {
	defer close(s.done)
	batch := make([]Entry, 0, s.batchSize)
	ticker := time.NewTicker(s.flushEvery)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.insert(batch)
		batch = batch[:0]
	}
	for {
		select {
		case ev, ok := <-s.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ev)
			if len(batch) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *SQLiteSink) insert(batch []Entry) {
	tx, err := s.db.Begin()
	if err != nil {
		s.logger.Error("accesslog local: begin tx failed", "err", err)
		s.raiseAlert(AlertDBWriteFailed, AlertLevelError,
			"本地访问日志库写入失败（磁盘或数据库异常），正在丢弃新记录")
		s.pending.Add(-int64(len(batch)))
		s.dropped.Add(int64(len(batch)))
		return
	}
	stmt, err := tx.Prepare(`INSERT INTO access
		(ts_ms, ts, trace_id, site, client_ip, method, path, query, status, bytes, latency_ms, ua, outcome, rule, attack_type, body_skip)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		s.logger.Error("accesslog local: prepare failed", "err", err)
		s.raiseAlert(AlertDBWriteFailed, AlertLevelError,
			"本地访问日志库写入失败（磁盘或数据库异常），正在丢弃新记录")
		s.pending.Add(-int64(len(batch)))
		s.dropped.Add(int64(len(batch)))
		return
	}
	var failed int64
	for i := range batch {
		e := &batch[i]
		if _, err := stmt.Exec(
			parseEntryTS(e.TS).UnixMilli(), e.TS, e.TraceID, e.Site, e.ClientIP, e.Method,
			e.Path, e.Query, e.Status, e.Bytes, e.LatencyMS, e.UserAgent,
			e.Outcome, e.Rule, e.AttackType, e.BodySkip); err != nil {
			failed++
			s.logger.Error("accesslog local: insert failed", "err", err)
			s.raiseAlert(AlertDBWriteFailed, AlertLevelError,
				"本地访问日志库写入失败（磁盘或数据库异常），部分记录未落盘")
		}
	}
	if err := stmt.Close(); err != nil {
		s.logger.Error("accesslog local: stmt close failed", "err", err)
	}
	if err := tx.Commit(); err != nil {
		s.logger.Error("accesslog local: commit failed", "err", err)
		s.raiseAlert(AlertDBWriteFailed, AlertLevelError,
			"本地访问日志库写入提交失败（磁盘或数据库异常），本批记录未落盘")
		s.pending.Add(-int64(len(batch)))
		s.dropped.Add(int64(len(batch)))
		return
	}
	s.pending.Add(-int64(len(batch)))
	if failed > 0 {
		// Statement-level Exec failures that still ended in a successful
		// Commit lost exactly those rows (SQLite ABORT rolls back only the
		// failed statement). Count them as dropped and KEEP the alert raised:
		// like queue_full/capacity_evicted/disk_low_paused it must persist
		// while the condition exists and clear only on the next fully
		// successful insert — never within the same failing call.
		s.dropped.Add(failed)
	} else {
		s.clearAlert(AlertDBWriteFailed)
	}
	s.markWritten(batch)
}

// maintenanceLoop runs the periodic capacity guard (every 15 minutes, plus
// extra passes when accumulated write volume reaches the trigger) and the
// retention purge (daily) until Close.
func (s *SQLiteSink) maintenanceLoop() {
	defer close(s.mdone)
	capTicker := time.NewTicker(sqliteSinkCapacityEvery)
	defer capTicker.Stop()
	retTicker := time.NewTicker(sqliteSinkRetentionEvery)
	defer retTicker.Stop()
	for {
		select {
		case <-s.mstop:
			return
		case <-s.capKick:
			s.capacityPass("write-volume")
		case <-capTicker.C:
			s.capacityPass("periodic")
		case <-retTicker.C:
			if n, err := s.enforceRetention(); err != nil {
				s.logger.Warn("accesslog local: retention purge failed", "err", err)
			} else if n > 0 {
				s.logger.Info("accesslog local: retention purge", "rows", n, "days", s.retentionDays)
			}
		}
	}
}

// maintainOnce runs one retention purge followed by one capacity check: the
// startup maintenance pass (the periodic tickers first fire long after boot,
// so a frequently restarted instance could otherwise never purge). Also
// callable from tests.
func (s *SQLiteSink) maintainOnce() {
	if s.isClosed() {
		return
	}
	if n, err := s.enforceRetention(); err != nil {
		s.logger.Warn("accesslog local: retention purge failed", "err", err)
	} else if n > 0 {
		s.logger.Info("accesslog local: retention purge", "rows", n, "days", s.retentionDays)
	}
	if s.isClosed() {
		return
	}
	s.capacityPass("startup")
}

// enforceRetention deletes entries older than retention_days (daily job).
func (s *SQLiteSink) enforceRetention() (int64, error) {
	if s.retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -s.retentionDays)
	return s.purgeBefore(cutoff)
}

// purgeBefore deletes entries older than the given timestamp.
func (s *SQLiteSink) purgeBefore(before time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM access WHERE ts_ms < ?`, before.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("accesslog: purge: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// avgStoredRowBytes estimates the live per-row payload in bytes: the average
// summed column length over the newest rows (CAST to BLOB so LENGTH counts
// bytes, not characters — multibyte query/path text is common). Runs on the
// read pool under the read timeout; COALESCE keeps a table emptied between
// the row count and this query (a console PurgeAll racing the guard) from
// surfacing NULL.
func (s *SQLiteSink) avgStoredRowBytes() (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sqliteSinkReadTimeout)
	defer cancel()
	const lengthSum = `LENGTH(CAST(ts AS BLOB)) + LENGTH(CAST(trace_id AS BLOB)) + LENGTH(CAST(site AS BLOB))
		+ LENGTH(CAST(client_ip AS BLOB)) + LENGTH(CAST(method AS BLOB)) + LENGTH(CAST(path AS BLOB))
		+ LENGTH(CAST(query AS BLOB)) + LENGTH(CAST(status AS BLOB)) + LENGTH(CAST(bytes AS BLOB))
		+ LENGTH(CAST(latency_ms AS BLOB)) + LENGTH(CAST(ua AS BLOB)) + LENGTH(CAST(outcome AS BLOB))
		+ LENGTH(CAST(rule AS BLOB)) + LENGTH(CAST(attack_type AS BLOB))`
	var avg int64
	err := s.rdb.QueryRowContext(ctx, `SELECT CAST(COALESCE(AVG(l), 0) AS INTEGER) FROM (
		SELECT `+lengthSum+` AS l FROM access ORDER BY id DESC LIMIT ?)`,
		sqliteSinkPayloadSampleRows).Scan(&avg)
	if err != nil {
		return 0, fmt.Errorf("accesslog: capacity avg row: %w", err)
	}
	return avg, nil
}

// enforceCapacity evicts the oldest days when the on-disk footprint exceeds
// the configured ceiling, down to 80% of it (modeled after the audit
// disk-guard's oldest-first policy). The eviction target is derived from the
// live PAYLOAD average (avgStoredRowBytes), never from the file footprint
// (GATE-1): the footprint (db + wal + shm) only decides WHETHER the guard
// runs. DELETE frees pages for reuse without shrinking the file, so a
// footprint-derived average collapses once the database sits at its
// high-water mark — every pass then re-evicted at least 20% of the surviving
// rows and the retention window decayed to zero on low traffic. Eviction
// never crosses into the most recent 24h of data (a ceiling smaller than one
// day of traffic degrades to the disk-guard pause instead of wiping the
// store), and a TRUNCATE checkpoint afterwards pulls the WAL back down so
// the footprint trigger reflects the live payload again.
func (s *SQLiteSink) enforceCapacity() (int64, error) {
	ceiling := s.capacityCeiling()
	if ceiling <= 0 {
		return 0, nil
	}
	size := s.SizeBytes()
	if size <= ceiling {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), sqliteSinkReadTimeout)
	defer cancel()
	var rows int64
	if err := s.rdb.QueryRowContext(ctx, `SELECT COUNT(*) FROM access`).Scan(&rows); err != nil {
		return 0, fmt.Errorf("accesslog: capacity count: %w", err)
	}
	if rows == 0 {
		return 0, nil
	}
	avgRow, err := s.avgStoredRowBytes()
	if err != nil {
		return 0, err
	}
	if avgRow <= 0 {
		// A non-positive estimate must never drive eviction: a degenerate
		// targetRows=0 used to wipe the whole store. Skip the pass; the next
		// one re-estimates.
		s.logger.Warn("accesslog local: capacity guard skipped, live payload estimate unavailable",
			"rows", rows, "avg_row_bytes", avgRow)
		return 0, nil
	}
	targetRows := ceiling * sqliteSinkEvictFloorPct / 100 / avgRow
	// Floor: eviction stops at the recent-day boundary — data younger than
	// 24h is never evicted.
	evictBefore := time.Now().Add(-24 * time.Hour)
	var evicted int64
	for i := 0; i < sqliteSinkMaxEvictCycles && rows > targetRows; i++ {
		oldest, ok := s.oldestTS()
		if !ok {
			break
		}
		cutoff := oldest.Add(24 * time.Hour)
		if cutoff.After(evictBefore) {
			cutoff = evictBefore
		}
		if !cutoff.After(oldest) {
			break // only recent-day data remains: protected
		}
		n, err := s.purgeBefore(cutoff)
		if err != nil {
			return evicted, err
		}
		if n == 0 {
			break
		}
		s.evicted.Add(n)
		evicted += n
		rows -= n
	}
	if evicted > 0 {
		// The deleted pages sit in the WAL until checkpointed; a TRUNCATE
		// checkpoint pulls the footprint (the guard's trigger) back toward
		// the live payload. Best-effort: failure only leaves the wal larger
		// and the eviction result stands.
		if _, cerr := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); cerr != nil {
			s.logger.Warn("accesslog local: wal checkpoint after eviction failed", "err", cerr)
		}
	}
	return evicted, nil
}

// Rows returns the number of rows currently stored (console-facing COUNT(*)
// with the read-pool timeout; never called on the request path).
func (s *SQLiteSink) Rows() (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sqliteSinkReadTimeout)
	defer cancel()
	var rows int64
	if err := s.rdb.QueryRowContext(ctx, `SELECT COUNT(*) FROM access`).Scan(&rows); err != nil {
		return 0, fmt.Errorf("accesslog: row count: %w", err)
	}
	return rows, nil
}

// OldestTS returns the oldest recorded timestamp (ok=false for an empty
// store); the record status object surfaces it as oldest_ts.
func (s *SQLiteSink) OldestTS() (time.Time, bool) { return s.oldestTS() }

// PurgeAll deletes every recorded row and reclaims the file space: DELETE
// alone leaves the SQLite file at its high-water mark (freed pages are
// reused, never returned to the OS), so the delete is followed by VACUUM
// and a WAL checkpoint truncate. Rows still sitting in the write queue are
// flushed afterwards — they are post-purge records and stay. The write
// mutex is NOT held across the statements (a console purge must never stall
// the request path; WAL + busy_timeout serializes the writers instead).
func (s *SQLiteSink) PurgeAll() (int64, error) {
	if s.isClosed() {
		return 0, fmt.Errorf("accesslog: local store already closed")
	}
	res, err := s.db.Exec(`DELETE FROM access`)
	if err != nil {
		return 0, fmt.Errorf("accesslog: purge all: %w", err)
	}
	n, _ := res.RowsAffected()
	if _, verr := s.db.Exec(`VACUUM`); verr != nil {
		return n, fmt.Errorf("accesslog: vacuum: %w", verr)
	}
	if _, cerr := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); cerr != nil {
		// Space-reclaim nicety; the destructive contract (rows gone) held.
		s.logger.Warn("accesslog local: wal checkpoint after purge failed", "err", cerr)
	}
	return n, nil
}

// oldestTS returns the oldest recorded timestamp (day-batch eviction start).
func (s *SQLiteSink) oldestTS() (time.Time, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), sqliteSinkReadTimeout)
	defer cancel()
	var ms int64
	if err := s.rdb.QueryRowContext(ctx, `SELECT MIN(ts_ms) FROM access`).Scan(&ms); err != nil || ms == 0 {
		return time.Time{}, false
	}
	return time.UnixMilli(ms).UTC(), true
}

func parseEntryTS(ts string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t
	}
	return time.Now()
}

// HistoryQuery filters the local history query (parameter parsing mirrors
// the audit-log query: site substring, outcome exact, IP prefix, free text
// over path/ua/rule/ip/trace, RFC3339 time range).
type HistoryQuery struct {
	Site    string
	Outcome string
	IP      string
	Text    string
	Since   time.Time
	Until   time.Time
	Limit   int
	Offset  int
}

// HistoryPage is one page of the local history query.
type HistoryPage struct {
	Items []Entry
	Total int
}

// History returns one page of locally recorded entries, newest first.
func (s *SQLiteSink) History(q HistoryQuery) (HistoryPage, error) {
	where, args := historyWhere(q)
	ctx, cancel := context.WithTimeout(context.Background(), sqliteSinkReadTimeout)
	defer cancel()
	var total int
	if err := s.rdb.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM access WHERE `+where, args...).Scan(&total); err != nil {
		return HistoryPage{}, fmt.Errorf("accesslog: history count: %w", err)
	}
	limit, offset := normalizeHistoryWindow(q)
	qargs := append(args, limit, offset)
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT ts, trace_id, site, client_ip, method, path, query, status, bytes, latency_ms, ua, outcome, rule, attack_type, body_skip
		 FROM access WHERE `+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, qargs...)
	if err != nil {
		return HistoryPage{}, fmt.Errorf("accesslog: history query: %w", err)
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
		return HistoryPage{}, fmt.Errorf("accesslog: history rows: %w", err)
	}
	return HistoryPage{Items: items, Total: total}, nil
}

// normalizeHistoryWindow normalizes the paging window shared by History and
// LocalHistory: non-positive limits default to 100, limits above 1000 clamp
// to 1000 (S-10: silently dropping an over-cap limit to 100 made large
// explicit pages return fewer rows than requested), offset never negative.
func normalizeHistoryWindow(q HistoryQuery) (limit, offset int) {
	limit = q.Limit
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}
	offset = q.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// historyWhere builds the WHERE clause shared by History and its COUNT.
func historyWhere(q HistoryQuery) (string, []any) {
	where := []string{"1=1"}
	var args []any
	if !q.Since.IsZero() {
		where = append(where, "ts_ms >= ?")
		args = append(args, q.Since.UnixMilli())
	}
	if !q.Until.IsZero() {
		where = append(where, "ts_ms <= ?")
		args = append(args, q.Until.UnixMilli())
	}
	if q.Outcome != "" {
		where = append(where, "outcome = ?")
		args = append(args, q.Outcome)
	}
	if s := strings.TrimSpace(q.Site); s != "" {
		where = append(where, `site LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(s)+"%")
	}
	if ip := strings.TrimSpace(q.IP); ip != "" {
		where = append(where, `client_ip LIKE ? ESCAPE '\'`)
		args = append(args, escapeLike(ip)+"%")
	}
	if t := strings.TrimSpace(q.Text); t != "" {
		like := "%" + escapeLike(t) + "%"
		where = append(where, `(path LIKE ? ESCAPE '\' OR ua LIKE ? ESCAPE '\' OR rule LIKE ? ESCAPE '\'
			OR client_ip LIKE ? ESCAPE '\' OR trace_id LIKE ? ESCAPE '\')`)
		args = append(args, like, like, like, like, like)
	}
	return strings.Join(where, " AND "), args
}

// escapeLike escapes LIKE wildcards (same convention as the audit store).
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
