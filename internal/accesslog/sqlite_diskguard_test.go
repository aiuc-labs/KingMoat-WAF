package accesslog

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// findAlert returns the active alert with the given code (nil when absent).
func findAlert(alerts []SinkAlert, code string) *SinkAlert {
	for i := range alerts {
		if alerts[i].Code == code {
			return &alerts[i]
		}
	}
	return nil
}

// TestSQLiteSinkDiskLowWatermark pins the data-volume guard: free space
// below the floor pauses recording (counted drops, error-level alert);
// restored headroom resumes recording and clears the alert. diskFree is
// injected — the test never depends on the host's real volumes.
func TestSQLiteSinkDiskLowWatermark(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1, MaxDiskMB: 128}, 64, true)
	// 128MB ceiling → floor = max(1.2×128MB, 512MB) = 512MB.
	if got := s.diskFloorBytes(); got != 512<<20 {
		t.Fatalf("diskFloorBytes = %d, want %d (1.2× ceiling floored at 512MB)", got, 512<<20)
	}

	// Healthy headroom: passive, no alerts, recording stays on.
	s.setDiskFree(func(string) (int64, bool) { return 10 << 30, true }) // 10GB
	start := time.Now()
	s.capacityPass("test")
	t.Logf("capacityPass (healthy) latency: %v", time.Since(start)) // 实测：检查成本基线
	if s.diskPaused.Load() {
		t.Fatal("healthy headroom must not pause recording")
	}
	if alerts := s.Alerts(); len(alerts) != 0 {
		t.Fatalf("healthy headroom must raise no alerts, got %+v", alerts)
	}

	// Below the floor: pause + counted drops + error alert.
	s.setDiskFree(func(string) (int64, bool) { return 100 << 20, true }) // 100MB < 512MB
	start = time.Now()
	s.capacityPass("test")
	t.Logf("capacityPass (low watermark) latency: %v", time.Since(start))
	if !s.diskPaused.Load() {
		t.Fatal("low watermark must pause recording")
	}
	s.Write(entryAt("a.local", 0, "/paused"))
	if s.Dropped() != 1 {
		t.Fatalf("paused write must be a counted drop, got dropped=%d", s.Dropped())
	}
	a := findAlert(s.Alerts(), AlertDiskLowPaused)
	if a == nil {
		t.Fatal("disk_low_paused alert missing while paused")
	}
	if a.Level != AlertLevelError || a.Since.IsZero() || a.Message == "" {
		t.Fatalf("disk_low_paused shape = %+v, want error level, non-zero since, Chinese message", *a)
	}

	// Restored headroom: resume + clear + writes land again.
	s.setDiskFree(func(string) (int64, bool) { return 600 << 20, true })
	s.capacityPass("test")
	if s.diskPaused.Load() {
		t.Fatal("restored headroom must resume recording")
	}
	if a := findAlert(s.Alerts(), AlertDiskLowPaused); a != nil {
		t.Fatalf("disk_low_paused must clear after restoration, got %+v", *a)
	}
	s.Write(entryAt("a.local", 0, "/resumed"))
	if err := s.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	if page, err := s.History(HistoryQuery{Limit: 10}); err != nil || page.Total != 1 {
		t.Fatalf("post-resume write must land (total=%d, err=%v)", page.Total, err)
	}
}

// TestSQLiteSinkDiskUnknownVolumeStaysPassive: a failed free-space lookup
// keeps the previous behavior (guard passive, recording on).
func TestSQLiteSinkDiskUnknownVolumeStaysPassive(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all"}, 8, true)
	s.setDiskFree(func(string) (int64, bool) { return 0, false })
	s.capacityPass("test")
	if s.diskPaused.Load() {
		t.Fatal("unknown volume must not pause recording")
	}
	if alerts := s.Alerts(); len(alerts) != 0 {
		t.Fatalf("unknown volume must raise no alerts, got %+v", alerts)
	}
}

// TestSQLiteSinkCapacityEvictedAlert walks the real eviction path: data over
// a (shrunken) ceiling is evicted oldest-first and the capacity_evicted
// warning is raised; a later pass within the ceiling clears it. The rows
// carry a 72h-old timestamp so the eviction window sits outside the
// protected recent day (the 24h floor must not block the guard); 30 rows of
// the filler exceed the 80% target of the 16KB ceiling (the long single-chunk
// value collapses to a masked k=*** chunk, ~580B stored per row); the clear
// phase widens the ceiling back above the file's high-water mark (DELETE
// never shrinks the file).
func TestSQLiteSinkCapacityEvictedAlert(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 64, true)
	filler := strings.Repeat("k=zzzz", 700)
	for i := 0; i < 30; i++ {
		e := entryAt("a.local", 72, "/cap")
		e.Query = filler
		e.UserAgent = filler
		s.Write(e)
	}
	if err := s.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	s.setCapacityCeiling(16 << 10) // 16KB: live payload (~26KB) exceeds the 80% target — eviction runs
	s.setDiskFree(func(string) (int64, bool) { return 10 << 30, true })
	s.capacityPass("test")
	if s.Evicted() == 0 {
		t.Fatal("over-ceiling data must be evicted")
	}
	a := findAlert(s.Alerts(), AlertCapacityEvicted)
	if a == nil || a.Level != AlertLevelWarning || a.Since.IsZero() {
		t.Fatalf("capacity_evicted shape = %+v, want warning level + since", a)
	}
	if rows, err := s.Rows(); err != nil || rows != 0 {
		t.Fatalf("rows after eviction = %d/%v, want 0/nil", rows, err)
	}
	// A later pass with the footprint within the ceiling clears the alert.
	s.setCapacityCeiling(64 << 10)
	s.clearAlert(AlertCapacityEvicted)
	s.capacityPass("test")
	if a := findAlert(s.Alerts(), AlertCapacityEvicted); a != nil {
		t.Fatalf("capacity_evicted must clear within the ceiling, got %+v", *a)
	}
}

// TestSQLiteSinkWriteVolumeKick pins the write-volume trigger: committed
// payload accumulates until the threshold, then one non-blocking kick is
// produced for the maintenance loop and the counter resets (兜底 ticker is
// exercised by the existing maintenance tests). The kick consumer is
// test-owned (workers=false + a counting goroutine): racing the production
// maintenanceLoop made the channel-length assertions scheduling-dependent
// and flaky on multi-P runs.
func TestSQLiteSinkWriteVolumeKick(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 8, false)
	s.capKick = make(chan struct{}, 1) // nil without workers; test-owned channel plus counting consumer
	s.writeTriggerBytes = 1024
	s.writtenSinceCheck.Store(0)

	var kicks atomic.Int64
	stop := make(chan struct{})
	consumerDone := make(chan struct{})
	go func() {
		defer close(consumerDone)
		for {
			select {
			case <-s.capKick:
				kicks.Add(1)
			case <-stop:
				return
			}
		}
	}()
	var stopOnce sync.Once
	stopConsumer := func() {
		stopOnce.Do(func() {
			close(stop)
			<-consumerDone
		})
	}
	t.Cleanup(stopConsumer)

	s.markWritten([]Entry{*entryAt("a.local", 0, "/small")})
	if kicks.Load() != 0 {
		t.Fatal("below the trigger must not kick")
	}
	if s.writtenSinceCheck.Load() == 0 {
		t.Fatal("committed payload must accumulate below the trigger")
	}

	big := entryAt("a.local", 0, "/big")
	big.Query = strings.Repeat("x", 2000)
	s.markWritten([]Entry{*big})
	// Synchronize on the consumer's accumulated kick count instead of racing
	// the channel length: markWritten fires at most one kick per call, so
	// exactly one arrives.
	deadline := time.Now().Add(2 * time.Second)
	for kicks.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("reaching the trigger must kick once, got %d kicks", kicks.Load())
		}
		time.Sleep(time.Millisecond)
	}
	if s.writtenSinceCheck.Load() != 0 {
		t.Fatal("the counter must reset after the kick")
	}

	// Buffered(1) + non-blocking, verified in a consumer-free window: two
	// over-threshold markWritten calls leave exactly one kick in the channel
	// (the second is dropped by the select default, never blocking).
	stopConsumer()
	select {
	case <-s.capKick:
	default:
	}
	s.markWritten([]Entry{*big, *big})
	if len(s.capKick) != 1 {
		t.Fatalf("kick channel must stay at 1 (non-blocking), got %d", len(s.capKick))
	}
}

// TestSQLiteSinkQueueFullAlert: queue overflow raises the queue_full warning
// and draining below half capacity clears it.
func TestSQLiteSinkQueueFullAlert(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all"}, 2, false) // workers=false: queue never drains
	s.Write(entryAt("a.local", 0, "/q1"))
	s.Write(entryAt("a.local", 0, "/q2")) // queue now full
	s.Write(entryAt("a.local", 0, "/q3")) // overflow → dropped + alert
	if s.Dropped() != 1 {
		t.Fatalf("overflow drop = %d, want 1", s.Dropped())
	}
	a := findAlert(s.Alerts(), AlertQueueFull)
	if a == nil || a.Level != AlertLevelWarning {
		t.Fatalf("queue_full shape = %+v, want warning level", a)
	}
	// Drain below half capacity → the alert clears on the next successful send.
	s.clearQueueForTest()
	s.Write(entryAt("a.local", 0, "/q4"))
	if a := findAlert(s.Alerts(), AlertQueueFull); a != nil {
		t.Fatalf("queue_full must clear after draining, got %+v", *a)
	}
}

// clearQueueForTest drains the write queue (workers=false keeps it full).
func (s *SQLiteSink) clearQueueForTest() {
	for {
		select {
		case <-s.ch:
		default:
			return
		}
	}
}

// storedPayload sums the stored column lengths and the row count straight
// from the database (the same payload definition the guard's estimator
// uses), so the assertions below measure truth, not the estimate.
func storedPayload(t *testing.T, s *SQLiteSink) (rows, payload int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := s.rdb.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(
		LENGTH(CAST(ts AS BLOB)) + LENGTH(CAST(trace_id AS BLOB)) + LENGTH(CAST(site AS BLOB))
		+ LENGTH(CAST(client_ip AS BLOB)) + LENGTH(CAST(method AS BLOB)) + LENGTH(CAST(path AS BLOB))
		+ LENGTH(CAST(query AS BLOB)) + LENGTH(CAST(status AS BLOB)) + LENGTH(CAST(bytes AS BLOB))
		+ LENGTH(CAST(latency_ms AS BLOB)) + LENGTH(CAST(ua AS BLOB)) + LENGTH(CAST(outcome AS BLOB))
		+ LENGTH(CAST(rule AS BLOB)) + LENGTH(CAST(attack_type AS BLOB))), 0) FROM access`).Scan(&rows, &payload)
	if err != nil {
		t.Fatalf("stored payload query: %v", err)
	}
	return rows, payload
}

// TestEnforceCapacityRatchetGuard pins the GATE-1 fix end to end. Fill a
// fixed-width store past its ceiling, evict once, then keep firing the guard
// over the SAME data: the file stays at its high-water mark, so the
// footprint trigger keeps firing, but the payload-based target is stable —
// every idle pass must be a no-op (the old footprint-derived average
// re-evicted ≥20% per pass and decayed the retention window to zero on low
// traffic). Low-traffic rounds (a few fresh rows) rotate one oldest day
// batch, never a compounding cut, and the surviving payload stays within
// the 80% target (±10% tolerance).
func TestEnforceCapacityRatchetGuard(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 256}, 4096, true)
	s.setDiskFree(func(string) (int64, bool) { return 10 << 30, true }) // hermetic disk guard

	const (
		ceiling    = int64(2 << 20) // 2MB
		rowsPerDay = 100
		days       = 100 // day 0 = now (protected by the 24h floor), days 1..99 evictable
	)
	path := "/ratchet/" + strings.Repeat("x", 160) // fixed-width rows: the payload math below is exact
	for chunk := 0; chunk < days/10; chunk++ {
		for d := chunk * 10; d < (chunk+1)*10; d++ {
			for i := 0; i < rowsPerDay; i++ {
				s.Write(entryAt("a.local", d*24, path+"/"+itoa(i)))
			}
		}
		if err := s.Flush(10 * time.Second); err != nil {
			t.Fatalf("fill flush: %v", err)
		}
	}

	rowsAll, payloadAll := storedPayload(t, s)
	if rowsAll == 0 || payloadAll == 0 {
		t.Fatalf("fill landed %d rows / %d payload bytes", rowsAll, payloadAll)
	}
	rowWidth := payloadAll / rowsAll
	s.setCapacityCeiling(ceiling)
	if s.SizeBytes() <= ceiling {
		t.Fatalf("fill must trip the footprint trigger: size=%d ceiling=%d", s.SizeBytes(), ceiling)
	}
	if payloadAll <= ceiling*80/100 {
		t.Fatalf("fill must carry more live payload than the 80%% target: payload=%d target=%d", payloadAll, ceiling*80/100)
	}

	// Round 1: the over-ceiling pass evicts down to the row target.
	n1, err := s.enforceCapacity()
	if err != nil {
		t.Fatalf("enforceCapacity: %v", err)
	}
	if n1 == 0 || n1 != s.Evicted() {
		t.Fatalf("first pass evicted %d (counter %d), want >0 with matching counter", n1, s.Evicted())
	}
	rows1, payload1 := storedPayload(t, s)
	targetRows := ceiling * 80 / 100 / rowWidth
	if rows1 < targetRows*9/10 {
		t.Fatalf("rows after eviction = %d, want >= %d (0.8×ceiling/rowWidth = %d, 10%% tolerance)", rows1, targetRows*9/10, targetRows)
	}
	if payload1 < ceiling*72/100 {
		t.Fatalf("payload after eviction = %d, want >= %d (80%% target, 10%% tolerance)", payload1, ceiling*72/100)
	}

	// Rounds 2–4: idle passes over the SAME data must not cut rows.
	for round := 2; round <= 4; round++ {
		n, err := s.enforceCapacity()
		if err != nil {
			t.Fatalf("idle round %d: %v", round, err)
		}
		rows, payload := storedPayload(t, s)
		if n != 0 || rows != rows1 {
			t.Fatalf("idle round %d evicted %d rows → %d (was %d): the ratchet is back", round, n, rows, rows1)
		}
		if payload < ceiling*72/100 {
			t.Fatalf("idle round %d payload = %d, below the 72%% floor", round, payload)
		}
	}

	// Low-traffic rounds: a few fresh rows push the store past the target
	// again; each pass rotates at most one oldest day batch (drop < 5%),
	// never a compounding cut.
	for round := 0; round < 3; round++ {
		for i := 0; i < 10; i++ {
			s.Write(entryAt("a.local", 0, path+"/fresh"+itoa(round*100+i)))
		}
		if err := s.Flush(10 * time.Second); err != nil {
			t.Fatalf("low-traffic flush round %d: %v", round, err)
		}
		before, _ := storedPayload(t, s)
		if _, err := s.enforceCapacity(); err != nil {
			t.Fatalf("low-traffic round %d: %v", round, err)
		}
		after, payload := storedPayload(t, s)
		if drop := before - after; drop*20 >= before {
			t.Fatalf("low-traffic round %d dropped %d of %d rows (≥5%%): ratchet", round, drop, before)
		}
		if payload < ceiling*72/100 {
			t.Fatalf("low-traffic round %d payload = %d, below the 72%% floor", round, payload)
		}
	}
}

// TestEnforceCapacityEmptyStore pins the rows=0 guard: an over-ceiling
// footprint with an empty table must be a no-op (no division by zero, no
// eviction), and the payload estimator reports 0 for the empty sample
// (invariant: a non-positive estimate never drives eviction).
func TestEnforceCapacityEmptyStore(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 8, false)
	s.setDiskFree(func(string) (int64, bool) { return 10 << 30, true })
	s.setCapacityCeiling(1) // any footprint exceeds this; the table is empty
	n, err := s.enforceCapacity()
	if err != nil || n != 0 {
		t.Fatalf("enforceCapacity on an empty store = %d/%v, want 0/nil", n, err)
	}
	if avg, err := s.avgStoredRowBytes(); err != nil || avg != 0 {
		t.Fatalf("avgStoredRowBytes on an empty store = %d/%v, want 0/nil", avg, err)
	}
}

// TestSQLiteSinkDBWriteFailedAlert: a failed batch insert raises the
// db_write_failed error alert (the disk/database failure shape). s.db is
// closed first, so this exercises the BEGIN-failure branch: raise + counted
// drop + the alert staying raised (early return, no clear).
func TestSQLiteSinkDBWriteFailedAlert(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 2}, 8, true)
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	s.insert([]Entry{*entryAt("a.local", 0, "/fail")})
	a := findAlert(s.Alerts(), AlertDBWriteFailed)
	if a == nil || a.Level != AlertLevelError || a.Message == "" {
		t.Fatalf("db_write_failed shape = %+v, want error level + message", a)
	}
}

// TestSQLiteSinkPartialExecFailureKeepsAlert covers the failure shape the
// alert contract previously missed: statement-level Exec failures inside a
// transaction that still Commits (SQLite ABORT rolls back only the failed
// statement). The failed rows must be counted in Dropped(), the
// db_write_failed alert must STAY raised (no raise→clear transient inside
// the same insert), and the next fully successful insert clears it.
func TestSQLiteSinkPartialExecFailureKeepsAlert(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 4}, 8, true)
	// Inject statement-level failures without touching the sink: the trigger
	// aborts exactly the rows whose path is /boom (ABORT keeps the
	// transaction alive, so Commit succeeds — empty tx or not).
	if _, err := s.db.Exec(`CREATE TRIGGER accesslog_test_boom BEFORE INSERT ON access
		WHEN NEW.path = '/boom' BEGIN SELECT RAISE(ABORT, 'injected test failure'); END`); err != nil {
		t.Fatal(err)
	}

	// Mixed batch: one row lands, two rows fail at Exec, Commit succeeds.
	s.pending.Add(3) // simulate the enqueue side of the batch lifecycle
	before := s.Dropped()
	s.insert([]Entry{*entryAt("a.local", 0, "/ok"), *entryAt("a.local", 0, "/boom"), *entryAt("a.local", 0, "/boom")})
	if got := s.Dropped() - before; got != 2 {
		t.Fatalf("dropped grew by %d, want 2 (the Exec-failed rows)", got)
	}
	if s.Pending() != 0 {
		t.Fatalf("pending = %d, want 0 after the committed batch", s.Pending())
	}
	if a := findAlert(s.Alerts(), AlertDBWriteFailed); a == nil || a.Level != AlertLevelError {
		t.Fatalf("db_write_failed must stay raised after partial Exec failures, got %+v", a)
	}
	// The surviving row is queryable; the aborted ones are gone.
	page, err := s.History(HistoryQuery{Text: "/ok"})
	if err != nil || page.Total != 1 {
		t.Fatalf("committed rows = %d/%v, want 1 (only the healthy row lands)", page.Total, err)
	}

	// All-fail batch: an EMPTY transaction that still Commits — the dropped
	// counting and the alert persistence hold identically.
	s.pending.Add(2)
	before = s.Dropped()
	s.insert([]Entry{*entryAt("a.local", 0, "/boom"), *entryAt("a.local", 0, "/boom")})
	if got := s.Dropped() - before; got != 2 {
		t.Fatalf("dropped grew by %d, want 2 for the all-fail batch", got)
	}
	if s.Pending() != 0 {
		t.Fatalf("pending = %d, want 0 after the all-fail batch", s.Pending())
	}
	if a := findAlert(s.Alerts(), AlertDBWriteFailed); a == nil {
		t.Fatal("db_write_failed must stay raised after an all-fail batch")
	}

	// The alert clears only on the next fully successful insert.
	s.pending.Add(1)
	s.insert([]Entry{*entryAt("a.local", 0, "/recovered")})
	if a := findAlert(s.Alerts(), AlertDBWriteFailed); a != nil {
		t.Fatalf("db_write_failed must clear after the next fully successful insert, got %+v", *a)
	}
}

// TestSinkAlertsSnapshot pins the Alerts() contract: snapshot isolation,
// re-raise refreshes the message but keeps Since, clear retires the entry.
func TestSinkAlertsSnapshot(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all"}, 4, false)
	if got := s.Alerts(); len(got) != 0 {
		t.Fatalf("fresh sink must be healthy, got %+v", got)
	}
	s.raiseAlert(AlertCapacityEvicted, AlertLevelWarning, "本地访问日志库超出容量上限，已按最旧优先淘汰 10 行")
	s.raiseAlert(AlertDiskLowPaused, AlertLevelError, "数据盘剩余空间低于安全水位，本地访问日志已暂停落盘")
	snap := s.Alerts()
	if len(snap) != 2 {
		t.Fatalf("alerts = %d, want 2", len(snap))
	}
	first := findAlert(snap, AlertCapacityEvicted)
	time.Sleep(2 * time.Millisecond)
	s.raiseAlert(AlertCapacityEvicted, AlertLevelWarning, "更新后的文案")
	again := findAlert(s.Alerts(), AlertCapacityEvicted)
	if !again.Since.Equal(first.Since) {
		t.Fatalf("re-raise must keep Since (%v), got %v", first.Since, again.Since)
	}
	if again.Message != "更新后的文案" {
		t.Fatalf("re-raise must refresh the message, got %q", again.Message)
	}
	s.clearAlert(AlertCapacityEvicted)
	s.clearAlert(AlertDiskLowPaused)
	if got := s.Alerts(); len(got) != 0 {
		t.Fatalf("cleared sink must be healthy, got %+v", got)
	}
}
