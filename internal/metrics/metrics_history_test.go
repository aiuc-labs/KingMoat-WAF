package metrics

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRecordDailyHistoryFoldsAndPrunes verifies the per-day history fold:
// counters land on the day they belong to (yesterday after midnight), the
// same-day fold refreshes in place and days beyond the retention window
// are pruned.
func TestRecordDailyHistoryFoldsAndPrunes(t *testing.T) {
	ResetDailyForTest()
	t.Cleanup(ResetDailyForTest)

	// Freeze "now" once and derive every day key from it: independent
	// time.Now() calls straddling local midnight made yesterday/today
	// disagree (ms-wide window) and failed the test around 00:00 local.
	now := time.Now()
	DailyReqInc("a.local", "forwarded")
	DailyReqInc("a.local", "forwarded")
	DailyReqInc("b.local", "blocked")

	yesterday := now.AddDate(0, 0, -1)
	yKey := localDayKey(yesterday)
	// Simulate the post-midnight flush: the pending counters belong to
	// yesterday's day key.
	dailyDay.Store(yKey)
	recordDailyHistory(dayKeyString(yKey))

	hist := SnapshotRequestsHistory()
	yDate := yesterday.Format("2006-01-02")
	if h := hist[yDate]; h == nil || h["forwarded"] != 2 || h["blocked"] != 1 {
		t.Fatalf("yesterday fold wrong: %+v", hist[yDate])
	}

	// A day beyond retention is pruned on the next fold.
	old := now.AddDate(0, 0, -(dailyHistoryRetention + 5))
	dailyHistoryMu.Lock()
	dailyHistory[old.Format("2006-01-02")] = map[string]int64{"forwarded": 9}
	dailyHistoryMu.Unlock()
	recordDailyHistory(now.Format("2006-01-02"))
	hist = SnapshotRequestsHistory()
	if _, ok := hist[old.Format("2006-01-02")]; ok {
		t.Fatalf("stale day survived pruning: %+v", hist)
	}
	today := now.Format("2006-01-02")
	if h := hist[today]; h == nil || h["forwarded"] != 2 {
		t.Fatalf("today fold wrong: %+v", hist[today])
	}
}

// TestRolloverFoldsFinalCountsIntoHistory verifies that the request-side
// rollover folds the final counts into the previous day's history key before
// wiping the live counters, and that subsequent same-day folds (flushes) no
// longer overwrite that old day.
func TestRolloverFoldsFinalCountsIntoHistory(t *testing.T) {
	resetDaily(t)

	// Freeze "now" once (see TestRecordDailyHistoryFoldsAndPrunes): all day
	// keys below must agree even when the wall clock crosses local midnight
	// mid-test. The rollover trigger itself compares against the real clock
	// and fires whenever the stored key is a previous day.
	now := time.Now()
	DailyReqInc("a.local", "forwarded")
	DailyReqInc("a.local", "forwarded")
	DailyReqInc("a.local", "blocked")

	yDate := now.AddDate(0, 0, -1).Format("2006-01-02")
	// Pretend the live counters belong to yesterday and let the next
	// request trigger the rollover.
	dailyDay.Store(localDayKey(now.AddDate(0, 0, -1)))
	DailyReqInc("b.local", "challenged")

	hist := SnapshotRequestsHistory()
	if h := hist[yDate]; h == nil || h["forwarded"] != 2 || h["blocked"] != 1 {
		t.Fatalf("rollover must fold final counts into history[%s]: %+v", yDate, hist[yDate])
	}

	// A later fold for the new day must not touch the old day.
	today := now.Format("2006-01-02")
	recordDailyHistory(today)
	hist = SnapshotRequestsHistory()
	if h := hist[yDate]; h == nil || h["forwarded"] != 2 || h["blocked"] != 1 {
		t.Fatalf("later fold must not overwrite history[%s]: %+v", yDate, hist[yDate])
	}
	if h := hist[today]; h == nil || h["challenged"] != 1 {
		t.Fatalf("post-rollover fold must land on today: %+v", hist[today])
	}
}

// TestFlushFoldKeepsYesterdayFinalCounts exercises the flush critical
// section (foldDailyAndRoll) on the post-midnight path: the pending counts
// belong to yesterday, and the fold-then-roll sequence must preserve them
// on yesterday's history key instead of overwriting it with the post-roll
// (empty) snapshot.
func TestFlushFoldKeepsYesterdayFinalCounts(t *testing.T) {
	resetDaily(t)

	// Freeze "now" once (see TestRecordDailyHistoryFoldsAndPrunes).
	now := time.Now()
	DailyReqInc("a.local", "forwarded")
	DailyReqInc("a.local", "challenged")
	yDate := now.AddDate(0, 0, -1).Format("2006-01-02")
	dailyDay.Store(localDayKey(now.AddDate(0, 0, -1)))

	foldDailyAndRoll()

	hist := SnapshotRequestsHistory()
	if h := hist[yDate]; h == nil || h["forwarded"] != 1 || h["challenged"] != 1 {
		t.Fatalf("flush must keep yesterday's final counts in history[%s]: %+v", yDate, hist[yDate])
	}
	// The rollover advanced the day key to the fold-time day: the frozen
	// "now" day, or the next day when local midnight crossed inside
	// foldDailyAndRoll's own clock reads.
	if d := dailyDay.Load(); d != localDayKey(now) && d != localDayKey(time.Now()) {
		t.Fatalf("day key not advanced: %d", d)
	}
	if m := SnapshotDailyRequestsBySite(); len(m) != 0 {
		t.Fatalf("live counters must be reset after the rollover: %+v", m)
	}
}

// TestRequestsHistoryPersist verifies the flush writes the history file and
// LoadRequestsHistory restores it.
func TestRequestsHistoryPersist(t *testing.T) {
	ResetDailyForTest()
	t.Cleanup(ResetDailyForTest)

	now0 := time.Now() // before the counters are armed: the fold lands on the inc-day
	dir := t.TempDir()
	DailyReqInc("a.local", "forwarded")
	DailyReqInc("a.local", "challenged")

	ctx, cancel := context.WithCancel(context.Background())
	histPath := filepath.Join(dir, "requests_history.json")
	done := make(chan struct{})
	go func() {
		StartDailyRequestsPersist(ctx, filepath.Join(dir, "requests_daily.json"), histPath, time.Hour)
		close(done)
	}()
	// The first flush runs synchronously at startup; give it a moment.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(histPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	b, err := os.ReadFile(histPath)
	if err != nil {
		t.Fatalf("history file missing: %v", err)
	}
	var onDisk map[string]map[string]int64
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatal(err)
	}
	// The fold lands on the day the increments happened (the stored day key
	// survives a midnight crossing inside the flush); after the flush the
	// only other legal key is the crossed-into day.
	today := now0.Format("2006-01-02")
	todayAfter := time.Now().Format("2006-01-02")
	h := onDisk[today]
	if h == nil && todayAfter != today {
		h = onDisk[todayAfter]
	}
	if h == nil || h["forwarded"] != 1 || h["challenged"] != 1 {
		t.Fatalf("persisted history wrong (keys %s/%s): %+v", today, todayAfter, onDisk)
	}

	// A fresh process restores it from disk.
	ResetDailyForTest()
	LoadRequestsHistory(histPath)
	hist := SnapshotRequestsHistory()
	rh := hist[today]
	if rh == nil && todayAfter != today {
		rh = hist[todayAfter]
	}
	if rh == nil || rh["forwarded"] != 1 || rh["challenged"] != 1 {
		t.Fatalf("restored history wrong (keys %s/%s): %+v", today, todayAfter, hist)
	}
}
