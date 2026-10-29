package metrics

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// resetBytesShared clears the shared daily-counter state (request AND byte
// series) before the test and registers the cleanup for after it.
func resetBytesShared(t *testing.T) {
	t.Helper()
	ResetDailyForTest()
	t.Cleanup(ResetDailyForTest)
}

// TestSiteBytesIncAndSnapshot verifies the per-site byte increments (down =
// response, up = request body), the empty-site row for no_site traffic and
// the mirror into the cumulative Prometheus counter.
func TestSiteBytesIncAndSnapshot(t *testing.T) {
	resetBytesShared(t)
	SiteBytesInc("a.local", 100, 50)
	SiteBytesInc("a.local", 30, 0) // down only
	SiteBytesInc("b.local", 0, 7)  // up only
	SiteBytesInc("", 5, 5)         // no_site rows keep the empty label

	m := SnapshotDailyBytesBySite()
	if m["a.local"].Down != 130 || m["a.local"].Up != 50 {
		t.Fatalf("a.local wrong: %+v", m["a.local"])
	}
	if m["b.local"].Down != 0 || m["b.local"].Up != 7 {
		t.Fatalf("b.local wrong: %+v", m["b.local"])
	}
	if p, ok := m[""]; !ok || p.Down != 5 || p.Up != 5 {
		t.Fatalf("empty-site row missing: %+v", m)
	}
	snap := BytesTotal.Snapshot()
	if snap["a.local\x00down"] != 130 || snap["a.local\x00up"] != 50 {
		t.Fatalf("cumulative bytes wrong: %+v", snap)
	}
	if _, ok := snap["a.local\x00down\x00junk"]; ok {
		t.Fatalf("unexpected label combination: %+v", snap)
	}
}

// TestDailyBytesRollover verifies the local-midnight rollover: the live byte
// counters (and the recovered baseline) are wiped while the pending counts
// land on the previous day's history key, keeping per-site granularity.
func TestDailyBytesRollover(t *testing.T) {
	resetBytesShared(t)
	SiteBytesInc("a.local", 100, 50)
	// Simulate a date change: the live counters now belong to yesterday.
	bytesDaily.day.Store(localDayKey(time.Now().AddDate(0, 0, -1)))
	SiteBytesInc("b.local", 10, 3)

	m := SnapshotDailyBytesBySite()
	if m["a.local"].Down != 0 || m["a.local"].Up != 0 {
		t.Fatalf("rollover must wipe the live byte counters: %+v", m)
	}
	if m["b.local"].Down != 10 || m["b.local"].Up != 3 {
		t.Fatalf("post-rollover b.local wrong: %+v", m["b.local"])
	}
	yDate := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	hist := SnapshotBytesHistory()
	if h := hist[yDate]; h == nil || h["a.local\x00down"] != 100 || h["a.local\x00up"] != 50 {
		t.Fatalf("rollover must fold bytes into history[%s] per site: %+v", yDate, hist[yDate])
	}
	// The cumulative counter is NOT part of the daily roll.
	if snap := BytesTotal.Snapshot(); snap["a.local\x00down"] != 100 {
		t.Fatalf("cumulative bytes must survive the daily roll: %+v", snap)
	}
}

// TestLoadBytesBaseDateGate verifies that only a state file dated today is
// restored as the byte baseline; a stale file is discarded so "today" never
// mixes in previous-day counts.
func TestLoadBytesBaseDateGate(t *testing.T) {
	resetBytesShared(t)
	dir := t.TempDir()
	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	write := func(name, date string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		b, err := json.Marshal(dailyFileState{Date: date, Counts: map[string]int64{"a.local\x00down": 100}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	LoadBytesBase(write("today.json", today))
	if m := SnapshotDailyBytesBySite(); m["a.local"].Down != 100 {
		t.Fatalf("today's byte base not restored: %+v", m)
	}

	resetBytesShared(t)
	LoadBytesBase(write("stale.json", yesterday))
	if m := SnapshotDailyBytesBySite(); len(m) != 0 {
		t.Fatalf("stale byte base must be discarded: %+v", m)
	}
}

// TestBytesHistoryFoldAndPrune verifies the flush fold: bytes keep the
// site\x00direction sub-keys, the pending counts land on the previous day
// after midnight and days beyond the retention window are pruned.
func TestBytesHistoryFoldAndPrune(t *testing.T) {
	resetBytesShared(t)
	now := time.Now()
	SiteBytesInc("a.local", 100, 50)
	SiteBytesInc("b.local", 0, 7)

	// Simulate the post-midnight flush: the pending counters belong to
	// yesterday's day key.
	yKey := localDayKey(now.AddDate(0, 0, -1))
	bytesDaily.day.Store(yKey)
	bytesDaily.recordHistory(dayKeyString(yKey))

	yDate := now.AddDate(0, 0, -1).Format("2006-01-02")
	hist := SnapshotBytesHistory()
	if h := hist[yDate]; h == nil || h["a.local\x00down"] != 100 || h["b.local\x00up"] != 7 {
		t.Fatalf("bytes fold must keep per-site keys: %+v", hist[yDate])
	}

	// A day beyond retention is pruned on the next fold.
	old := now.AddDate(0, 0, -(dailyHistoryRetention + 5)).Format("2006-01-02")
	bytesDaily.historyMu.Lock()
	(*bytesDaily.history)[old] = map[string]int64{"a.local\x00down": 9}
	bytesDaily.historyMu.Unlock()
	today := now.Format("2006-01-02")
	bytesDaily.recordHistory(today)
	hist = SnapshotBytesHistory()
	if _, ok := hist[old]; ok {
		t.Fatalf("stale byte day survived pruning: %+v", hist)
	}
	if h := hist[today]; h == nil || h["a.local\x00down"] != 100 || h["a.local\x00up"] != 50 {
		t.Fatalf("today bytes fold wrong: %+v", hist[today])
	}
}

// TestBytesPersist verifies the flush loop: baseline+live merge into the
// daily state file with today's date (a same-day restart carries the byte
// counts forward) and the history file carries the same per-site fold.
func TestBytesPersist(t *testing.T) {
	resetBytesShared(t)
	dir := t.TempDir()
	dailyPath := filepath.Join(dir, "bytes_daily.json")
	histPath := filepath.Join(dir, "bytes_history.json")
	today := time.Now().Format("2006-01-02")
	b, err := json.Marshal(dailyFileState{Date: today, Counts: map[string]int64{"a.local\x00down": 70}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dailyPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	LoadBytesBase(dailyPath)
	SiteBytesInc("a.local", 10, 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		StartBytesPersist(ctx, dailyPath, histPath, 50*time.Millisecond)
		close(done)
	}()
	time.Sleep(200 * time.Millisecond)

	raw, err := os.ReadFile(dailyPath)
	if err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	var st dailyFileState
	if err := json.Unmarshal(raw, &st); err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	cancel()
	<-done
	if st.Date != today {
		t.Fatalf("persisted date = %q, want %q", st.Date, today)
	}
	if got := st.Counts["a.local\x00down"]; got != 80 {
		t.Fatalf("persisted bytes = %d, want 80 (base 70 + live 10)", got)
	}
	hb, err := os.ReadFile(histPath)
	if err != nil {
		t.Fatal(err)
	}
	var hist map[string]map[string]int64
	if err := json.Unmarshal(hb, &hist); err != nil {
		t.Fatal(err)
	}
	if h := hist[today]; h == nil || h["a.local\x00down"] != 80 {
		t.Fatalf("persisted byte history wrong: %+v", hist[today])
	}
}
