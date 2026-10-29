// Generalized per-day counter machinery shared by the request series and
// the site-byte series: a live labeled counter that resets at local
// midnight, a persisted same-day baseline restored at boot (the state file
// carries the calendar date, so a restart only restores counts that belong
// to today) and a per-day history map with retention pruning (dashboard
// time-range cards).
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// dailyFileState is the persisted per-day state file shape.
type dailyFileState struct {
	Date   string           `json:"date"`
	Counts map[string]int64 `json:"counts"`
}

// dailyReqState keeps the historical name of dailyFileState.
type dailyReqState = dailyFileState

// dailySeries is the reusable per-day counter machinery. foldKey maps a
// live-counter key onto its history sub-key: the request series folds
// site\x00outcome onto the bare outcome, the byte series keeps the full
// site\x00direction key so per-site range aggregation survives the fold.
//
// The storage fields are pointers: the request series wires the
// package-level variables below (existing tests reach into those bare
// identifiers directly), while the byte series owns private storage built
// by newDailySeries.
type dailySeries struct {
	live    *counterVec
	foldKey func(key string) (sub string, ok bool)

	day   *atomic.Int64 // local calendar day of the live counters, encoded as YYYYMMDD
	dayMu *sync.Mutex

	baseMu *sync.RWMutex
	base   *map[string]int64

	historyMu *sync.RWMutex
	history   *map[string]map[string]int64
}

// newDailySeries builds a series that owns its own storage.
func newDailySeries(live *counterVec, foldKey func(string) (string, bool)) *dailySeries {
	s := &dailySeries{live: live, foldKey: foldKey}
	s.day = new(atomic.Int64)
	s.dayMu = new(sync.Mutex)
	s.baseMu = new(sync.RWMutex)
	s.historyMu = new(sync.RWMutex)
	base := map[string]int64{}
	s.base = &base
	hist := map[string]map[string]int64{}
	s.history = &hist
	return s
}

// localDayKey encodes a time's local calendar date as a comparable number
// (e.g. 20260923) so the hot path compares ints instead of formatting date
// strings per request.
func localDayKey(t time.Time) int64 {
	return int64(t.Year())*10000 + int64(t.Month())*100 + int64(t.Day())
}

// dayKeyString renders the YYYYMMDD day encoding as a date string.
func dayKeyString(cur int64) string {
	return fmt.Sprintf("%04d-%02d-%02d", cur/10000, (cur/100)%100, cur%100)
}

// dailyHistoryRetention caps the per-day history (days kept); 35 covers the
// widest dashboard range (30) plus headroom.
const dailyHistoryRetention = 35

// roll resets the live counters when the local calendar day has changed
// (first request or first persistence flush after local midnight). The
// unchanged-day path stays lock-free.
func (s *dailySeries) roll() {
	day := localDayKey(time.Now())
	if s.day.Load() == day {
		return
	}
	s.dayMu.Lock()
	defer s.dayMu.Unlock()
	s.rollLocked(day)
}

// rollLocked performs the rollover with dayMu held: the final counts are
// folded into the previous day's history key before the live counters are
// dropped, so a request-side rollover no longer loses the last flush
// interval, and the fold cannot interleave with a concurrent flush's
// history-key selection (overwrite semantics make repeated folds idempotent).
func (s *dailySeries) rollLocked(day int64) {
	if s.day.Load() == day {
		return
	}
	if cur := s.day.Load(); cur != 0 {
		s.recordHistoryLocked(dayKeyString(cur))
	}
	s.live.resetAll()
	// The recovered baseline belongs to the previous day once the clock
	// crossed midnight; drop it along with the live counters.
	s.baseMu.Lock()
	*s.base = nil
	s.baseMu.Unlock()
	s.day.Store(day)
}

// inc counts one unit under the pre-joined label key.
func (s *dailySeries) inc(key string) {
	s.roll()
	s.live.cell(key).Add(1)
}

// add counts n units under the pre-joined label key (no-op for n == 0 so
// idle requests do not create counter cells).
func (s *dailySeries) add(key string, n uint64) {
	if n == 0 {
		return
	}
	s.roll()
	s.live.cell(key).Add(n)
}

// recordHistory folds the current counters (baseline+live) into
// history[dayKey] via foldKey and prunes days older than the retention
// window. The dayMu round-trip keeps the standalone form safe for tests and
// future callers; the flush path uses recordHistoryLocked under its own
// dayMu hold.
func (s *dailySeries) recordHistory(dayKey string) {
	s.dayMu.Lock()
	defer s.dayMu.Unlock()
	s.recordHistoryLocked(dayKey)
}

// recordHistoryLocked is recordHistory for callers already holding dayMu:
// the counter read and the history overwrite must stay atomic relative to
// rollLocked, or a midnight reset in between would be folded as an empty
// snapshot over the previous day's history.
func (s *dailySeries) recordHistoryLocked(dayKey string) {
	sums := map[string]int64{}
	s.baseMu.RLock()
	for k, v := range *s.base {
		if sub, ok := s.foldKey(k); ok {
			sums[sub] += v
		}
	}
	s.baseMu.RUnlock()
	for k, v := range s.live.Snapshot() {
		if sub, ok := s.foldKey(k); ok {
			sums[sub] += int64(v)
		}
	}
	s.historyMu.Lock()
	(*s.history)[dayKey] = sums
	cutoff := time.Now().AddDate(0, 0, -dailyHistoryRetention).Format("2006-01-02")
	for d := range *s.history {
		if d < cutoff {
			delete(*s.history, d)
		}
	}
	s.historyMu.Unlock()
}

// foldAndRoll folds the live counters into the per-day history and rolls
// the day forward as one critical section under dayMu: right after local
// midnight the pending counts belong to the previous day and must land on
// that date, and the history-key selection and the counter read must not
// interleave with a concurrent rollover — a reset in between would make the
// fold overwrite the previous day's history with zeros.
func (s *dailySeries) foldAndRoll() {
	s.dayMu.Lock()
	defer s.dayMu.Unlock()
	histKey := time.Now().Format("2006-01-02")
	if cur := s.day.Load(); cur != 0 && cur != localDayKey(time.Now()) {
		histKey = dayKeyString(cur)
	}
	s.recordHistoryLocked(histKey)
	s.rollLocked(localDayKey(time.Now()))
}

// loadBase loads the persisted daily counters as the baseline, but only
// when the state file belongs to today (local time); a file from a previous
// day is discarded so "today" never mixes in stale counts.
func (s *dailySeries) loadBase(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var st dailyFileState
	if json.Unmarshal(b, &st) != nil || len(st.Counts) == 0 {
		return
	}
	if st.Date != time.Now().Format("2006-01-02") {
		return
	}
	s.baseMu.Lock()
	*s.base = st.Counts
	s.baseMu.Unlock()
	// Arm the day key so the first request does not trigger a rollover
	// that would immediately wipe the just-restored baseline.
	s.day.Store(localDayKey(time.Now()))
}

// loadHistory loads persisted per-day totals (JSON map of date → sub-key →
// count).
func (s *dailySeries) loadHistory(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var hist map[string]map[string]int64
	if json.Unmarshal(b, &hist) != nil || len(hist) == 0 {
		return
	}
	s.historyMu.Lock()
	*s.history = hist
	s.historyMu.Unlock()
}

// historySnapshot returns a copy of the per-day history.
func (s *dailySeries) historySnapshot() map[string]map[string]int64 {
	s.historyMu.RLock()
	defer s.historyMu.RUnlock()
	out := make(map[string]map[string]int64, len(*s.history))
	for d, m := range *s.history {
		cp := make(map[string]int64, len(m))
		for k, v := range m {
			cp[k] = v
		}
		out[d] = cp
	}
	return out
}

// startPersist flushes baseline+live counters to the state file every
// interval and once on shutdown, until ctx is cancelled. When historyPath
// is non-empty the same flush also folds the counters into the per-day
// history (dashboard time-range cards).
func (s *dailySeries) startPersist(ctx context.Context, dailyPath, historyPath string, interval time.Duration) {
	if dailyPath == "" {
		return
	}
	flush := func() {
		s.foldAndRoll()
		st := dailyFileState{Date: time.Now().Format("2006-01-02"), Counts: map[string]int64{}}
		s.baseMu.RLock()
		for k, v := range *s.base {
			st.Counts[k] += v
		}
		s.baseMu.RUnlock()
		for k, v := range s.live.Snapshot() {
			st.Counts[k] += int64(v)
		}
		b, err := json.Marshal(st)
		if err != nil {
			return
		}
		tmp := dailyPath + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, dailyPath)
		}
		if historyPath != "" {
			if hb, err := json.Marshal(s.historySnapshot()); err == nil {
				htmp := historyPath + ".tmp"
				if os.WriteFile(htmp, hb, 0o600) == nil {
					_ = os.Rename(htmp, historyPath)
				}
			}
		}
	}
	flush()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-t.C:
			flush()
		}
	}
}

// resetForTest clears the series' live counters, baseline, day key and
// history (test hook).
func (s *dailySeries) resetForTest() {
	s.live.resetAll()
	s.baseMu.Lock()
	*s.base = nil
	s.baseMu.Unlock()
	s.day.Store(0)
	s.historyMu.Lock()
	*s.history = map[string]map[string]int64{}
	s.historyMu.Unlock()
}

// ===== request series =====

// Daily per-site request counters feed /api/stats/per-site ("requests
// today" per site). Unlike RequestsTotal these reset at local midnight and
// persist per day: the state file carries the calendar date, so a restart
// only restores counts that belong to today.
var (
	DailyRequestsTotal = &counterVec{} // labels: site, outcome
	dailyDay           atomic.Int64    // local calendar day of the live counters, encoded as YYYYMMDD
	dailyDayMu         sync.Mutex
	dailyBaseMu        sync.RWMutex
	dailyBase          map[string]int64

	dailyHistoryMu sync.RWMutex
	dailyHistory   = map[string]map[string]int64{} // date → outcome → count
)

// foldOutcome maps a site\x00outcome counter key onto the bare outcome for
// the per-day request history (per-site granularity is not needed there).
func foldOutcome(key string) (string, bool) {
	parts := strings.SplitN(key, "\x00", 2)
	if len(parts) != 2 {
		return "", false
	}
	return parts[1], true
}

// reqDaily is the request series; its storage stays in the package-level
// variables above (existing tests reach into them directly) and is wired in
// by pointer.
var reqDaily = &dailySeries{
	live:    DailyRequestsTotal,
	foldKey: foldOutcome,
	day:     &dailyDay, dayMu: &dailyDayMu,
	baseMu: &dailyBaseMu, base: &dailyBase,
	historyMu: &dailyHistoryMu, history: &dailyHistory,
}

// DailyReqInc counts one request for the per-site "today" card.
func DailyReqInc(site, outcome string) {
	reqDaily.inc(site + "\x00" + outcome)
}

// LoadDailyRequestsBase loads the persisted daily counters as the baseline,
// but only when the state file belongs to today (local time); a file from a
// previous day is discarded so "today" never mixes in stale counts.
func LoadDailyRequestsBase(path string) { reqDaily.loadBase(path) }

// StartDailyRequestsPersist flushes baseline+live daily counters to the
// state file every interval and once on shutdown, until ctx is cancelled.
// When historyPath is non-empty the same flush also folds the counters into
// the per-day request history (dashboard time-range cards).
func StartDailyRequestsPersist(ctx context.Context, dailyPath, historyPath string, interval time.Duration) {
	reqDaily.startPersist(ctx, dailyPath, historyPath, interval)
}

// recordDailyHistory folds the current daily request counters into
// history[dayKey] (kept as a package-level helper for existing tests).
func recordDailyHistory(dayKey string) { reqDaily.recordHistory(dayKey) }

// foldDailyAndRoll is the request series' flush critical section (kept as a
// package-level helper for existing tests).
func foldDailyAndRoll() { reqDaily.foldAndRoll() }

// LoadRequestsHistory loads persisted per-day request totals (JSON map of
// date → outcome → count).
func LoadRequestsHistory(path string) { reqDaily.loadHistory(path) }

// SnapshotRequestsHistory returns a copy of the per-day request history.
func SnapshotRequestsHistory() map[string]map[string]int64 { return reqDaily.historySnapshot() }

// SnapshotDailyRequestsBySite sums the persisted baseline and the live daily
// counters per site label (all outcomes), for /api/stats/per-site. Empty
// site labels (no_site rows) are kept here; the API merge step filters them.
func SnapshotDailyRequestsBySite() map[string]int64 {
	out := map[string]int64{}
	for key, v := range DailyRequestsTotal.Snapshot() {
		site := strings.SplitN(key, "\x00", 2)[0]
		out[site] += int64(v)
	}
	dailyBaseMu.RLock()
	defer dailyBaseMu.RUnlock()
	for key, v := range dailyBase {
		site := strings.SplitN(key, "\x00", 2)[0]
		out[site] += v
	}
	return out
}

// ResetDailyForTest clears the shared daily-counter state (request AND byte
// series: live counters, persisted-day baselines and per-day histories), the
// cumulative byte counter and its persisted baseline (also process-global
// test state). Test hook for consumer packages that share these
// process-global counters; pair with t.Cleanup.
func ResetDailyForTest() {
	reqDaily.resetForTest()
	bytesDaily.resetForTest()
	BytesTotal.resetAll()
	bytesBaseMu.Lock()
	bytesBase = nil
	bytesBaseMu.Unlock()
}
