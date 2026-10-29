// Site transferred-byte counters: per-site payload bytes for the dashboard
// traffic panel (a dailySeries with the same midnight rollover, same-day
// baseline persistence and 35-day history as the request counters) plus a
// cumulative Prometheus family.
package metrics

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Byte counters. DailyBytesTotal feeds the per-day series (rolls at local
// midnight, persisted like the request counters); BytesTotal is the
// cumulative process-lifetime counter for the Prometheus exposition.
var (
	DailyBytesTotal = &counterVec{} // labels: site, direction (down/up)
	BytesTotal      = &counterVec{} // labels: site, direction (down/up)
)

// Byte count directions: down = response bytes sent to the client, up =
// request-body bytes received from the client.
const (
	BytesDirDown = "down"
	BytesDirUp   = "up"
)

// foldSiteDir keeps the full site\x00direction key in the per-day bytes
// history so per-site range aggregation survives the fold.
func foldSiteDir(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	return key, true
}

// bytesDaily is the byte series (own storage, same machinery as requests).
var bytesDaily = newDailySeries(DailyBytesTotal, foldSiteDir)

// SiteBytesInc adds one request's transferred bytes to the daily per-site
// series and the cumulative counter: down = response bytes written to the
// client (proxied body or intercept/challenge page), up = request-body bytes
// read from the client (inspection reads + forwarded copy of the remainder).
// Zero deltas are skipped so body-less requests do not create counter
// cells. The empty site label (no_site rows) is kept like DailyReqInc; the
// API merge step filters it.
func SiteBytesInc(site string, down, up int64) {
	if down > 0 {
		bytesDaily.add(site+"\x00"+BytesDirDown, uint64(down))
		BytesTotal.Add(uint64(down), site, BytesDirDown)
	}
	if up > 0 {
		bytesDaily.add(site+"\x00"+BytesDirUp, uint64(up))
		BytesTotal.Add(uint64(up), site, BytesDirUp)
	}
}

// LoadBytesBase loads the persisted daily byte counters as the baseline
// (only a state file dated today is restored, like the request counters).
func LoadBytesBase(path string) { bytesDaily.loadBase(path) }

// LoadBytesHistory loads the persisted per-day byte history (date →
// site\x00direction → bytes).
func LoadBytesHistory(path string) { bytesDaily.loadHistory(path) }

// StartBytesPersist flushes baseline+live daily byte counters to the state
// file every interval and once on shutdown; historyPath folds them into the
// per-day history (dashboard traffic-panel time ranges).
func StartBytesPersist(ctx context.Context, dailyPath, historyPath string, interval time.Duration) {
	bytesDaily.startPersist(ctx, dailyPath, historyPath, interval)
}

// BytesPair is one series' transferred bytes: Down = response bytes sent to
// the client, Up = request-body bytes received from the client.
type BytesPair struct {
	Down int64 `json:"down"`
	Up   int64 `json:"up"`
}

// SnapshotDailyBytesBySite returns per-site down/up byte totals for today
// (persisted baseline + live counters), for /api/stats. Empty site labels
// (no_site rows) are kept here; the API merge step filters them.
func SnapshotDailyBytesBySite() map[string]BytesPair {
	out := map[string]BytesPair{}
	collect := func(key string, v int64) {
		parts := strings.SplitN(key, "\x00", 2)
		if len(parts) != 2 {
			return
		}
		p := out[parts[0]]
		switch parts[1] {
		case BytesDirDown:
			p.Down += v
		case BytesDirUp:
			p.Up += v
		default:
			return
		}
		out[parts[0]] = p
	}
	for key, v := range DailyBytesTotal.Snapshot() {
		collect(key, int64(v))
	}
	bytesDaily.baseMu.RLock()
	for key, v := range *bytesDaily.base {
		collect(key, v)
	}
	bytesDaily.baseMu.RUnlock()
	return out
}

// SnapshotBytesHistory returns a copy of the per-day byte history (date →
// site\x00direction → bytes).
func SnapshotBytesHistory() map[string]map[string]int64 { return bytesDaily.historySnapshot() }

// ===== cumulative site-byte persistence (dedicated site-bytes-state.json) =====

// The cumulative Prometheus counter (BytesTotal) is process-lifetime state,
// so like the cumulative request counters it is restored at boot and
// re-flushed by the shared 30s persist loop (LoadRequestsBase /
// StartRequestsPersist). Unlike the request counters, byte entries are kept
// in a DEDICATED state file (site-bytes-state.json, same directory,
// permissions and flush cadence as metrics-state.json): the main state file
// stays a pure request-key map, so rolling back to a build that predates the
// byte counters cannot even see this data — and therefore cannot ingest the
// entries as request outcomes and write them back (S-15). The keys inside
// the byte file keep the flat "site_bytes|<site>|<direction>" encoding
// (site labels are hostnames, never contain '|'); malformed keys are
// dropped on load and never leak into the request outcome base.
const siteBytesStateFile = "site-bytes-state.json"

// siteBytesStatePathFor derives the dedicated byte-state file path from the
// shared request state path (same directory, fixed name) so callers keep
// passing a single path.
func siteBytesStatePathFor(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), siteBytesStateFile)
}

// loadBytesStateFile restores the cumulative byte baseline from the
// dedicated byte-state file. Missing/corrupt file = fresh start (no base),
// mirroring LoadRequestsBase's tolerance; malformed keys are dropped.
func loadBytesStateFile(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var m map[string]int64
	if json.Unmarshal(b, &m) != nil || len(m) == 0 {
		return
	}
	entries := map[string]int64{}
	for k, v := range m {
		if site, dir, ok := parseSiteBytesStateKey(k); ok {
			entries[site+"\x00"+dir] += v
		}
	}
	storeBytesBase(entries)
}

const siteBytesStatePrefix = "site_bytes|"

// siteBytesStateKey encodes one site+direction cumulative total as a flat
// state-file key.
func siteBytesStateKey(site, dir string) string {
	return siteBytesStatePrefix + site + "|" + dir
}

// parseSiteBytesStateKey decodes a key written by siteBytesStateKey; ok is
// false for every other key (request outcomes and malformed byte keys).
func parseSiteBytesStateKey(key string) (site, dir string, ok bool) {
	rest, found := strings.CutPrefix(key, siteBytesStatePrefix)
	if !found {
		return "", "", false
	}
	site, dir, found = strings.Cut(rest, "|")
	if !found {
		return "", "", false
	}
	return site, dir, true
}

// Cumulative site-byte baseline restored from the shared state file
// (internal keys: site\x00direction), merged with the live BytesTotal cells
// by SnapshotSiteBytesCumulative so the Prometheus exposition and the state
// flush both see the restored totals.
var (
	bytesBaseMu sync.RWMutex
	bytesBase   map[string]int64
)

// storeBytesBase replaces the cumulative byte baseline (boot-time restore
// from the shared state file; replace semantics, mirroring the request base
// reload).
func storeBytesBase(entries map[string]int64) {
	bytesBaseMu.Lock()
	bytesBase = entries
	bytesBaseMu.Unlock()
}

// SnapshotSiteBytesCumulative returns the cumulative per-site byte counters
// (persisted baseline + live process counters) in the exposition label-key
// shape (site\x00direction) of kingmoat_site_bytes_total.
func SnapshotSiteBytesCumulative() map[string]uint64 {
	out := map[string]uint64{}
	bytesBaseMu.RLock()
	for k, v := range bytesBase {
		if v > 0 { // a non-positive baseline is corrupt data, not history
			out[k] += uint64(v)
		}
	}
	bytesBaseMu.RUnlock()
	for k, v := range BytesTotal.Snapshot() {
		out[k] += v
	}
	return out
}

// siteBytesStateEntries maps a cumulative snapshot onto the flat state-file
// keys ("site_bytes|site|direction") for the dedicated byte-state file flush.
func siteBytesStateEntries(cum map[string]uint64) map[string]int64 {
	out := make(map[string]int64, len(cum))
	for k, v := range cum {
		parts := strings.SplitN(k, "\x00", 2)
		if len(parts) != 2 {
			continue
		}
		out[siteBytesStateKey(parts[0], parts[1])] = int64(v)
	}
	return out
}
