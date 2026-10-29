// Package metrics holds the KingMoat data-plane counters and observability
// gauges as plain in-process atomics (no Prometheus client dependency):
// consumers are the console API (/api/stats, /api/host/stats) and the
// anomaly-alert engine. Hot-path Inc is lock-free for existing label keys.
package metrics

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// counterVec is a tiny labeled counter: existing label combinations are
// incremented with a single atomic add; new combinations take the write lock
// once to create their cell.
type counterVec struct {
	mu   sync.RWMutex
	vals map[string]*atomic.Uint64
}

func (c *counterVec) cell(key string) *atomic.Uint64 {
	c.mu.RLock()
	if v, ok := c.vals[key]; ok {
		c.mu.RUnlock()
		return v
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.vals[key]; ok {
		return v
	}
	if c.vals == nil {
		c.vals = map[string]*atomic.Uint64{}
	}
	v := &atomic.Uint64{}
	c.vals[key] = v
	return v
}

func (c *counterVec) Inc(labels ...string) {
	c.cell(strings.Join(labels, "\x00")).Add(1)
}

// Add adds n units to the cell for the given labels (no-op for n == 0, so
// zero-delta callers do not create cells).
func (c *counterVec) Add(n uint64, labels ...string) {
	if n == 0 {
		return
	}
	c.cell(strings.Join(labels, "\x00")).Add(n)
}

// resetAll drops every live counter cell (daily rollover). Increments that
// raced the reset may add into a discarded cell and are lost, matching the
// accepted at-boundary drift of the other counters.
func (c *counterVec) resetAll() {
	c.mu.Lock()
	c.vals = nil
	c.mu.Unlock()
}

// Sum returns the total across all label combinations.
func (c *counterVec) Sum() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var sum uint64
	for _, v := range c.vals {
		sum += v.Load()
	}
	return float64(sum)
}

// Snapshot returns every label combination with its count.
func (c *counterVec) Snapshot() map[string]uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]uint64, len(c.vals))
	for k, v := range c.vals {
		out[k] = v.Load()
	}
	return out
}

// gauge stores a float64 in an atomic uint64 (bit pattern); Set is called by
// slow background pollers only.
type gauge struct {
	bits atomic.Uint64
}

func (g *gauge) Set(v float64) { g.bits.Store(math.Float64bits(v)) }
func (g *gauge) Get() float64  { return math.Float64frombits(g.bits.Load()) }

// Data-plane request counters.
var (
	RequestsTotal    = &counterVec{} // labels: site, outcome
	StageHits        = &counterVec{} // labels: stage
	UpstreamErrors   = &counterVec{} // labels: site
	Reloads          = &counterVec{} // labels: outcome
	BotRequestsTotal = &counterVec{} // labels: site, class
	BotDeniedTotal   = &counterVec{} // labels: site
	BotChallengedTotal = &counterVec{} // labels: site
	BodyBypassTotal    = &counterVec{} // labels: site, policy (bypass|prefix)
	BodyGuardRejected  = &counterVec{} // labels: site
	BodyIdleAborts     = &counterVec{} // labels: site
)

// Observability gauges (set by the 15s poller in the entrypoint).
var (
	AuditDropped          gauge
	AuditQueueDepth       gauge
	AccessLogDropped      gauge
	AccessLogQueueDepth   gauge
	AccessLocalDropped    gauge
	AccessLocalQueueDepth gauge
	LogShipperDropped     gauge
	LogShipperQueueDepth  gauge
)

// SnapshotRequests sums RequestsTotal by outcome label (forwarded / blocked /
// challenged / redirected / monitor_forwarded) for the console dashboard.
// The result INCLUDES the persisted base loaded by LoadRequestsBase, so the
// dashboard's cumulative counters survive process restarts.
func SnapshotRequests() map[string]int64 {
	live := map[string]int64{}
	for key, v := range RequestsTotal.Snapshot() {
		parts := strings.Split(key, "\x00")
		outcome := parts[len(parts)-1]
		live[outcome] += int64(v)
	}
	reqBaseMu.RLock()
	defer reqBaseMu.RUnlock()
	if len(reqBase) == 0 {
		return live
	}
	out := make(map[string]int64, len(live)+len(reqBase))
	for k, v := range reqBase {
		out[k] += v
	}
	for k, v := range live {
		out[k] += v
	}
	return out
}

// Persisted cumulative request counters: the live in-process counters reset
// on restart, so the dashboard's cumulative card would drop to zero. The
// base is loaded from a small JSON state file at boot and re-flushed
// periodically (base + live), making the displayed total monotonic across
// restarts (at most one persist-interval of hard-kill loss).
var (
	reqBaseMu    sync.RWMutex
	reqBase      map[string]int64
	reqStatePath string
)

// LoadRequestsBase loads the persisted cumulative counters as the display
// baseline. Missing/corrupt file = fresh start (no base). Keys prefixed
// "site_bytes|" are legacy debris from a now-removed shared-file layout:
// they are ignored entirely (never request outcomes, not a byte baseline
// either — the byte counters restart from zero on such an upgrade) so a
// rollback-contaminated main file can neither pollute the request base nor
// resurrect byte state. The byte counters restore from their dedicated
// site-bytes-state.json (same directory) instead, independently of the
// main file's presence; see bytes.go.
func LoadRequestsBase(path string) {
	if path == "" {
		// Same guard as StartRequestsPersist: an empty path means "no
		// request-baseline persistence configured" — a relative-path fallback
		// would silently seed state from CWD debris (review G-9).
		return
	}
	reqStatePath = path
	loadBytesStateFile(siteBytesStatePathFor(path))
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var m map[string]int64
	if json.Unmarshal(b, &m) != nil || len(m) == 0 {
		return
	}
	req := make(map[string]int64, len(m))
	for k, v := range m {
		if strings.HasPrefix(k, siteBytesStatePrefix) {
			continue // legacy byte key: ignored, never a request outcome
		}
		req[k] = v
	}
	reqBaseMu.Lock()
	reqBase = req
	reqBaseMu.Unlock()
}

// StartRequestsPersist flushes base+live to the state file every interval
// and once on shutdown, until ctx is cancelled. The same loop (interval and
// flush call) also writes the cumulative site-byte counters to their
// dedicated byte-state file next to it (pure "site_bytes|..." keys; the
// main file stays request-only so a rollback to an older build cannot
// ingest byte entries as request outcomes), keeping both families monotonic
// across restarts.
func StartRequestsPersist(ctx context.Context, path string, interval time.Duration) {
	if path == "" {
		return
	}
	reqStatePath = path
	bytesPath := siteBytesStatePathFor(path)
	flush := func() {
		m := SnapshotRequests()
		b, err := json.Marshal(m)
		if err != nil {
			return
		}
		tmp := path + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, path)
		}
		bb, err := json.Marshal(siteBytesStateEntries(SnapshotSiteBytesCumulative()))
		if err != nil {
			return
		}
		btmp := bytesPath + ".tmp"
		if os.WriteFile(btmp, bb, 0o600) == nil {
			_ = os.Rename(btmp, bytesPath)
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

// The per-day counter series (requests, site bytes) and their shared
// machinery live in daily.go (dailySeries); the site byte counters and
// their exported surface in bytes.go.

// SortedKeys returns the counter's label keys in stable order (tests/debug).
func (c *counterVec) SortedKeys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	keys := make([]string, 0, len(c.vals))
	for k := range c.vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
