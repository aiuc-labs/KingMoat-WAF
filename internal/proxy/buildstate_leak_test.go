package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/ipgroups"
	"github.com/kingmoat/kingmoat/internal/stages"
)

// leakTestUpstream starts the minimal upstream the test configs forward to.
func leakTestUpstream(t *testing.T) string {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)
	return strings.TrimPrefix(up.URL, "http://")
}

// copyTestMMDB copies the repo's embedded country database into a fresh temp
// file so a custom geo db_path opens a REAL closable handle (the empty-path
// embedded singleton is intentionally never closed by Geo.Close).
func copyTestMMDB(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "geoip", "dbip-country-lite.mmdb"))
	if err != nil {
		t.Fatalf("read embedded mmdb fixture: %v", err)
	}
	p := filepath.Join(t.TempDir(), "geo.mmdb")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatalf("write mmdb copy: %v", err)
	}
	return p
}

// sweeperProbe is the stack-frame fragment every RateLimit sweeper goroutine
// shows in a runtime.Stack(all=true) dump (stages.(*RateLimit).sweeper).
// The `created by stages.NewRateLimit` line never matches it, and no other
// frame in this module can, so each live sweeper contributes at least one
// match (a sweeper mid-eviction contributes two: the sweeper frame and its
// sweeper.func1 closure frame — counting is therefore a lower bound, which
// is all the assertions below rely on).
const sweeperProbe = "RateLimit).sweeper"

// sweeperStackDump takes one full-process stack snapshot. The buffer is
// deliberately generous: runtime.Stack truncates to the buffer and the tail
// of the dump holds the most recently created goroutines — exactly where the
// sweeper under observation sits — so an undersized buffer would silently
// under-count (weaker assertion, never a false failure).
func sweeperStackDump() []byte {
	buf := make([]byte, 4<<20)
	n := runtime.Stack(buf, true)
	return buf[:n]
}

// countSweepers reports how many sweeper frames the current dump shows.
// A sweeper blocked in select — the steady state of both a LEAKED sweeper
// and a healthy between-ticks one — is always dumped with its frames; the
// only under-counting window is _Grunning at the stop-the-world instant of
// the dump itself ("goroutine running on other thread; stack unavailable"),
// which is transient. Counting can therefore be momentarily low, never
// wrongly high, and callers poll instead of trusting a single sample.
func countSweepers() int {
	return strings.Count(string(sweeperStackDump()), sweeperProbe)
}

// waitForSweeperUp polls until the live sweeper count reaches want
// (baseline+1: one rl per config here) or fails. NewRateLimit only executes
// `go rl.sweeper(...)`; when the new goroutine first becomes visible in a
// dump is scheduling-dependent, so the previous one-shot existence check
// flaked under load (measured 0.3% miss rate idle, 0.6% under 8-process CPU
// pressure: at the dump's stop-the-world instant a just-started goroutine
// can be _Grunning and prints no frames). Polling keeps the probe honest —
// a build that never started the sweeper still fails here — while a merely
// slow-to-schedule one no longer fails spuriously.
func waitForSweeperUp(t *testing.T, want int, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if countSweepers() >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: RateLimit sweeper goroutine never became visible (want >= %d): rate-limited site did not start the sweeper (probe would be vacuous)", what, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// assertSweeperGone polls until the live sweeper count returns to baseline
// (the count observed before this test built anything) or times out.
//
// Why this still catches the original defect: the sweeper exits ONLY via
// RateLimit.Close (select on rl.stop), and buildState registers rl as a
// closer exactly so every mid-build failure runs state.close(). If
// buildState regressed to leaking the rl handle, the freshly built sweeper
// would stay blocked in select FOREVER — permanently visible to every dump
// — this count would never return to baseline, and the assertion below
// would fail. The long deadline only trades failure latency for timing
// robustness (a just-closed sweeper needs one scheduling slot to actually
// exit; starving it for 15s under full-suite load is implausible), never
// detection power.
//
// Why baseline-scoped instead of "zero alive": other tests in this binary
// (reload/transport/... hot-swaps into rate-limited configs) legitimately
// leave their final states un-closed, and those sweepers stay alive for the
// rest of the process — a process-global zero assertion false-fails on them
// deterministically from the second `go test -count=N` iteration on.
// Comparing against the pre-test baseline isolates THIS test's handles; a
// leak of our rl pushes the count to baseline+1 and keeps it there.
func assertSweeperGone(t *testing.T, baseline int, what string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if countSweepers() <= baseline {
			return
		}
		if time.Now().After(deadline) {
			got := countSweepers()
			t.Fatalf("%s: %d RateLimit sweeper goroutine(s) still alive above baseline %d after 15s — buildState leaked the rl handle; live sweepers:\n%s",
				what, got-baseline, baseline, sweeperEvidence())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// sweeperEvidence extracts a few (goroutine header + matching frame) pairs
// from a fresh dump so a failure names the goroutine that kept the count up.
func sweeperEvidence() string {
	lines := strings.Split(string(sweeperStackDump()), "\n")
	var out []string
	for i := 1; i < len(lines) && len(out) < 10; i++ {
		if strings.Contains(lines[i], sweeperProbe) {
			out = append(out, "    "+strings.TrimSpace(lines[i-1]), "    "+strings.TrimSpace(lines[i]))
		}
	}
	if len(out) == 0 {
		return "    (no matching frames in a fresh dump — sweeper exited between count and evidence dump)"
	}
	return strings.Join(out, "\n")
}

// assertMMDBUnlocked fails while the mmdb file cannot be deleted: on Windows
// a mapped (open) mmdb handle blocks deletion, so deletability proves the
// geo handle was closed by the failed build (skipped on other GOOSes, where
// the rl goroutine probe carries the leak proof).
func assertMMDBUnlocked(t *testing.T, path, what string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := os.Remove(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: geo mmdb %s still locked — buildState leaked the geo handle", what, path)
}

// leakTestCfg builds a config whose site carries RateLimit (starts the
// sweeper goroutine) and a custom geo db (opens a closable mmdb handle).
func leakTestCfg(upstream, mmdbPath string) *config.Config {
	cfg := reloadTestCfg(upstream, true)
	cfg.Sites[0].Security.Geo = &config.GeoSettings{
		Enabled:   true,
		DBPath:    mmdbPath,
		Blacklist: []string{"ZZ"}, // never matches: keeps NewGeo behavior deterministic
	}
	return cfg
}

// TestBuildStateFailureClosesStagedHandles is the C10 regression: every
// mid-build failure after geo/rl were built must run state.close() so no
// handle leaks. Two failure shapes are covered — the direct-return branches
// (respFilter) and the state.close() branches (matcher) — plus the success
// path registration completeness.
//
// Leak evidence uses poll-until-steady counts over full stack dumps against
// a pre-test baseline, never a one-shot goroutine existence check: under
// full-suite CPU contention a single dump can miss a just-started (still
// _Grunning) goroutine, while a leaked one is permanently visible.
func TestBuildStateFailureClosesStagedHandles(t *testing.T) {
	up := leakTestUpstream(t)
	logger := testLogger()

	// Baseline: sweeper goroutines left alive by OTHER tests of this binary.
	// They are legitimately (if untidily) immortal — RateLimit.Close is the
	// only exit — so the assertions below compare against this number instead
	// of demanding a zero process-global count.
	baseline := countSweepers()

	// Success path: geo and rl must be registered as closers the moment they
	// are built, and closing the state really stops the rl sweeper.
	mmdb := copyTestMMDB(t)
	groups := ipgroups.NewManager(leakTestCfg(up, mmdb), logger)
	defer groups.Close()
	st, err := buildState(leakTestCfg(up, mmdb), 1, groups, nil, logger, nil, nil)
	if err != nil {
		t.Fatalf("clean buildState failed: %v", err)
	}
	var hasGeo, hasRL bool
	for _, c := range st.closers {
		switch c.(type) {
		case *stages.Geo:
			hasGeo = true
		case *stages.RateLimit:
			hasRL = true
		}
	}
	if !hasGeo || !hasRL {
		t.Fatalf("success-path closers must contain geo and rl (geo=%v rl=%v)", hasGeo, hasRL)
	}
	waitForSweeperUp(t, baseline+1, "success-path build")
	st.close() // idempotent for rl; releases the success-path handles
	assertSweeperGone(t, baseline, "success-path state.close()")

	// Failure shape 1: respFilter preset error — a direct-return branch.
	mmdb = copyTestMMDB(t)
	cfg := leakTestCfg(up, mmdb)
	cfg.Sites[0].Security.RespFilter = &config.RespFilterSettings{
		Enabled: true,
		Presets: []string{"no-such-preset"},
	}
	groups2 := ipgroups.NewManager(cfg, logger)
	defer groups2.Close()
	if _, err := buildState(cfg, 2, groups2, nil, logger, nil, nil); err == nil {
		t.Fatal("unknown respfilter preset must fail the build")
	}
	assertSweeperGone(t, baseline, "respFilter-failure path")
	assertMMDBUnlocked(t, mmdb, "respFilter-failure path")

	// Failure shape 2: matcher regex compile error — a state.close() branch.
	mmdb = copyTestMMDB(t)
	cfg = leakTestCfg(up, mmdb)
	cfg.Policy = &config.Policy{Matchers: []config.MatcherRule{{
		Name:    "bad-regex",
		Enabled: true,
		Action:  "deny",
		Conditions: []config.MatcherCondition{{
			Field: "path",
			Op:    config.OpRegex,
			Value: "(unbalanced",
		}},
	}}}
	groups3 := ipgroups.NewManager(cfg, logger)
	defer groups3.Close()
	if _, err := buildState(cfg, 3, groups3, nil, logger, nil, nil); err == nil {
		t.Fatal("invalid matcher regex must fail the build")
	}
	assertSweeperGone(t, baseline, "matcher-failure path")
	assertMMDBUnlocked(t, mmdb, "matcher-failure path")
}
