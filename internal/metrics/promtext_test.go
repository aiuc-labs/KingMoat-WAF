package metrics

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// promtextSeq disambiguates the label across -count=N re-runs in one
// process: the run-scoped timestamp alone could repeat on a coarse clock,
// the atomic suffix makes every call unique.
var promtextSeq atomic.Uint64

func TestPrometheusText(t *testing.T) {
	// RequestsTotal is a process-global counter and PrometheusText renders
	// it as-is, so an exact-value assertion on a fixed label ("site-a")
	// only holds for the first run in a process: with -count>=2 the cells
	// accumulate (2 -> 4 -> 6) and the assertion explodes (the old flake).
	// A per-call unique site keeps the exact-value semantics deterministic.
	//
	// Regression guard: if this is ever reverted to fixed labels, -count=2
	// fails again (the fixed-label line turns 4); and if the renderer ever
	// drops a label, misorders site/outcome or renders a wrong value, the
	// exact-line matches below fail in every single run.
	site := fmt.Sprintf("site-%d-%d", time.Now().UnixNano(), promtextSeq.Add(1))
	RequestsTotal.Inc(site, "blocked")
	RequestsTotal.Inc(site, "blocked")
	RequestsTotal.Inc(site, "forwarded")
	// AuditDropped is a gauge set absolutely (not incremented), so its
	// rendered value is deterministic even across -count=N re-runs; no
	// other test in this package touches it.
	AuditDropped.Set(3)
	out := PrometheusText("v-test")
	for _, want := range []string{
		"kingmoat_build_info{version=\"v-test\"} 1",
		"kingmoat_requests_total{site=\"" + site + "\",outcome=\"blocked\"} 2",
		"kingmoat_requests_total{site=\"" + site + "\",outcome=\"forwarded\"} 1",
		"kingmoat_audit_dropped_total 3",
		"# TYPE kingmoat_requests_total counter",
		"go_goroutines",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("prometheus text missing %q\n%s", want, out)
		}
	}
}