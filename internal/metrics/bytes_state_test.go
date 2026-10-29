package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// resetCumBytesShared clears the shared cumulative-byte state (live counter,
// persisted baseline and both daily series) before the test and registers
// the cleanup for after it.
func resetCumBytesShared(t *testing.T) {
	t.Helper()
	ResetDailyForTest()
	t.Cleanup(ResetDailyForTest)
}

// TestSiteBytesStatePersistReload covers the byte-counter persistence round
// trip AND the rollback-safe upgrade path (S-15): a legacy main file that
// still carries flat "site_bytes|..." keys (shared-file layout of the wip
// builds) is loaded with the byte keys ignored entirely — they must neither
// pollute the request base nor restore a byte baseline — while live traffic
// and the shared persist loop move the byte counters into the dedicated
// site-bytes-state.json. After a flush the main file is pure request keys
// (an older build reading it cannot even see byte data), and a "new
// process" reload restores the byte baseline from the dedicated file.
func TestSiteBytesStatePersistReload(t *testing.T) {
	resetCumBytesShared(t)
	path := filepath.Join(t.TempDir(), "metrics-state.json")
	// The dedicated byte file is derived from the main state path by the
	// production code itself — assert against that same derivation.
	bytesPath := siteBytesStatePathFor(path)

	// Legacy (rollback-contaminated) main file: request outcomes plus byte
	// keys from the pre-split layout. The request base must come through,
	// the byte keys must be dropped on the floor.
	seed := `{"forwarded":100,"blocked":7,"site_bytes|seed.local|down":500,"site_bytes|seed.local|up":60}`
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadRequestsBase(path)

	// Request base restored untouched by the byte keys; byte baseline stays
	// zero (legacy byte keys are ignored, not migrated).
	if m := SnapshotRequests(); m["forwarded"] < 100 || m["blocked"] < 7 {
		t.Fatalf("request base not restored: %+v", m)
	}
	if cum := SnapshotSiteBytesCumulative(); len(cum) != 0 {
		t.Fatalf("legacy main-file byte keys must not restore a byte baseline: %+v", cum)
	}

	// Live traffic adds on top of the (empty) restored baseline.
	SiteBytesInc("seed.local", 11, 7)

	// Same writer/persist loop as the request counters now flushes the byte
	// family into the dedicated file (same waiting discipline as the request
	// test: cancel() alone does not retire the goroutine or its shutdown
	// flush).
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() {
		cancel()
		<-done
	}()
	go func() {
		defer close(done)
		StartRequestsPersist(ctx, path, 50*time.Millisecond)
	}()
	time.Sleep(200 * time.Millisecond)

	// Main file after the flush: flat request-key map, ZERO site_bytes keys.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]int64
	if err := json.Unmarshal(b, &persisted); err != nil {
		t.Fatalf("main state file left the flat-number shape (old builds would reject it): %v", err)
	}
	for k := range persisted {
		if strings.HasPrefix(k, siteBytesStatePrefix) {
			t.Fatalf("main state file must not carry byte keys after a flush, found %q (old builds would ingest it as a request outcome)", k)
		}
	}
	if persisted["forwarded"] < 100 || persisted["blocked"] < 7 {
		t.Fatalf("persisted state lost request counters: %+v", persisted)
	}

	// Dedicated byte file: the flat byte entries landed there.
	bb, err := os.ReadFile(bytesPath)
	if err != nil {
		t.Fatalf("dedicated byte state file missing after flush: %v", err)
	}
	var bytePersisted map[string]int64
	if err := json.Unmarshal(bb, &bytePersisted); err != nil {
		t.Fatalf("byte state file must stay a flat number map: %v", err)
	}
	if bytePersisted["site_bytes|seed.local|down"] < 11 || bytePersisted["site_bytes|seed.local|up"] < 7 {
		t.Fatalf("byte state file lost byte counters: %+v", bytePersisted)
	}
	cancel()
	<-done

	// Reload in a "new process": the byte baseline comes back from the
	// dedicated file and the cumulative view (and with it the Prometheus
	// counter) stays monotonic; the request base carries forward too.
	LoadRequestsBase(path)
	cum2 := SnapshotSiteBytesCumulative()
	if cum2["seed.local\x00down"] < uint64(bytePersisted["site_bytes|seed.local|down"]) ||
		cum2["seed.local\x00up"] < uint64(bytePersisted["site_bytes|seed.local|up"]) {
		t.Fatalf("reload dropped byte counters: %+v", cum2)
	}
	if m := SnapshotRequests(); m["forwarded"] < persisted["forwarded"] {
		t.Fatalf("reload dropped request counters: %+v", m)
	}

	// The exposition renders the restored totals (baseline + live).
	out := PrometheusText("v-test")
	line := ""
	prefix := `kingmoat_site_bytes_total{site="seed.local",direction="down"} `
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, prefix) {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("exposition missing restored byte line %q\n%s", prefix, out)
	}
	var got int64
	if _, err := fmt.Sscanf(line, prefix+"%d", &got); err != nil {
		t.Fatalf("bad exposition line %q: %v", line, err)
	}
	if got < bytePersisted["site_bytes|seed.local|down"] {
		t.Fatalf("exposition value %d < persisted %d", got, bytePersisted["site_bytes|seed.local|down"])
	}
}

// TestSiteBytesStateLegacyFile verifies the backward-compatible direction: a
// state file written before the byte persistence (no site_bytes keys)
// restores only the request baseline while the byte view starts at the live
// counters (missing key = zero).
func TestSiteBytesStateLegacyFile(t *testing.T) {
	resetCumBytesShared(t)
	path := filepath.Join(t.TempDir(), "metrics-state.json")
	if err := os.WriteFile(path, []byte(`{"forwarded":42,"blocked":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadRequestsBase(path)

	if m := SnapshotRequests(); m["forwarded"] < 42 || m["blocked"] < 3 {
		t.Fatalf("legacy request base not restored: %+v", m)
	}
	if cum := SnapshotSiteBytesCumulative(); len(cum) != 0 {
		t.Fatalf("legacy file must not restore a byte baseline: %+v", cum)
	}
	SiteBytesInc("legacy.local", 5, 0)
	if cum := SnapshotSiteBytesCumulative(); cum["legacy.local\x00down"] != 5 {
		t.Fatalf("live bytes must still count with a legacy file: %+v", cum)
	}
}

// TestSiteBytesStateMalformedKeys verifies load-time tolerance on the main
// file: byte-prefixed keys — malformed or not — are ignored entirely. They
// must neither poison the request outcome base as pseudo-outcomes nor
// restore a byte baseline (the dedicated byte file is the only byte source).
func TestSiteBytesStateMalformedKeys(t *testing.T) {
	resetCumBytesShared(t)
	path := filepath.Join(t.TempDir(), "metrics-state.json")
	if err := os.WriteFile(path, []byte(`{"forwarded":1,"site_bytes|nosite":9,"site_bytes||down":4}`), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadRequestsBase(path)

	if m := SnapshotRequests(); m["forwarded"] < 1 {
		t.Fatalf("request base not restored with legacy byte keys present: %+v", m)
	}
	if cum := SnapshotSiteBytesCumulative(); len(cum) != 0 {
		t.Fatalf("main-file byte keys (malformed or not) must not restore a byte baseline: %+v", cum)
	}
}

// TestSiteBytesStateDedicatedFileMalformed covers the dedicated byte file's
// own load tolerance: malformed keys are dropped, valid keys round-trip, and
// a corrupt file is a fresh start — never an error.
func TestSiteBytesStateDedicatedFileMalformed(t *testing.T) {
	resetCumBytesShared(t)
	path := filepath.Join(t.TempDir(), "metrics-state.json")
	bytesPath := siteBytesStatePathFor(path)

	seed := `{"site_bytes|ok.local|down":33,"site_bytes|bad":9,"site_bytes||up":2}`
	if err := os.WriteFile(bytesPath, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadRequestsBase(path)

	cum := SnapshotSiteBytesCumulative()
	if cum["ok.local\x00down"] != 33 {
		t.Fatalf("valid byte key not restored from the dedicated file: %+v", cum)
	}
	// Same key semantics as the old shared-file partition: the empty-site
	// row is a valid site label and must round-trip, while a byte key
	// without a direction part is dropped.
	if cum["\x00up"] != 2 {
		t.Fatalf("empty-site byte row must round-trip: %+v", cum)
	}
	if len(cum) != 2 {
		t.Fatalf("malformed byte keys must be dropped: %+v", cum)
	}
	// Byte-file keys must never surface as request outcomes (live counter
	// keys from other tests may appear here under -count>1, so only the key
	// shape is asserted, not the map size).
	for k := range SnapshotRequests() {
		if strings.HasPrefix(k, siteBytesStatePrefix) {
			t.Fatalf("byte-file key leaked into the request base: %q", k)
		}
	}

	// Corrupt file at a fresh boot (baseline still zero): ignored without
	// error, byte view stays at the live counters — same tolerance as the
	// main request file (LoadRequestsBase never panics on bad JSON).
	ResetDailyForTest()
	if err := os.WriteFile(bytesPath, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadRequestsBase(path)
	if cum := SnapshotSiteBytesCumulative(); len(cum) != 0 {
		t.Fatalf("corrupt byte file must be ignored at a fresh boot: %+v", cum)
	}
}
