package proxy

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/metrics"
)

// TestProxyCountsTransferredBytes drives body-carrying POSTs through the
// full proxy (body buffering → inspection → forward) and asserts the
// per-site byte counters increase by exactly the payload sizes: up counts
// the request body once (the forwarded copy reads the rewound buffer, not
// the client stream), down counts the upstream response body. A blocked
// request counts its request body (read during inspection) and the
// deny-page bytes written to the client — byte counting is independent of
// the access-log switch (no sink wired in this test).
func TestProxyCountsTransferredBytes(t *testing.T) {
	metrics.ResetDailyForTest()
	t.Cleanup(metrics.ResetDailyForTest)

	const upPayload = "up-payload-0123456789"         // 20 bytes
	const downPayload = "down-payload-9876543210-xyz" // 32 bytes
	up := v3up(t, downPayload)
	defer up.Close()
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF:      wafOff(),
			Security: &config.SecuritySettings{Semantic: &config.SemanticSettings{Enabled: true}},
		}},
	}
	h, err := NewReloadable(cfg, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	snap := func() [2]int64 {
		p := metrics.SnapshotDailyBytesBySite()["t.local"]
		return [2]int64{p.Down, p.Up}
	}
	before := snap()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://t.local/upload", strings.NewReader(upPayload))
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("forward failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != downPayload {
		t.Fatalf("upstream body lost: %q", rec.Body.String())
	}
	afterFwd := snap()
	if d := afterFwd[0] - before[0]; d != int64(len(downPayload)) {
		t.Fatalf("down bytes = %d, want exactly %d", d, len(downPayload))
	}
	if d := afterFwd[1] - before[1]; d != int64(len(upPayload)) {
		t.Fatalf("up bytes = %d, want exactly %d (buffered read only)", d, len(upPayload))
	}

	beforeBlock := snap()
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", `http://t.local/p?id=1%27%20or%20%271%27=%271`, strings.NewReader(upPayload))
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 403 {
		t.Fatalf("expected block, got %d", rec2.Code)
	}
	afterBlock := snap()
	if d := afterBlock[0] - beforeBlock[0]; d <= 0 {
		t.Fatalf("blocked request must count the deny-page response bytes, got %d", d)
	}
	if d := afterBlock[1] - beforeBlock[1]; d != int64(len(upPayload)) {
		t.Fatalf("blocked request up bytes = %d, want exactly %d (body read during inspection)", d, len(upPayload))
	}

	// The cumulative Prometheus counter mirrors the daily increments.
	snap2 := metrics.BytesTotal.Snapshot()
	if snap2["t.local\x00down"] < uint64(len(downPayload)) || snap2["t.local\x00up"] != uint64(2*len(upPayload)) {
		t.Fatalf("cumulative bytes wrong: %+v", snap2)
	}
}
