package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// TestAuditEventCarriesGeoCountry pins the write-path enrichment: audit
// events resolved from the request's client IP carry geo_country from the
// embedded DB-IP database — a public origin gets its ISO code, a private
// origin and a public origin without a database record both get the
// deterministic empty value (same source as the /api/stats/geo TOP5).
func TestAuditEventCarriesGeoCountry(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()

	store := &captureStore{}
	h, err := New(proxyConfig(trimScheme(up.URL)), pipeline.New(fixedStage{name: "waf", v: pipeline.Deny("waf/test", "blocked by test")}), store, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		remoteAddr string
		wantCC     string
		wantIP     string
	}{
		{"8.8.8.8:1234", "US", "8.8.8.8"},       // public, resolvable
		{"10.20.30.40:9999", "", "10.20.30.40"}, // private (RFC1918)
		{"127.0.0.1:8888", "", "127.0.0.1"},     // loopback
		{"192.0.2.1:1234", "", "192.0.2.1"},     // public, no record (TEST-NET-1)
		{"totally-bogus", "", "totally-bogus"},  // unparseable peer address
	}
	for i, tc := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.RemoteAddr = tc.remoteAddr
		h.ServeHTTP(rec, req)

		events := store.snapshot()
		if len(events) != i+1 {
			t.Fatalf("remote %s: audit events = %d, want %d", tc.remoteAddr, len(events), i+1)
		}
		ev := events[len(events)-1]
		if ev.Action != "blocked" || ev.Rule != "waf/test" {
			t.Fatalf("remote %s: unexpected event %+v", tc.remoteAddr, ev)
		}
		if ev.ClientIP != tc.wantIP {
			t.Fatalf("remote %s: ClientIP = %q, want %q", tc.remoteAddr, ev.ClientIP, tc.wantIP)
		}
		if ev.GeoCountry != tc.wantCC {
			t.Fatalf("remote %s: GeoCountry = %q, want %q", tc.remoteAddr, ev.GeoCountry, tc.wantCC)
		}
	}
}
