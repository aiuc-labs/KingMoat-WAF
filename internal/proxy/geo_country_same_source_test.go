package proxy

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/geoip"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// customGeoDB materializes the embedded country database as a standalone
// file so a site geo.db_path opens a real custom reader (same fixture trick
// as buildstate_leak_test.go). Values match the embedded DB, so every
// same-source assertion below compares against geoip lookups of the SAME
// database bytes.
func customGeoDB(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "geoip", "dbip-country-lite.mmdb"))
	if err != nil {
		t.Fatalf("read embedded geo db: %v", err)
	}
	p := filepath.Join(t.TempDir(), "geo.mmdb")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatalf("write fixture db: %v", err)
	}
	return p
}

// geoSameSourceCfg builds one geo site with a custom db (blacklisting the
// unreachable "ZZ" so verdicts stay deterministic) and one plain site.
func geoSameSourceCfg(dbPath, upstream string) *config.Config {
	return &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{
			{
				Domains:  []string{"t.local"},
				Mode:     "intercept",
				Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: upstream}}},
				Security: &config.SecuritySettings{
					Geo: &config.GeoSettings{Enabled: true, DBPath: dbPath, Blacklist: []string{"US"}},
				},
			},
			{
				Domains:  []string{"plain.local"},
				Mode:     "intercept",
				Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: upstream}}},
			},
		},
	}
}

// TestGeoBlockedAuditCarriesSiteDBCountry is the end-to-end same-source
// regression: an attack blocked BY the geo stage on a custom-db site records
// geo_country from the geo stage's own per-request lookup (rc.Values), i.e.
// the exact value the blocking decision used — not a second resolution
// through the embedded database.
func TestGeoBlockedAuditCarriesSiteDBCountry(t *testing.T) {
	if !geoip.Available() {
		t.Skip("embedded geoip unavailable in test environment")
	}
	dbPath := customGeoDB(t)
	store := &captureStore{}
	h, err := NewReloadable(geoSameSourceCfg(dbPath, "127.0.0.1:9"), store, testLogger())
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}
	st := h.state.Load()
	if st.geo == nil {
		t.Fatal("reloadable build must expose the geo engine on planeState")
	}
	if st.geo.ReaderForDomain("t.local") == nil {
		t.Fatal("custom-db site must have a site reader")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://t.local/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("US client must be geo-blacklisted, status = %d", rec.Code)
	}
	events := store.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Rule != "geo/blacklist" {
		t.Fatalf("rule = %q, want geo/blacklist", ev.Rule)
	}
	if ev.GeoCountry != "US" {
		t.Fatalf("GeoCountry = %q, want US (same source as the geo deny)", ev.GeoCountry)
	}
}

// TestGeoCountryFallbackPriority pins the audit resolution order:
//  1. rc.Values["geo_country"] (geo stage result, empty string is terminal)
//  2. the site geo engine's reader (requests that never reached the stage)
//  3. the embedded database (non-geo sites / static mode / no site)
func TestGeoCountryFallbackPriority(t *testing.T) {
	if !geoip.Available() {
		t.Skip("embedded geoip unavailable in test environment")
	}
	dbPath := customGeoDB(t)
	h, err := NewReloadable(geoSameSourceCfg(dbPath, "127.0.0.1:9"), &captureStore{}, testLogger())
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}
	st := h.state.Load()

	// Priority 1: the geo stage's published result wins verbatim, "" included.
	rc := &pipeline.RequestContext{Values: map[string]any{"geo_country": "ZZ"}}
	if got := h.geoCountry(st, "t.local", "8.8.8.8", rc); got != "ZZ" {
		t.Fatalf("rc result must win: got %q, want ZZ", got)
	}
	rcEmpty := &pipeline.RequestContext{Values: map[string]any{"geo_country": ""}}
	if got := h.geoCountry(st, "t.local", "8.8.8.8", rcEmpty); got != "" {
		t.Fatalf("empty rc result is terminal: got %q, want \"\"", got)
	}

	// Priority 2: site geo engine reader for requests that never reached the
	// stage (rc == nil) — value must equal a lookup through the SAME reader.
	siteReader := st.geo.ReaderForDomain("t.local")
	if siteReader == nil {
		t.Fatal("site reader missing")
	}
	if got := h.geoCountry(st, "t.local", "8.8.8.8", nil); got != geoip.LookupCountryWith(siteReader, "8.8.8.8") {
		t.Fatalf("fallback must resolve through the site reader: got %q", got)
	}
	// Case-insensitive domain: newEvent passes firstDomain() verbatim.
	if got := h.geoCountry(st, "T.LOCAL", "8.8.8.8", nil); got != "US" {
		t.Fatalf("case-insensitive site match broken: got %q, want US", got)
	}
	// Empty-string semantics preserved on the fallback path too.
	for _, ip := range []string{"10.20.30.40", "203.0.113.7", "bogus", ""} {
		if got := h.geoCountry(st, "t.local", ip, nil); got != "" {
			t.Fatalf("geoCountry(%q) = %q, want \"\"", ip, got)
		}
	}

	// Priority 3: non-geo sites fall back to the embedded database — exactly
	// the pre-existing behavior (ReaderForDomain returns nil there).
	if st.geo.ReaderForDomain("plain.local") != nil {
		t.Fatal("plain site must not map into the geo engine")
	}
	if got := h.geoCountry(st, "plain.local", "8.8.8.8", nil); got != geoip.LookupCountry("8.8.8.8") {
		t.Fatalf("non-geo site must fall back to the embedded db: got %q", got)
	}
	if got := h.geoCountry(st, "", "8.8.8.8", nil); got != geoip.LookupCountry("8.8.8.8") {
		t.Fatalf("no-site events must fall back to the embedded db: got %q", got)
	}
}

// TestGeoCountryStaticModeUnchanged pins the static/test-mode contract: a
// handler built via New has no geo engine (state.geo == nil) and every event
// resolves through the embedded database — byte-for-byte the pre-change
// behavior.
func TestGeoCountryStaticModeUnchanged(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()

	h, err := New(proxyConfig(trimScheme(up.URL)), pipeline.New(fixedStage{name: "waf", v: pipeline.Deny("waf/test", "blocked by test")}), &captureStore{}, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h.state.Load().geo != nil {
		t.Fatal("static mode must not carry a geo engine")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	h.ServeHTTP(rec, req)
	store := h.audit.(*captureStore)
	events := store.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if events[0].GeoCountry != geoip.LookupCountry("8.8.8.8") {
		t.Fatalf("static mode GeoCountry = %q, want the embedded-db value %q", events[0].GeoCountry, geoip.LookupCountry("8.8.8.8"))
	}
}

// TestGeoCountryConcurrentResolution interleaves the three resolution paths
// under concurrency (no data races, stable values). Run with -count=20; the
// machine has no cgo so -race is unavailable — repeated interleaving is the
// race screen here.
func TestGeoCountryConcurrentResolution(t *testing.T) {
	if !geoip.Available() {
		t.Skip("embedded geoip unavailable in test environment")
	}
	dbPath := customGeoDB(t)
	h, err := NewReloadable(geoSameSourceCfg(dbPath, "127.0.0.1:9"), &captureStore{}, testLogger())
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}
	st := h.state.Load()
	embeddedUS := geoip.LookupCountry("8.8.8.8")

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rcHit := &pipeline.RequestContext{Values: map[string]any{"geo_country": "ZZ"}}
			rcEmpty := &pipeline.RequestContext{Values: map[string]any{}}
			for i := 0; i < 200; i++ {
				switch (g + i) % 5 {
				case 0:
					if got := h.geoCountry(st, "t.local", "8.8.8.8", rcHit); got != "ZZ" {
						t.Errorf("concurrent rc hit drifted: %q", got)
						return
					}
				case 1:
					if got := h.geoCountry(st, "t.local", "8.8.8.8", rcEmpty); got != "US" {
						t.Errorf("concurrent site-reader path drifted: %q", got)
						return
					}
				case 2:
					if got := h.geoCountry(st, "plain.local", "8.8.8.8", nil); got != embeddedUS {
						t.Errorf("concurrent embedded fallback drifted: %q", got)
						return
					}
				case 3:
					if got := h.geoCountry(st, "t.local", "10.20.30.40", nil); got != "" {
						t.Errorf("concurrent private-origin drifted: %q", got)
						return
					}
				case 4:
					if got := h.geoCountry(st, "t.local", "203.0.113.7", rcEmpty); got != "" {
						t.Errorf("concurrent no-record drifted: %q", got)
						return
					}
				}
			}
		}(g)
	}
	wg.Wait()
}
