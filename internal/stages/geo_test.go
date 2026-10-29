package stages

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/geoip"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

func geoCapture(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func geoCfg(dbPath string, blacklist, whitelist []string) *config.Config {
	return &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9"}}},
			Security: &config.SecuritySettings{
				Geo: &config.GeoSettings{
					Enabled:   true,
					DBPath:    dbPath,
					Blacklist: blacklist,
					Whitelist: whitelist,
				},
			},
		}},
	}
}

func geoRun(t *testing.T, g *Geo, domain string) pipeline.Verdict {
	t.Helper()
	r := httptest.NewRequest("GET", "http://"+domain+"/", nil)
	r.RemoteAddr = "9.9.9.9:1234"
	rc := &pipeline.RequestContext{
		Request: r,
		Site:    pipeline.SiteView{Domain: domain},
		Values:  map[string]any{},
	}
	return g.Inspect(context.Background(), rc)
}

func geoWarnCount(buf *bytes.Buffer) int {
	return strings.Count(buf.String(), "geo: configured but engine missing")
}

// TestGeoEngineMissingWarnRateLimited pins the fail-open guard: a domain the
// config declared geo-enabled but the running engine has no mapping for must
// never pass silently. Requests stay allowed (alerting only, no false
// positives) and the warning is capped at one per domain per interval.
// The desync is unreachable in production builds (byDomain and configured are
// written in the same NewGeo loop), so the test simulates it defensively via
// delete to exercise the sentinel logic itself.
func TestGeoEngineMissingWarnRateLimited(t *testing.T) {
	var buf bytes.Buffer
	g, err := NewGeo(geoCfg("", nil, nil), geoCapture(&buf))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.warnEvery = 50 * time.Millisecond
	delete(g.byDomain, "t.local") // defensive-path simulation: unreachable in production builds, deleted here to exercise the sentinel logic

	for i := 0; i < 5; i++ {
		if v := geoRun(t, g, "t.local"); v.Action != pipeline.ActionAllow {
			t.Fatalf("engine-missing request must not be blocked: %+v", v)
		}
	}
	if n := geoWarnCount(&buf); n != 1 {
		t.Fatalf("warnings within window = %d, want 1\nlog:\n%s", n, buf.String())
	}

	time.Sleep(60 * time.Millisecond)
	geoRun(t, g, "t.local")
	if n := geoWarnCount(&buf); n != 2 {
		t.Fatalf("warnings after window = %d, want 2 (rate limit must be per-window, not once-ever)\nlog:\n%s", n, buf.String())
	}
}

// TestGeoEngineMissingNotWarnedForPlainSites pins the negative half of the
// guard: domains without geo in the config must stay silent (no warning
// noise for the majority of sites).
func TestGeoEngineMissingNotWarnedForPlainSites(t *testing.T) {
	var buf bytes.Buffer
	g, err := NewGeo(geoCfg("", nil, nil), geoCapture(&buf))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	delete(g.byDomain, "t.local")

	if v := geoRun(t, g, "other.local"); v.Action != pipeline.ActionAllow {
		t.Fatalf("non-geo site request must pass: %+v", v)
	}
	if n := geoWarnCount(&buf); n != 0 {
		t.Fatalf("warnings for non-geo site = %d, want 0\nlog:\n%s", n, buf.String())
	}
}

// TestGeoNormalMappingUnaffected is the regression for correctly mapped
// sites: lookups still run, verdicts are unchanged by the guard, domain
// matching stays case-insensitive, and no engine-missing warning fires.
// "ZZ" is not a valid ISO code, so it never matches a lookup result: the
// blacklist case deterministically allows and the whitelist case
// deterministically denies.
func TestGeoNormalMappingUnaffected(t *testing.T) {
	var buf bytes.Buffer
	g, err := NewGeo(geoCfg("", []string{"ZZ"}, nil), geoCapture(&buf))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	if !g.configured["t.local"] || g.byDomain["t.local"] == nil {
		t.Fatal("configured/byDomain must both contain the geo site after build")
	}
	if v := geoRun(t, g, "t.local"); v.Action != pipeline.ActionAllow {
		t.Fatalf("blacklist miss must allow: %+v", v)
	}
	// Case-insensitive domain matching (pre-existing behavior).
	if v := geoRun(t, g, "T.Local"); v.Action != pipeline.ActionAllow {
		t.Fatalf("case-insensitive domain must still map: %+v", v)
	}
	if n := geoWarnCount(&buf); n != 0 {
		t.Fatalf("engine-missing warnings for mapped site = %d, want 0\nlog:\n%s", n, buf.String())
	}

	// Whitelist mode regression: unknown countries denied with the
	// pre-existing rule identifier.
	gw, err := NewGeo(geoCfg("", nil, []string{"ZZ"}), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	v := geoRun(t, gw, "t.local")
	if v.Action != pipeline.ActionDeny || v.Rule != "geo/not_whitelisted" {
		t.Fatalf("whitelist miss must deny with geo/not_whitelisted: %+v", v)
	}
}

// TestGeoEmptyDBPathUsesEmbeddedAndSurvivesClose pins the embedded-database
// contract: an empty db_path builds against the geoip.Reader() singleton and
// keeps working after the engine is closed — a successful hot-reload closes
// the previous engine, and the singleton must survive it (closing it silently
// broke every lookup in the new engine; production-verified).
func TestGeoEmptyDBPathUsesEmbeddedAndSurvivesClose(t *testing.T) {
	g, err := NewGeo(geoCfg("", nil, nil), quiet())
	if err != nil {
		t.Fatalf("empty db_path must build against the embedded database: %v", err)
	}
	if g.byDomain["t.local"].db != geoip.Reader() {
		t.Fatal("empty db_path must use the geoip.Reader() singleton")
	}

	// Simulate the hot-reload swap: previous engine closed, lookup must
	// still work for the next engine built from the same singleton.
	if err := g.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	g2, err := NewGeo(geoCfg("", []string{"ZZ"}, nil), quiet())
	if err != nil {
		t.Fatalf("rebuild after close: %v", err)
	}
	defer g2.Close()
	if v := geoRun(t, g2, "t.local"); v.Action != pipeline.ActionAllow {
		t.Fatalf("lookup after engine close must still work (embedded db closed?): %+v", v)
	}
}

// TestGeoBuildWarnsWhenNoUsableDomains pins the defensive build-time warning:
// a geo-enabled site whose domain list is empty (or blank) can never be
// evaluated and must not stay silent.
func TestGeoBuildWarnsWhenNoUsableDomains(t *testing.T) {
	var buf bytes.Buffer
	cfg := geoCfg("", nil, nil)
	cfg.Sites[0].Domains = []string{"", "   "}
	g, err := NewGeo(cfg, geoCapture(&buf))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	if len(g.byDomain) != 0 {
		t.Fatalf("blank domains must not enter byDomain, got %d", len(g.byDomain))
	}
	if !strings.Contains(buf.String(), "no usable domains") {
		t.Fatalf("build must warn about unusable domains\nlog:\n%s", buf.String())
	}
}

// TestGeoCustomPathMissingFailsStatic is the regression for the pre-existing
// fail-static contract: a configured db_path that cannot be opened fails the
// build instead of degrading silently.
func TestGeoCustomPathMissingFailsStatic(t *testing.T) {
	if _, err := NewGeo(geoCfg(t.TempDir()+`\missing.mmdb`, nil, nil), quiet()); err == nil {
		t.Fatal("missing custom mmdb must fail the build (fail-static)")
	}
}

// geoFixtureDB copies the embedded country database asset (internal/geoip)
// into a temp dir and returns the path, so custom-db_path tests exercise
// NewGeo's file loading against a real, parseable mmdb without any external
// download. Its content is a byte-for-byte copy of what geoip.Reader() uses.
func geoFixtureDB(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "geoip", "dbip-country-lite.mmdb"))
	if err != nil {
		t.Fatalf("read embedded mmdb asset: %v", err)
	}
	path := filepath.Join(t.TempDir(), "custom.mmdb")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatalf("write fixture db: %v", err)
	}
	return path
}

// TestGeoCustomDBSurvivesEngineClose pins the invariant the hot-reload race
// fix depends on: closing an engine must NOT invalidate its reader. A reload
// closes the previous engine (Handler.Reload → old.close) while in-flight
// audit lookups may still resolve through ReaderForDomain →
// LookupCountryWith; an mmap-backed reader unmap'd under a concurrent lookup
// is an unrecoverable fatal fault (the R-1 crash), so after Close the
// reader must keep working from heap-backed data.
func TestGeoCustomDBSurvivesEngineClose(t *testing.T) {
	dbPath := geoFixtureDB(t)

	// Two engines over the same file mirror the reload swap: old and new
	// engine each hold their own reader for the same database.
	g1, err := NewGeo(geoCfg(dbPath, nil, nil), quiet())
	if err != nil {
		t.Fatalf("first engine must build from the custom db: %v", err)
	}
	g2, err := NewGeo(geoCfg(dbPath, nil, nil), quiet())
	if err != nil {
		t.Fatalf("second engine must build from the same custom db: %v", err)
	}
	defer g2.Close()

	// Sanity: the fixture must actually resolve a public IP, so the
	// post-close assertions below are meaningful.
	r := g1.ReaderForDomain("t.local")
	if r == nil {
		t.Fatal("custom db_path must map the site domain to its reader")
	}
	const probeIP = "8.8.8.8"
	if geoip.LookupCountryWith(r, probeIP) == "" {
		t.Fatalf("fixture db must resolve %s to a country (probe failed)", probeIP)
	}

	if err := g1.Close(); err != nil {
		t.Fatalf("close first engine: %v", err)
	}

	// The closed engine's reader must stay fully usable: a direct Lookup
	// must succeed and the audit path's LookupCountryWith must still
	// resolve. With the pre-fix mmap reader this point is a fatal fault.
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := r.Lookup(net.ParseIP(probeIP), &rec); err != nil {
		t.Fatalf("lookup on the closed engine's reader must still work: %v", err)
	}
	if cc := geoip.LookupCountryWith(r, probeIP); cc == "" {
		t.Fatalf("LookupCountryWith on the closed engine's reader must still resolve %s", probeIP)
	}

	// The surviving engine over the same file (the post-swap new engine in
	// production terms) must be unaffected by the neighbor's close.
	if v := geoRun(t, g2, "t.local"); v.Action != pipeline.ActionAllow {
		t.Fatalf("second engine must keep working after the first is closed: %+v", v)
	}
}

// TestGeoCustomDBInspectSemantics pins that a custom db_path builds a fully
// working geo engine with the pre-existing Inspect semantics: a whitelisted
// client country is allowed and an unknown country is denied with the
// established rule identifier — custom databases must follow the exact same
// decision path as the embedded one.
func TestGeoCustomDBInspectSemantics(t *testing.T) {
	dbPath := geoFixtureDB(t)

	// The fixture is a byte-for-byte copy of the embedded database, so the
	// country the embedded reader assigns to geoRun's client IP (9.9.9.9)
	// is exactly what the custom-db engine will resolve — this keeps the
	// whitelist-hit case deterministic across DB-IP monthly builds.
	probe := geoip.LookupCountryWith(geoip.Reader(), "9.9.9.9")
	if probe == "" {
		t.Fatal("embedded database must resolve the probe IP to a country")
	}

	// Whitelist hit: allowed with the pre-existing semantics.
	gHit, err := NewGeo(geoCfg(dbPath, nil, []string{probe}), quiet())
	if err != nil {
		t.Fatalf("custom db_path engine must build: %v", err)
	}
	defer gHit.Close()
	if v := geoRun(t, gHit, "t.local"); v.Action != pipeline.ActionAllow {
		t.Fatalf("whitelisted country must allow: %+v", v)
	}

	// Whitelist miss ("ZZ" is not a valid ISO code, never matches):
	// denied with the established rule identifier, same as embedded.
	gMiss, err := NewGeo(geoCfg(dbPath, nil, []string{"ZZ"}), quiet())
	if err != nil {
		t.Fatalf("custom db_path engine must build: %v", err)
	}
	defer gMiss.Close()
	v := geoRun(t, gMiss, "t.local")
	if v.Action != pipeline.ActionDeny || v.Rule != "geo/not_whitelisted" {
		t.Fatalf("non-whitelisted country must deny with geo/not_whitelisted: %+v", v)
	}
}
