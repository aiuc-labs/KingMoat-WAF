package stages

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/kingmoat/kingmoat/internal/geoip"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// TestGeoStagePublishesGeoCountry pins the same-source audit enrichment:
// every successful geo lookup publishes the resolved country (empty string
// included) as rc.Values["geo_country"], so the audit write path can reuse
// THIS result instead of re-resolving through another database.
func TestGeoStagePublishesGeoCountry(t *testing.T) {
	if !geoip.Available() {
		t.Skip("embedded geoip unavailable in test environment")
	}
	g, err := NewGeo(geoCfg("", nil, nil), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	cases := []struct {
		remote        string
		want          string
		wantPublished bool
	}{
		{"9.9.9.9:1234", "US", true},   // public, resolvable
		{"203.0.113.7:9999", "", true}, // public, no record (terminal "")
		{"10.20.30.40:1234", "", true}, // private (mmdb carries no record)
		// Unparseable peer: clientIP() yields nil, the stage allows before any
		// lookup and publishes nothing — the proxy audit path then resolves
		// through its own fallback (geoip.LookupCountryWith -> "").
		{"totally-bogus:1", "", false},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "http://t.local/", nil)
		r.RemoteAddr = tc.remote
		rc := &pipeline.RequestContext{
			Request: r,
			Site:    pipeline.SiteView{Domain: "t.local"},
			Values:  map[string]any{},
		}
		if v := g.Inspect(context.Background(), rc); v.Action != pipeline.ActionAllow {
			t.Fatalf("remote %s: blacklist-miss request must allow: %+v", tc.remote, v)
		}
		got, ok := rc.Values["geo_country"].(string)
		if ok != tc.wantPublished {
			t.Fatalf("remote %s: published = %v, want %v", tc.remote, ok, tc.wantPublished)
		}
		if ok && got != tc.want {
			t.Fatalf("remote %s: geo_country = %q, want %q", tc.remote, got, tc.want)
		}
	}
}

// TestReaderForDomain pins the shared-reader accessor: mapped domains return
// the exact reader the stage uses for lookups (case-insensitive, trimmed),
// unmapped domains return nil so the audit path falls back correctly.
func TestReaderForDomain(t *testing.T) {
	if !geoip.Available() {
		t.Skip("embedded geoip unavailable in test environment")
	}
	g, err := NewGeo(geoCfg("", nil, nil), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	if g.byDomain["t.local"].db == nil {
		t.Fatal("geo site must carry a reader")
	}
	if got := g.ReaderForDomain("t.local"); got != g.byDomain["t.local"].db {
		t.Fatal("ReaderForDomain must return the exact per-site reader instance")
	}
	if got := g.ReaderForDomain("T.LOCAL"); got == nil {
		t.Fatal("domain matching must stay case-insensitive")
	}
	if got := g.ReaderForDomain("  t.local  "); got == nil {
		t.Fatal("domain matching must tolerate surrounding blanks")
	}
	if got := g.ReaderForDomain("other.local"); got != nil {
		t.Fatalf("unmapped domain must return nil, got %v", got)
	}
}
