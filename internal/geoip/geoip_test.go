package geoip

import (
	"net"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/apiasset"
)

// TestLookupCountryLocalOrigins pins the boundary contract for origins that
// carry no country: the empty string is the single deterministic value, and
// the console derives the "本地局域网 vs 未知地区" distinction from the IP.
func TestLookupCountryLocalOrigins(t *testing.T) {
	for _, ip := range []string{
		"10.1.2.3",        // RFC1918
		"172.16.5.5",      // RFC1918
		"192.168.1.1",     // RFC1918
		"127.0.0.1",       // IPv4 loopback
		"169.254.1.1",     // IPv4 link-local
		"100.64.0.1",      // CGNAT
		"100.127.255.254", // CGNAT upper bound
		"::1",             // IPv6 loopback
		"fd00::1",         // IPv6 ULA
		"fe80::1",         // IPv6 link-local
	} {
		if got := LookupCountry(ip); got != "" {
			t.Errorf("LookupCountry(%q) = %q, want \"\" (local origin)", ip, got)
		}
	}
}

// TestLookupCountryPublicResolvable pins the happy path: public origins
// resolve to the uppercase ISO 3166-1 alpha-2 code of the embedded DB-IP
// database (values verified against the shipped build).
func TestLookupCountryPublicResolvable(t *testing.T) {
	for ip, want := range map[string]string{
		"8.8.8.8":              "US",
		"114.114.114.114":      "CN",
		"2001:4860:4860::8888": "CA",
	} {
		got := LookupCountry(ip)
		if got != want {
			t.Errorf("LookupCountry(%q) = %q, want %q", ip, got, want)
		}
		if len(got) != 2 || got != strings.ToUpper(got) {
			t.Errorf("LookupCountry(%q) = %q, want a two-letter uppercase ISO code", ip, got)
		}
	}
}

// TestLookupCountryPublicNoRecord pins the "public but unknown" boundary:
// documentation/reserved/multicast ranges parse as IPs and reach the
// database, which carries no country record for them — the result is the
// same empty string, never an error or a placeholder code.
func TestLookupCountryPublicNoRecord(t *testing.T) {
	for _, ip := range []string{
		"203.0.113.7", // TEST-NET-3
		"198.51.100.7", // TEST-NET-2
		"240.0.0.1",   // reserved
		"224.0.0.1",   // multicast
		"0.0.0.0",     // unspecified
	} {
		if got := LookupCountry(ip); got != "" {
			t.Errorf("LookupCountry(%q) = %q, want \"\" (no record)", ip, got)
		}
	}
}

// TestLookupCountryUnparseableInput pins the parse-failure boundary: input
// that is not an IP never reaches the database.
func TestLookupCountryUnparseableInput(t *testing.T) {
	for _, in := range []string{"", "not-an-ip", "999.999.999.999", "10.0.0.256"} {
		if got := LookupCountry(in); got != "" {
			t.Errorf("LookupCountry(%q) = %q, want \"\" (unparseable)", in, got)
		}
	}
}

// TestLookupCountryDatabaseUnavailable pins the geo-unavailable boundary:
// a nil reader (embedded database failed to parse) yields the empty string
// instead of a panic — lookupISO is the branch LookupCountry takes after
// the local-origin shortcut when Reader() returns nil.
func TestLookupCountryDatabaseUnavailable(t *testing.T) {
	ip := net.ParseIP("8.8.8.8")
	if ip == nil {
		t.Fatal("test IP must parse")
	}
	if got := lookupISO(nil, ip); got != "" {
		t.Errorf("lookupISO(nil, ip) = %q, want \"\"", got)
	}
}

// TestLocalOriginMatchesAggregationClassifier guards the same-source
// invariant: the geo aggregation (api/geo_stats.go) classifies origins with
// apiasset.IsPrivateIP, audit events with geoip.isLocalOrigin — both must
// agree on every representative address, or the log region and the TOP5
// local bucket would drift apart.
func TestLocalOriginMatchesAggregationClassifier(t *testing.T) {
	cases := map[string]bool{
		"10.1.2.3": true, "172.31.255.254": true, "192.168.0.1": true,
		"127.0.0.1": true, "169.254.9.9": true, "100.64.0.1": true,
		"100.127.255.254": true, "::1": true, "fd00::1": true, "fe80::1": true,
		"8.8.8.8": false, "203.0.113.7": false, "240.0.0.1": false,
		"224.0.0.1": false, "0.0.0.0": false, "2001:4860:4860::8888": false,
	}
	for ip, want := range cases {
		if got := isLocalOrigin(net.ParseIP(ip)); got != want {
			t.Errorf("isLocalOrigin(%q) = %v, want %v", ip, got, want)
		}
		if got := apiasset.IsPrivateIP(ip); got != want {
			t.Errorf("apiasset.IsPrivateIP(%q) = %v, want %v (classifier drift)", ip, got, want)
		}
	}
}

func BenchmarkLookupCountryPublic(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = LookupCountry("8.8.8.8")
	}
}

func BenchmarkLookupCountryLocalOrigin(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = LookupCountry("10.1.2.3")
	}
}
