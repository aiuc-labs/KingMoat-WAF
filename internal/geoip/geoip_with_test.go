package geoip

import (
	"testing"

	"github.com/oschwald/maxminddb-golang"
)

// TestLookupCountryWithMatchesLookupCountry pins the same-source primitive:
// LookupCountryWith over the embedded singleton must return exactly what
// LookupCountry returns (the audit write path routes through it when a site
// geo engine exists, so both entry points must stay value-identical).
func TestLookupCountryWithMatchesLookupCountry(t *testing.T) {
	if !Available() {
		t.Skip("embedded geoip unavailable in test environment")
	}
	for _, ip := range []string{"8.8.8.8", "114.114.114.114", "203.0.113.7", "10.1.2.3", "not-an-ip", ""} {
		with := LookupCountryWith(Reader(), ip)
		direct := LookupCountry(ip)
		if with != direct {
			t.Errorf("LookupCountryWith(Reader(), %q) = %q, LookupCountry = %q (drift)", ip, with, direct)
		}
	}
}

// TestLookupCountryWithNilReader pins the unavailable-database boundary for
// the explicit-reader variant: nil reader -> terminal empty string.
func TestLookupCountryWithNilReader(t *testing.T) {
	if got := LookupCountryWith((*maxminddb.Reader)(nil), "8.8.8.8"); got != "" {
		t.Errorf("LookupCountryWith(nil, 8.8.8.8) = %q, want \"\"", got)
	}
}

// TestLookupCountryWithEmptySemantics pins the "" contract of the
// explicit-reader variant: private/loopback origins and unparseable input
// never reach the database; public IPs without a record stay "".
func TestLookupCountryWithEmptySemantics(t *testing.T) {
	if !Available() {
		t.Skip("embedded geoip unavailable in test environment")
	}
	r := Reader()
	for _, ip := range []string{
		"10.20.30.40", // RFC1918
		"127.0.0.1",   // loopback
		"100.64.0.9",  // CGNAT
		"203.0.113.7", // public, no record (TEST-NET-3)
		"bogus",       // unparseable
	} {
		if got := LookupCountryWith(r, ip); got != "" {
			t.Errorf("LookupCountryWith(%q) = %q, want \"\"", ip, got)
		}
	}
}
