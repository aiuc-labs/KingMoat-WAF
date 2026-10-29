// Package geoip embeds a country-level GeoIP database so site GeoIP
// blocking works out of the box (no user-supplied mmdb required).
//
// Database: DB-IP IP to Country Lite (monthly build), redistributed under
// CC BY 4.0 — attribution required: "IP Geolocation by DB-IP"
// (https://db-ip.com). A custom site geo.db_path always takes precedence
// over this embedded copy.
package geoip

import (
	_ "embed"
	"net"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

//go:embed dbip-country-lite.mmdb
var embedded []byte

var (
	once   sync.Once
	reader *maxminddb.Reader
	openErr error
)

// Reader returns the embedded country database (nil when it cannot be
// parsed; callers must fall back to "geo unavailable" behavior).
func Reader() *maxminddb.Reader {
	once.Do(func() {
		reader, openErr = maxminddb.FromBytes(embedded)
	})
	if openErr != nil {
		return nil
	}
	return reader
}

// Available reports whether the embedded database opened successfully.
func Available() bool { return Reader() != nil }

// Info returns the embedded database type and build month (best effort).
func Info() (dbType string, buildDate string) {
	r := Reader()
	if r == nil {
		return "", ""
	}
	m := r.Metadata
	if m.DatabaseType != "" {
		dbType = m.DatabaseType
	}
	if m.BuildEpoch > 0 {
		buildDate = time.Unix(int64(m.BuildEpoch), 0).UTC().Format("2006-01")
	}
	return dbType, buildDate
}

// mmdbCountry is the minimal record shape shared by every country lookup
// (identical to the anonymous struct in api/geo_stats.go so both resolve
// the same field of the same database).
type mmdbCountry struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// LookupCountry resolves an IP string to its ISO 3166-1 alpha-2 country
// code (uppercase two letters, e.g. "CN") via the embedded DB-IP country
// database — the same process-wide Reader() singleton used by the geo
// blocking stage and the /api/stats/geo aggregation fallback, never a
// second copy of the database.
//
// The empty string is the single deterministic "no country" value for:
// empty or unparseable input; private/loopback/link-local/CGNAT origins
// (isLocalOrigin — mirrors apiasset.IsPrivateIP, the classifier the
// dashboard uses for its 本地局域网 bucket); public IPs without a database
// record; lookup errors; and an unavailable database. Callers must treat
// "" as terminal (no retry), and the console derives the private-vs-unknown
// display distinction from the IP itself.
func LookupCountry(ipStr string) string {
	return LookupCountryWith(Reader(), ipStr)
}

// LookupCountryWith resolves an IP string through the GIVEN reader with the
// exact same "" semantics as LookupCountry. It lets the audit write path
// reuse an already-open site geo engine (stages.Geo.ReaderForDomain) so the
// log geo_country and the geo blocking/decision path share one source, and
// it never opens a second copy of any database. A nil reader yields ""
// (same terminal value as an unavailable embedded database).
func LookupCountryWith(r *maxminddb.Reader, ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if isLocalOrigin(ip) {
		return ""
	}
	return lookupISO(r, ip)
}

// isLocalOrigin mirrors apiasset.IsPrivateIP (internal/apiasset/collector.go)
// so audit-event enrichment and the dashboard geo aggregation classify
// origins identically: RFC1918/RFC4193 private, loopback, link-local
// unicast and CGNAT 100.64.0.0/10 carry no mmdb country. geoip stays a
// dependency-free leaf package, so the predicate is replicated here and
// geoip_test.go cross-checks both implementations against each other.
func isLocalOrigin(ip net.IP) bool {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
	}
	return false
}

// lookupISO resolves through the given reader (nil → ""). Split from
// LookupCountry so the unavailable-database branch stays unit-testable.
func lookupISO(r *maxminddb.Reader, ip net.IP) string {
	if r == nil {
		return ""
	}
	var rec mmdbCountry
	if err := r.Lookup(ip, &rec); err != nil {
		return ""
	}
	return rec.Country.ISOCode
}
