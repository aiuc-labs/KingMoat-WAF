package logstore

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestEventGeoCountryRoundTrip pins the write-path contract: the field
// travels through the store's raw JSON column unchanged (no schema
// migration involved) and comes back on Recent.
func TestEventGeoCountryRoundTrip(t *testing.T) {
	s := newTestStore(t)
	s.Write(&Event{
		TS:         time.Now().Format(time.RFC3339Nano),
		Action:     "blocked",
		Site:       "a.example.com",
		ClientIP:   "8.8.8.8",
		GeoCountry: "US",
		Method:     "GET",
		Path:       "/x",
		Rule:       "r1",
	})
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	rec := s.Recent(1)
	if len(rec) != 1 {
		t.Fatalf("event lost, got %d", len(rec))
	}
	if rec[0].GeoCountry != "US" {
		t.Fatalf("GeoCountry = %q, want US (raw-JSON round trip broken)", rec[0].GeoCountry)
	}
}

// TestEventGeoCountryOmittedWhenEmpty pins the omitempty contract: events
// without a country carry no geo_country key at all, so the API/shipper
// payloads of legacy-shaped events stay byte-stable.
func TestEventGeoCountryOmittedWhenEmpty(t *testing.T) {
	raw, err := json.Marshal(&Event{Action: "blocked", ClientIP: "10.0.0.1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "geo_country") {
		t.Fatalf("empty GeoCountry must not serialize, got %s", raw)
	}

	s := newTestStore(t)
	s.Write(&Event{TS: time.Now().Format(time.RFC3339Nano), Action: "blocked", ClientIP: "10.0.0.1"})
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	rec := s.Recent(1)
	if len(rec) != 1 {
		t.Fatalf("event lost, got %d", len(rec))
	}
	if rec[0].GeoCountry != "" {
		t.Fatalf("GeoCountry = %q, want empty", rec[0].GeoCountry)
	}
}

// TestEventLegacyRawWithoutGeoCountry pins the read-side safety guarantee
// for pre-existing rows: a raw JSON payload written before the field
// existed unmarshals without error and yields the zero value — both for a
// direct unmarshal and through the full store read path (Recent).
func TestEventLegacyRawWithoutGeoCountry(t *testing.T) {
	legacy := `{"ts":"2026-01-01T00:00:00Z","action":"blocked","site":"a.example.com","client_ip":"8.8.8.8","rule":"r1"}`
	var ev Event
	if err := json.Unmarshal([]byte(legacy), &ev); err != nil {
		t.Fatalf("legacy raw unmarshal: %v", err)
	}
	if ev.GeoCountry != "" {
		t.Fatalf("legacy GeoCountry = %q, want empty", ev.GeoCountry)
	}

	s := newTestStore(t)
	s.Write(&Event{TS: time.Now().Format(time.RFC3339Nano), Action: "blocked", ClientIP: "8.8.8.8", GeoCountry: "US"})
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	// Overwrite the stored payload with a legacy-shaped one, exactly like a
	// row written by an older release.
	if _, err := s.db.Exec(`UPDATE events SET raw = ?`, legacy); err != nil {
		t.Fatalf("legacy raw rewrite: %v", err)
	}
	rec := s.Recent(1)
	if len(rec) != 1 {
		t.Fatalf("legacy event lost, got %d", len(rec))
	}
	if rec[0].Action != "blocked" || rec[0].ClientIP != "8.8.8.8" {
		t.Fatalf("legacy event fields corrupted: %+v", rec[0])
	}
	if rec[0].GeoCountry != "" {
		t.Fatalf("legacy GeoCountry = %q, want empty", rec[0].GeoCountry)
	}
}
