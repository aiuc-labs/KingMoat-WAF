package main

import (
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

func TestSectionTrackerUnchangedSemantics(t *testing.T) {
	var tr sectionTracker[config.AccessLogSettings]

	// Unseeded + nil section: absent from both revisions, nothing to rebuild.
	if !tr.unchanged(nil) {
		t.Fatal("unseeded tracker with a nil section must report unchanged")
	}
	// Unseeded + live section: the boot/rebuild path must still run.
	if tr.unchanged(&config.AccessLogSettings{Enabled: true, Type: "loki", URL: "https://loki.internal:3100"}) {
		t.Fatal("unseeded tracker with a live section must report changed")
	}

	tr.seed(&config.AccessLogSettings{Enabled: true, Type: "loki", URL: "https://loki.internal:3100", Index: "kingmoat_access"})
	if !tr.unchanged(&config.AccessLogSettings{Enabled: true, Type: "loki", URL: "https://loki.internal:3100", Index: "kingmoat_access"}) {
		t.Fatal("deep-equal section must report unchanged (no reconnect on unrelated publishes)")
	}
	if tr.unchanged(&config.AccessLogSettings{Enabled: true, Type: "loki", URL: "https://loki.internal:3100", Index: "other"}) {
		t.Fatal("index change must report changed")
	}
	if tr.unchanged(nil) {
		t.Fatal("removing the section must report changed")
	}

	tr.seed(nil)
	if !tr.unchanged(nil) {
		t.Fatal("seeded nil vs nil must report unchanged")
	}
	if tr.unchanged(&config.AccessLogSettings{Enabled: true, Type: "loki"}) {
		t.Fatal("re-enabling an absent section must report changed")
	}
}

func TestSectionTrackerSeedsTheGivenSnapshot(t *testing.T) {
	var tr sectionTracker[config.ShipperSettings]
	ship := &config.ShipperSettings{Type: "clickhouse", URL: "http://ch.internal:8123"}
	tr.seed(ship)
	if !tr.unchanged(ship) {
		t.Fatal("the section a live instance was built from must be unchanged")
	}
	if !tr.unchanged(&config.ShipperSettings{Type: "clickhouse", URL: "http://ch.internal:8123"}) {
		t.Fatal("an equal copy from the next revision must be unchanged")
	}
}
