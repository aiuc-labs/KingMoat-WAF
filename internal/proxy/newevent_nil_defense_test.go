package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// TestNewEventNilStateDefense pins the newEvent nil-defense symmetry
// (S-17): a nil planeState (handler before its first buildState store, or a
// broken start-up window) and a planeState without cfg must both degrade
// exactly like geoCountry already does — no panic, the event is still
// returned, request capture is skipped — while a real cfg keeps capturing.
func TestNewEventNilStateDefense(t *testing.T) {
	req := httptest.NewRequest("GET", "http://t.local/admin?x=1", nil)
	v := pipeline.Deny("waf/test", "blocked by test")

	// st == nil: no state ever stored on the handler.
	h := &Handler{audit: &captureStore{}, logger: testLogger()}
	ev := h.newEvent(req, "t.local", v, "blocked", 0, nil)
	if ev == nil {
		t.Fatal("nil planeState must still yield an event")
	}
	if ev.Rule != "waf/test" || ev.Action != "blocked" || ev.Site != "t.local" {
		t.Fatalf("nil-state event fields degraded: %+v", ev)
	}
	if ev.Headers != nil || ev.Body != "" {
		t.Fatalf("nil planeState must skip request capture: %+v", ev)
	}

	// st != nil but st.cfg == nil: degenerate state.
	h2 := &Handler{audit: &captureStore{}, logger: testLogger()}
	h2.state.Store(&planeState{})
	ev2 := h2.newEvent(req, "t.local", v, "blocked", 0, nil)
	if ev2 == nil {
		t.Fatal("nil cfg must still yield an event")
	}
	if ev2.Headers != nil || ev2.Body != "" {
		t.Fatalf("nil cfg must skip request capture: %+v", ev2)
	}

	// Sanity: a real cfg with capture enabled still captures — the nil
	// defense must not silently disable the feature for valid states.
	h3 := &Handler{audit: &captureStore{}, logger: testLogger()}
	h3.state.Store(&planeState{cfg: &config.Config{CaptureRequests: true}})
	ev3 := h3.newEvent(req, "t.local", v, "blocked", 0, nil)
	if ev3.Headers == nil {
		t.Fatal("capture must still run for a real cfg (defense must not disable the feature)")
	}
}
