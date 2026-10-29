package apiasset

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRiskScanProducesFindings(t *testing.T) {
	store, err := Open(t.TempDir() + "/risk.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	old := time.Now().AddDate(0, 0, -60)
	// R2 seed: credential-heavy API hammered anonymously.
	if err := store.UpsertAsset(&Asset{
		Site: "s.local", Method: "GET", NormPath: "/api/v1/orders",
		AuthedRatio: 0.8, AnonOK: 50, Hits: 100,
		StatusDist: map[string]int{"2xx": 90},
		FirstSeen:  old, LastSeen: time.Now(),
	}, false); err != nil {
		t.Fatal(err)
	}
	// R5 seed: stale asset.
	if err := store.UpsertAsset(&Asset{
		Site: "s.local", Method: "GET", NormPath: "/api/legacy",
		Hits: 10, FirstSeen: old, LastSeen: old,
	}, false); err != nil {
		t.Fatal(err)
	}
	// R7 seed: plaintext sensitive params.
	if err := store.UpsertAsset(&Asset{
		Site: "http.local", Method: "POST", NormPath: "/api/login",
		Hits: 30, Sensitive: map[string]int{"password": 30},
		FirstSeen: old, LastSeen: time.Now(),
	}, false); err != nil {
		t.Fatal(err)
	}
	// R1 seed: respfilter detections.
	for i := 0; i < 12; i++ {
		if err := store.UpsertRespFilterHit("s.local", "/api/v1/users", "phone", 1); err != nil {
			t.Fatal(err)
		}
	}

	var rawSens string
	_ = store.db.QueryRow("SELECT sensitive_json FROM api_assets WHERE norm_path='/api/login'").Scan(&rawSens)
	t.Logf("raw sensitive_json=%q", rawSens)
	dbgAssets, _, _ := store.ListAssets("", "", "", "", false, 0, 100)
	for _, da := range dbgAssets {
		t.Logf("asset %s %s sens=%v", da.Method, da.NormPath, da.Sensitive)
	}
	e := NewEngine(store, &RisksConfig{ZombieDays: 30}, nil, nil)
	n, err := e.RunScan()
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 {
		t.Fatalf("new findings = %d, want >= 4", n)
	}
	risks, total, err := store.ListRisks("open", "", "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if total < 4 {
		t.Fatalf("open risks = %d", total)
	}
	kinds := map[string]bool{}
	for _, r := range risks {
		kinds[r.Kind] = true
		t.Logf("risk kind=%s level=%s ref=%s", r.Kind, r.Level, r.AssetRef)
		if r.ID == "" || r.Status != "open" {
			t.Fatalf("bad risk: %+v", r)
		}
	}
	for _, want := range []string{RiskSensitiveExposure, RiskUnauthorized, RiskZombieAPI, RiskPlaintextSecret} {
		if !kinds[want] {
			t.Errorf("missing risk kind %q; got %v", want, kinds)
		}
	}

	// Re-scan must not create duplicates (count refresh instead).
	n2, err := e.RunScan()
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Fatalf("rescan created %d new findings, want 0", n2)
	}

	// Status machine.
	if err := store.SetRiskStatus(risks[0].ID, "ignored"); err != nil {
		t.Fatal(err)
	}
	if _, total2, err := store.ListRisks("ignored", "", "", 0, 10); err != nil || total2 != 1 {
		t.Fatalf("ignored list = %d, %v", total2, err)
	}
}

func TestRiskCandidateShadowAPI(t *testing.T) {
	store, err := Open(t.TempDir() + "/cand.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Shadow-API seed: low-hit admin endpoint still in the candidate pool
	// (below the asset maturity gate), first seen inside the 24h window.
	if err := store.UpsertAsset(&Asset{
		Site: "sh.local", Method: "GET", NormPath: "/admin/export/users",
		Tags: []string{"admin"}, Hits: 1,
		FirstSeen: time.Now().Add(-time.Hour), LastSeen: time.Now(),
	}, true); err != nil {
		t.Fatal(err)
	}
	// Non-matching candidate: no admin/export tag → must not fire.
	if err := store.UpsertAsset(&Asset{
		Site: "sh.local", Method: "GET", NormPath: "/api/v1/orders",
		Hits: 1, FirstSeen: time.Now().Add(-time.Hour), LastSeen: time.Now(),
	}, true); err != nil {
		t.Fatal(err)
	}
	// Over the low-hit gate → must not fire.
	if err := store.UpsertAsset(&Asset{
		Site: "sh.local", Method: "DELETE", NormPath: "/admin/users/1",
		Tags: []string{"admin"}, Hits: 9,
		FirstSeen: time.Now().Add(-time.Hour), LastSeen: time.Now(),
	}, true); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(store, nil, nil, nil)
	n, err := e.RunScan()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("new findings = %d, want 1", n)
	}
	risks, _, err := store.ListRisks("open", "", "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 || risks[0].Kind != RiskShadowAPI {
		t.Fatalf("risks = %+v, want one shadow_api", risks)
	}
	if risks[0].Evidence["source"] != "candidate" {
		t.Fatalf("evidence source = %v, want candidate", risks[0].Evidence["source"])
	}
	// Re-scan: same riskID → upsert refresh, no new finding.
	n2, err := e.RunScan()
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Fatalf("rescan created %d findings, want 0", n2)
	}
}

func TestWebhookNotifierPayload(t *testing.T) {
	var got string
	srv := startTestSrv(t, func(body []byte) { got = string(body) })
	n := NewWebhookNotifier(srv.URL, nil)
	if err := n.NotifyRisk(&Risk{ID: "r1", Kind: RiskBruteForce, Level: "high", Message: "m"}); err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("webhook body empty")
	}
	// Empty URL is a no-op.
	if err := NewWebhookNotifier("", nil).NotifyRisk(&Risk{ID: "r2"}); err != nil {
		t.Fatal(err)
	}
}

func startTestSrv(t *testing.T, onBody func([]byte)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		onBody(b)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEnginePeriodicScanLifecycle(t *testing.T) {
	store, err := Open(t.TempDir() + "/periodic.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	e := NewEngine(store, &RisksConfig{ZombieDays: 30}, nil, nil)
	e.StartPeriodic(20 * time.Millisecond) // test-scale interval
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := store.LastScanAt(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("periodic scan never ran")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// StartPeriodic with a non-positive interval must be a no-op that
	// still leaves the first loop stoppable.
	e2 := NewEngine(store, nil, nil, nil)
	e2.StartPeriodic(0)
	e2.Stop()

	// Stop must be idempotent and silence the loop.
	e.Stop()
	e.Stop()
	t1, _ := store.LastScanAt()
	time.Sleep(80 * time.Millisecond)
	t2, _ := store.LastScanAt()
	if !t1.Equal(t2) {
		t.Fatal("scan ran after Stop")
	}
	// Manual scan still works after Stop.
	if _, err := e.RunScan(); err != nil {
		t.Fatalf("manual scan after Stop: %v", err)
	}
}
