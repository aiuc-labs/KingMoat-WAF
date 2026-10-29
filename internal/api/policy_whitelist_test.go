package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// getConfig fetches the active config document as a generic map.
func getConfig(t *testing.T, ts *httptest.Server, client *http.Client) (int, map[string]any) {
	t.Helper()
	resp, err := client.Get(ts.URL + "/api/config")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode /api/config: %v (%s)", err, b)
	}
	cfg, _ := out["config"].(map[string]any)
	return resp.StatusCode, cfg
}

// TestPolicyWhitelist covers POST /api/policy/whitelist: RBAC gating,
// rule structure (name prefix / sites / allow action / path condition),
// idempotent duplicates and name suffixing for repeat paths.
func TestPolicyWhitelist(t *testing.T) {
	ts, login := rbacServer(t)
	admin := login("admin", "hunter2")

	const audPass = "hunter2x"
	if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
		"username": "aud", "password": audPass, "role": "auditor",
	}); code != http.StatusOK {
		t.Fatalf("create auditor = %d", code)
	}
	auditor := login("aud", audPass)

	body := map[string]any{"site": "A.LOCAL", "path": "/api/search", "prefix": true, "comment": "fp in search box"}

	// Auditor is read-only.
	if code := doJSON(t, auditor, "POST", ts.URL+"/api/policy/whitelist", body); code != http.StatusForbidden {
		t.Fatalf("auditor POST whitelist = %d, want 403", code)
	}

	// First create succeeds and publishes a matcher rule.
	code, resp := doJSONBody(t, admin, "POST", ts.URL+"/api/policy/whitelist", body)
	if code != http.StatusOK || resp["ok"] != true || resp["unchanged"] == true {
		t.Fatalf("POST whitelist = %d, %v", code, resp)
	}
	name, _ := resp["name"].(string)
	if name != "误报加白: a.local/api/search" {
		t.Fatalf("rule name = %q", name)
	}

	// Structural assertions on the published rule.
	_, cfg := getConfig(t, ts, admin)
	ms, _ := cfg["policy"].(map[string]any)["matchers"].([]any)
	if len(ms) != 1 {
		t.Fatalf("matchers = %v, want exactly 1 rule", cfg["policy"])
	}
	rule, _ := ms[0].(map[string]any)
	if rule["name"] != name || rule["action"] != "allow" || rule["logic"] != "and" || rule["enabled"] != true {
		t.Fatalf("rule header wrong: %v", rule)
	}
	sites, _ := rule["sites"].([]any)
	if len(sites) != 1 || sites[0] != "a.local" {
		t.Fatalf("rule sites = %v, want [a.local]", rule["sites"])
	}
	conds, _ := rule["conditions"].([]any)
	if len(conds) != 1 {
		t.Fatalf("rule conditions = %v, want 1", rule["conditions"])
	}
	cond, _ := conds[0].(map[string]any)
	if cond["field"] != "path" || cond["op"] != "prefix" || cond["value"] != "/api/search" {
		t.Fatalf("path condition wrong: %v", cond)
	}
	comment, _ := rule["comment"].(string)
	if !strings.HasPrefix(comment, "误报加白") {
		t.Fatalf("rule comment = %q, want 误报加白 prefix", rule["comment"])
	}

	// Exact-path variant on the same site+path is a distinct rule and gets
	// a " #2" name suffix (same base name already taken).
	code, resp2 := doJSONBody(t, admin, "POST", ts.URL+"/api/policy/whitelist",
		map[string]any{"site": "a.local", "path": "/api/search", "prefix": false})
	if code != http.StatusOK || resp2["unchanged"] == true {
		t.Fatalf("POST whitelist exact = %d, %v", code, resp2)
	}
	if got, _ := resp2["name"].(string); got != "误报加白: a.local/api/search #2" {
		t.Fatalf("suffixed rule name = %q", got)
	}

	// Idempotency: repeating the first call returns unchanged and does not
	// add another rule.
	code, resp3 := doJSONBody(t, admin, "POST", ts.URL+"/api/policy/whitelist", body)
	if code != http.StatusOK || resp3["ok"] != true || resp3["unchanged"] != true {
		t.Fatalf("repeat POST whitelist = %d, %v, want unchanged", code, resp3)
	}
	_, cfg = getConfig(t, ts, admin)
	ms, _ = cfg["policy"].(map[string]any)["matchers"].([]any)
	if len(ms) != 2 {
		t.Fatalf("matchers after duplicate = %d, want 2", len(ms))
	}

	// Legacy all-sites entry (empty site) is accepted too.
	if code := doJSON(t, admin, "POST", ts.URL+"/api/policy/whitelist",
		map[string]any{"site": "", "path": "/health"}); code != http.StatusOK {
		t.Fatalf("POST whitelist empty site = %d", code)
	}
	_, cfg = getConfig(t, ts, admin)
	ms, _ = cfg["policy"].(map[string]any)["matchers"].([]any)
	last, _ := ms[len(ms)-1].(map[string]any)
	if _, has := last["sites"]; has {
		t.Fatalf("empty-site rule must omit sites, got %v", last["sites"])
	}

	// Bad path is rejected.
	if code := doJSON(t, admin, "POST", ts.URL+"/api/policy/whitelist",
		map[string]any{"site": "a.local", "path": "no-slash"}); code != http.StatusBadRequest {
		t.Fatalf("POST whitelist bad path = %d, want 400", code)
	}
}

// TestPolicyWhitelistBodyStream pins the one-click linkage: with body_stream
// the same publish also declares the path as a deep-inspection-prefix on the
// target site (over-limit uploads stop answering 413), the second call is
// idempotent across BOTH effects, and a concrete existing site is required.
func TestPolicyWhitelistBodyStream(t *testing.T) {
	ts, login := rbacServer(t)
	admin := login("admin", "hunter2")

	body := map[string]any{"site": "a.local", "path": "/v1/upload", "prefix": true, "body_stream": true}
	code, resp := doJSONBody(t, admin, "POST", ts.URL+"/api/policy/whitelist", body)
	if code != http.StatusOK || resp["unchanged"] == true || resp["body_stream"] != true {
		t.Fatalf("POST whitelist body_stream = %d, %v", code, resp)
	}
	_, cfg := getConfig(t, ts, admin)
	sites, _ := cfg["sites"].([]any)
	if len(sites) != 1 {
		t.Fatalf("sites = %v", cfg["sites"])
	}
	site, _ := sites[0].(map[string]any)
	waf, _ := site["waf"].(map[string]any)
	paths, _ := waf["body_stream_paths"].([]any)
	if len(paths) != 1 || paths[0] != "/v1/upload" {
		t.Fatalf("body_stream_paths = %v, want [/v1/upload]", waf["body_stream_paths"])
	}

	// Repeat: both effects already applied -> unchanged, no new revision.
	code, resp2 := doJSONBody(t, admin, "POST", ts.URL+"/api/policy/whitelist", body)
	if code != http.StatusOK || resp2["unchanged"] != true {
		t.Fatalf("repeat = %d %v, want unchanged", code, resp2)
	}

	// Unknown site / missing site are rejected before publishing.
	if code := doJSON(t, admin, "POST", ts.URL+"/api/policy/whitelist",
		map[string]any{"site": "nope.local", "path": "/x", "body_stream": true}); code != http.StatusNotFound {
		t.Fatalf("unknown site = %d, want 404", code)
	}
	if code := doJSON(t, admin, "POST", ts.URL+"/api/policy/whitelist",
		map[string]any{"site": "", "path": "/x", "body_stream": true}); code != http.StatusBadRequest {
		t.Fatalf("empty site = %d, want 400", code)
	}
}
