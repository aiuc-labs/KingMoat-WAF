package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/store"
	"github.com/kingmoat/kingmoat/internal/webui"
)

// deadStoreServer builds an auth-disabled console whose user store is closed,
// so every user-store operation fails with a driver error — the harness for
// the「存储层故障不得回显驱动错误 / 故障≠不存在」contract.
func deadStoreServer(t *testing.T) *httptest.Server {
	t.Helper()
	center, err := configcenter.Open(filepath.Join(t.TempDir(), "dead-store.db"), seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	srv := New(Options{SkipBootstrap: true, Center: center, Logs: audit, WebUI: webui.Handler("test")})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	if err := center.Close(); err != nil {
		t.Fatalf("close user store: %v", err)
	}
	return ts
}

// S-6 (revised by gate G-4): a failed user creation answers the classifier's
// fixed 5xx — a store failure is a server-side fact, not a client error; the
// SQLite driver text goes to the server log only.
func TestUserCreateStoreFailureNotEchoed(t *testing.T) {
	ts := deadStoreServer(t)
	code, body := doJSONBody(t, &http.Client{}, "POST", ts.URL+"/api/users", map[string]string{
		"username": "ghost", "password": "ghost-pass-1", "role": "auditor",
	})
	if code != http.StatusInternalServerError {
		t.Fatalf("create on dead store = %d, want 500", code)
	}
	if body["error"] != "用户数据操作失败，详情见服务端日志" {
		t.Fatalf("error = %v, want the fixed client message", body["error"])
	}
	raw, _ := json.Marshal(body)
	for _, leak := range []string{"store:", "database is closed", "SQLITE_"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("driver text %q echoed to the client: %s", leak, raw)
		}
	}
}

// S-7: GetUser failures split into「存储层故障 → 5xx」vs「用户不存在 → 404」.
func TestUserLookupFailureVsNotFound(t *testing.T) {
	t.Run("store failure answers 5xx with fixed message", func(t *testing.T) {
		ts := deadStoreServer(t)
		code, body := doJSONBody(t, &http.Client{}, "POST", ts.URL+"/api/users/ghost/reset-password", map[string]string{})
		if code != http.StatusInternalServerError {
			t.Fatalf("lookup on dead store = %d, want 500", code)
		}
		if body["error"] != "用户数据操作失败，详情见服务端日志" {
			t.Fatalf("error = %v, want the fixed client message", body["error"])
		}
	})
	t.Run("missing user answers 404", func(t *testing.T) {
		ts, _ := uploadServer(t)
		code, body := doJSONBody(t, &http.Client{}, "POST", ts.URL+"/api/users/ghost/reset-password", map[string]string{})
		if code != http.StatusNotFound {
			t.Fatalf("missing user = %d, want 404", code)
		}
		if body["error"] != "用户不存在" {
			t.Fatalf("error = %v, want 用户不存在", body["error"])
		}
	})
}

// S-7: MFA setup and confirm describe the same fact (target account does not
// exist) with the same code — both 404, never a 400/404 split.
func TestMFASetupAndConfirmAgreeOnMissingUser(t *testing.T) {
	ts, _ := uploadServer(t)
	setupCode, setupBody := doJSONBody(t, &http.Client{}, "POST", ts.URL+"/api/users/ghost/mfa/setup", map[string]string{})
	if setupCode != http.StatusNotFound || setupBody["error"] != "用户不存在" {
		t.Fatalf("setup = %d %v, want 404 用户不存在", setupCode, setupBody)
	}
	confirmCode, confirmBody := doJSONBody(t, &http.Client{}, "POST", ts.URL+"/api/users/ghost/mfa/confirm", map[string]string{"code": "000000"})
	if confirmCode != http.StatusNotFound || confirmBody["error"] != "用户不存在" {
		t.Fatalf("confirm = %d %v, want 404 用户不存在 (same fact, same code as setup)", confirmCode, confirmBody)
	}
}

// S-13: requireRole without a resolved identity answers the same 401 + text
// as the auth middleware (defense-in-depth branch, was 403).
func TestRequireRoleUnauthenticatedIs401(t *testing.T) {
	hash := "$argon2id$v=19$m=65536,t=3,p=4$" +
		mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("hunter2")
	srv := New(Options{SkipBootstrap: true, Center: mustCenter(t), Auth: NewAuth(hash)})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	if srv.requireRole(rr, req, store.RoleAdmin) {
		t.Fatal("request without identity must be denied")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("requireRole without identity = %d, want 401 (same as the auth middleware)", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not json: %v (%s)", err, rr.Body.String())
	}
	if body["error"] != "未登录或会话已失效，请重新登录" {
		t.Fatalf("message = %v, want the middleware's exact text", body["error"])
	}
}

// S-13: a store-level ErrUserNotFound on a named-user mutation renders 404
// (was 400 with the raw sentinel text).
func TestNamedUserNotFoundMapsTo404(t *testing.T) {
	ts, _ := uploadServer(t)
	code, body := doJSONBody(t, &http.Client{}, "DELETE", ts.URL+"/api/users/ghost/apikey", nil)
	if code != http.StatusNotFound {
		t.Fatalf("revoke key for missing user = %d, want 404", code)
	}
	if body["error"] != "用户不存在" {
		t.Fatalf("error = %v, want 用户不存在", body["error"])
	}
}
