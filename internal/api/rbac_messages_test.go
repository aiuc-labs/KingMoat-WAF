package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kingmoat/kingmoat/internal/store"
)

// 对外错误文案契约：控制台前端（web/console/src/api.js）只从 JSON 响应体的
// error/message 字段取展示文案（非 JSON 会退化成 HTTP statusText），而登录
// 流程还按字符串精确匹配 totp_required / invalid credentials /
// password_change_required 三个错误码。因此「对外英文文案中文化」必须同时守住
// 两条边界：
//  1. 未认证 401 与权限不足 403 都返回 application/json 的中文文案，且 403
//     文案带上所需角色的中文名与角色码；
//  2. 上述三个错误码保持英文原样，没有被顺手中文化。
func TestRBACErrorMessagesAreChineseJSON(t *testing.T) {
	ts, login := rbacServer(t)
	const (
		unauthenticated = "未登录或会话已失效，请重新登录"
		needAdmin       = "权限不足：该操作需要管理员（admin）权限"
		needOperator    = "权限不足：该操作需要操作员（operator）权限"
	)

	t.Run("未认证返回401中文JSON而非纯文本", func(t *testing.T) {
		req, err := http.NewRequest("GET", ts.URL+"/api/users", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("未认证访问 /api/users = %d, want 401", resp.StatusCode)
		}
		// 旧实现用 http.Error 回纯文本，前端只能显示 statusText；必须仍是 JSON。
		if ct := resp.Header.Get("Content-Type"); !bytes.Contains([]byte(ct), []byte("application/json")) {
			t.Fatalf("未认证响应 Content-Type = %q, want application/json", ct)
		}
		var got map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("未认证响应不是 JSON: %v", err)
		}
		if got["error"] != unauthenticated {
			t.Fatalf("未认证错误文案 = %v, want %q", got["error"], unauthenticated)
		}
	})

	admin := login("admin", "hunter2")
	for _, u := range []struct{ name, role string }{
		{"msgop", store.RoleOperator},
		{"msgaud", store.RoleAuditor},
	} {
		if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
			"username": u.name, "password": "msg-pass-wd", "role": u.role,
		}); code != http.StatusOK {
			t.Fatalf("创建 %s 账号 = %d, want 200", u.role, code)
		}
	}
	op := login("msgop", "msg-pass-wd")
	aud := login("msgaud", "msg-pass-wd")

	t.Run("权限不足403为中文且带所需角色名", func(t *testing.T) {
		// /api/users 需要 admin：操作员与审计员都应拿到「管理员（admin）」文案
		for name, client := range map[string]*http.Client{"operator": op, "auditor": aud} {
			code, body := doJSONBody(t, client, "GET", ts.URL+"/api/users", nil)
			if code != http.StatusForbidden {
				t.Fatalf("%s 访问 /api/users = %d, want 403", name, code)
			}
			if body["error"] != needAdmin {
				t.Fatalf("%s 403 文案 = %v, want %q", name, body["error"], needAdmin)
			}
		}
		// /api/config/publish 需要 operator：审计员应拿到「操作员（operator）」文案
		code, body := doJSONBody(t, aud, "POST", ts.URL+"/api/config/publish", map[string]any{})
		if code != http.StatusForbidden {
			t.Fatalf("auditor 发布配置 = %d, want 403", code)
		}
		if body["error"] != needOperator {
			t.Fatalf("auditor 发布 403 文案 = %v, want %q", body["error"], needOperator)
		}
	})

	t.Run("三档角色中文名映射", func(t *testing.T) {
		for role, want := range map[string]string{
			store.RoleAdmin:    "管理员",
			store.RoleOperator: "操作员",
			store.RoleAuditor:  "审计员",
		} {
			if got := roleLabel(role); got != want {
				t.Fatalf("roleLabel(%q) = %q, want %q", role, got, want)
			}
		}
	})

	t.Run("前端按字符串匹配的三个错误码保持原样", func(t *testing.T) {
		// invalid credentials：密码错误
		code, body := postLoginBody(t, ts, map[string]string{"username": "admin", "password": "not-the-password"})
		if code != http.StatusUnauthorized || body["error"] != "invalid credentials" {
			t.Fatalf("密码错误登录 = %d %v, want 401 invalid credentials", code, body)
		}

		// totp_required：密码正确但缺少动态口令
		mts, _, _ := mfaLoginServer(t)
		code, body = postLoginBody(t, mts, map[string]string{"username": "mfauser", "password": "mfa-user-pw"})
		if code != http.StatusUnauthorized || body["error"] != "totp_required" {
			t.Fatalf("缺动态口令登录 = %d %v, want 401 totp_required", code, body)
		}

		// password_change_required：初始密码未改，写操作被强制改密门禁拦截
		ets, _ := emptyUserServer(t, 0)
		req, err := http.NewRequest("GET", ets.URL+"/api/config", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("", testBootstrapPassword)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var got struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if resp.StatusCode != http.StatusForbidden || got.Error != "password_change_required" {
			t.Fatalf("初始密码未改访问 /api/config = %d %q, want 403 password_change_required", resp.StatusCode, got.Error)
		}
	})
}
