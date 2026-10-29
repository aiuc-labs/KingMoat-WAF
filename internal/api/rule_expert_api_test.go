package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kingmoat/kingmoat/internal/ai"
	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/store"
)

// fakeRuleAnswer is the fenced answer the fake OpenAI-compatible upstream
// returns; it is deliberately multi-line (backslash continuation) so the
// parser path exercised here matches real model output.
const fakeRuleAnswer = "```seclang\n" +
	"SecRule REQUEST_HEADERS:User-Agent \"@contains sqlmap\" \\\n" +
	"    \"id:100001,phase:1,deny,status:403,log,msg:'扫描器 UA'\"\n" +
	"```\n" +
	"说明：拦截 UA 含 sqlmap 的请求，建议先观察再拦截。\n"

// ruleExpertEnv is a console with an enabled ai section pointed at a fake
// OpenAI-compatible upstream. hits counts completions actually requested, so
// "extract never calls the model" is asserted by evidence, not by inspection.
type ruleExpertEnv struct {
	ts     *httptest.Server
	cookie *http.Cookie
	hits   *atomic.Int64
}

func newRuleExpertEnv(t *testing.T, tune func(*config.Config)) *ruleExpertEnv {
	t.Helper()
	dir := t.TempDir()
	kekPath := filepath.Join(dir, "ai-kek.key")
	hits := &atomic.Int64{}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		writeJSON(w, http.StatusOK, map[string]any{
			"choices": []any{map[string]any{
				"message":       map[string]any{"role": "assistant", "content": fakeRuleAnswer},
				"finish_reason": "stop",
			}},
			"usage": map[string]any{"prompt_tokens": 120, "completion_tokens": 80},
		})
	}))
	t.Cleanup(upstream.Close)
	t.Setenv("KMWAF_AI_API_KEY", "sk-test-key")

	cfg := seedCfg()
	cfg.AI = json.RawMessage(fmt.Sprintf(
		`{"enabled":true,"provider":{"template":"custom","base_url":%q,"model":"test-model","api_key_env":"KMWAF_AI_API_KEY"},"rule_expert":{"rate_per_min":60}}`,
		upstream.URL))
	if tune != nil {
		tune(cfg)
	}

	center, err := configcenter.Open(filepath.Join(dir, "re.db"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := logstore.NewSQLiteStore(filepath.Join(dir, "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	adminHash := "$argon2id$v=19$m=65536,t=3,p=4$" + mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("hunter2")
	if _, err := center.Store().CreateUser("admin", adminHash, store.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	var cur atomic.Pointer[ai.Service]
	srv := New(Options{
		SkipBootstrap: true,
		Center:        center,
		Logs:          audit,
		Auth:          NewAuth(adminHash),
		AIFn:          func() *ai.Service { return cur.Load() },
	})
	st := ai.ResolveSettings(cfg.AI, "", kekPath, quietSlog())
	if st == nil || !st.Enabled {
		t.Fatal("ai settings did not resolve as enabled")
	}
	svc, err := ai.NewService(st, &ai.DataSources{Version: "test"}, filepath.Join(dir, "ai.db"), st.KEK, quietSlog(), config.EmailSettings{})
	if err != nil {
		t.Fatalf("ai service: %v", err)
	}
	cur.Store(svc)
	t.Cleanup(func() {
		_ = svc.Close()
		center.Close()
		audit.Close()
	})

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &ruleExpertEnv{ts: ts, cookie: loginAs(t, ts, "admin", "hunter2"), hits: hits}
}

// doRawRequest sends an arbitrary body (multipart or JSON) with the session.
func doRawRequest(t *testing.T, ts *httptest.Server, path string, cookie *http.Cookie, body io.Reader, contentType string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

// multipartBody builds a multipart/form-data body from text fields plus one
// optional file part.
func ruleExpertMultipart(t *testing.T, fields map[string]string, fileName string, fileData []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if fileName != "" {
		fw, err := mw.CreateFormFile("file", fileName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(fileData); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, mw.FormDataContentType()
}

func errCode(t *testing.T, body []byte) string {
	t.Helper()
	var d struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("error body is not JSON: %s", body)
	}
	if d.Message == "" {
		t.Fatalf("error body has no Chinese message: %s", body)
	}
	return d.Code
}

func TestRuleExpertAIUnavailable(t *testing.T) {
	center, err := configcenter.Open(filepath.Join(t.TempDir(), "noai.db"), seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer center.Close()
	srv := New(Options{SkipBootstrap: true, Center: center})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	code, body := doReq(t, ts, "POST", "/api/policy/rule-expert", nil, map[string]string{"text": "CVE-2024-1"})
	if code != http.StatusNotFound {
		t.Fatalf("generate without AI = %d (%s), want 404", code, body)
	}
	if got := errCode(t, body); got != "ai_disabled" {
		t.Fatalf("code = %q, want ai_disabled", got)
	}
}

func TestRuleExpertOversize(t *testing.T) {
	env := newRuleExpertEnv(t, nil)
	huge := strings.Repeat("A", 9<<20)
	body, ct := ruleExpertMultipart(t, map[string]string{"source_type": "text", "text": huge}, "", nil)
	code, resp := doRawRequest(t, env.ts, "/api/policy/rule-expert/extract", env.cookie, body, ct)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("9MB extract = %d (%s), want 413", code, truncateForLog(resp))
	}
	if got := errCode(t, resp); got != "input_too_large" {
		t.Fatalf("code = %q, want input_too_large", got)
	}
	if env.hits.Load() != 0 {
		t.Fatalf("upstream called %d times for an oversized input", env.hits.Load())
	}
}

func TestRuleExpertMultipartFile(t *testing.T) {
	env := newRuleExpertEnv(t, nil)
	html := []byte("<html><body><h1>CVE-2024-9999 SQL 注入</h1><p>攻击参数 cmd，路径 /api/run</p></body></html>")
	body, ct := ruleExpertMultipart(t, map[string]string{"source_type": "file"}, "advisory.html", html)
	code, resp := doRawRequest(t, env.ts, "/api/policy/rule-expert", env.cookie, body, ct)
	if code != http.StatusOK {
		t.Fatalf("multipart generate = %d (%s)", code, truncateForLog(resp))
	}
	var d struct {
		Rule      string   `json:"rule"`
		Warnings  []string `json:"warnings"`
		Model     string   `json:"model"`
		Extracted struct {
			SourceType string `json:"source_type"`
			SourceName string `json:"source_name"`
			Chars      int    `json:"chars"`
			Truncated  bool   `json:"truncated"`
		} `json:"extracted"`
	}
	if err := json.Unmarshal(resp, &d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Rule, "SecRule") {
		t.Fatalf("rule = %q", d.Rule)
	}
	if d.Model != "test-model" {
		t.Fatalf("model = %q", d.Model)
	}
	if d.Extracted.SourceType != "file" || d.Extracted.SourceName != "advisory.html" || d.Extracted.Chars == 0 {
		t.Fatalf("extracted = %+v", d.Extracted)
	}
	if env.hits.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", env.hits.Load())
	}
	// The generation response must not echo the extracted body.
	if bytes.Contains(resp, []byte("攻击参数 cmd")) || bytes.Contains(resp, []byte("CVE-2024-9999")) {
		t.Fatalf("response leaked the input text: %s", truncateForLog(resp))
	}
}

func TestRuleExpertExtractOnly(t *testing.T) {
	env := newRuleExpertEnv(t, nil)
	body, ct := ruleExpertMultipart(t, map[string]string{
		"source_type": "text",
		"text":        "CVE-2024-7777 远程命令执行，参数 name，路径 /admin/exec",
	}, "", nil)
	code, resp := doRawRequest(t, env.ts, "/api/policy/rule-expert/extract", env.cookie, body, ct)
	if code != http.StatusOK {
		t.Fatalf("extract = %d (%s)", code, truncateForLog(resp))
	}
	var d struct {
		Text       string   `json:"text"`
		SourceType string   `json:"source_type"`
		Chars      int      `json:"chars"`
		Truncated  bool     `json:"truncated"`
		Warnings   []string `json:"warnings"`
	}
	if err := json.Unmarshal(resp, &d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Text, "CVE-2024-7777") || d.SourceType != "text" {
		t.Fatalf("extract payload = %+v", d)
	}
	if d.Chars == 0 || d.Warnings == nil {
		t.Fatalf("extract metadata = %+v", d)
	}
	if env.hits.Load() != 0 {
		t.Fatalf("extract called the model %d times, want 0", env.hits.Load())
	}
}

func TestRuleExpertSuccess(t *testing.T) {
	env := newRuleExpertEnv(t, nil)
	const marker = "MARKER-CVE-2024-4242-UNIQUE"
	code, resp := doReq(t, env.ts, "POST", "/api/policy/rule-expert", env.cookie,
		map[string]string{"text": marker + " 命令注入，参数 cmd"})
	if code != http.StatusOK {
		t.Fatalf("generate = %d (%s)", code, truncateForLog(resp))
	}
	var d struct {
		Rule     string   `json:"rule"`
		Notes    string   `json:"notes"`
		Warnings []string `json:"warnings"`
		Model    string   `json:"model"`
		Usage    struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
		Remaining struct {
			RequestsToday int   `json:"requests_today"`
			TokensToday   int64 `json:"tokens_today"`
		} `json:"remaining"`
	}
	if err := json.Unmarshal(resp, &d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Rule, "id:100001") || !strings.Contains(d.Rule, "msg:") {
		t.Fatalf("rule = %q", d.Rule)
	}
	if d.Notes == "" {
		t.Fatalf("notes = %q, want the Chinese explanation", d.Notes)
	}
	if d.Usage.PromptTokens != 120 || d.Usage.CompletionTokens != 80 {
		t.Fatalf("usage = %+v", d.Usage)
	}
	if d.Remaining.RequestsToday != 49 || d.Remaining.TokensToday != 200000-200 {
		t.Fatalf("remaining = %+v", d.Remaining)
	}
	if bytes.Contains(resp, []byte(marker)) {
		t.Fatalf("response leaked the pasted advisory: %s", truncateForLog(resp))
	}
	if env.hits.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", env.hits.Load())
	}
}

func TestRuleExpertDailyQuota(t *testing.T) {
	env := newRuleExpertEnv(t, func(cfg *config.Config) {
		cfg.AI = json.RawMessage(strings.Replace(string(cfg.AI),
			`"rate_per_min":60`, `"rate_per_min":60,"max_requests_per_day":2`, 1))
	})
	for i := 0; i < 2; i++ {
		if code, b := doReq(t, env.ts, "POST", "/api/policy/rule-expert", env.cookie,
			map[string]string{"text": "CVE-2024-" + strings.Repeat("1", i+1)}); code != http.StatusOK {
			t.Fatalf("generate #%d = %d (%s)", i+1, code, truncateForLog(b))
		}
	}
	code, body := doReq(t, env.ts, "POST", "/api/policy/rule-expert", env.cookie, map[string]string{"text": "CVE-2024-3"})
	if code != http.StatusTooManyRequests {
		t.Fatalf("third generate = %d (%s), want 429", code, truncateForLog(body))
	}
	if got := errCode(t, body); got != "quota_exceeded" {
		t.Fatalf("code = %q, want quota_exceeded", got)
	}
	if env.hits.Load() != 2 {
		t.Fatalf("upstream calls = %d, want 2 (quota must not reach the model)", env.hits.Load())
	}
}

func truncateForLog(b []byte) string {
	if len(b) > 400 {
		return string(b[:400]) + "..."
	}
	return string(b)
}
