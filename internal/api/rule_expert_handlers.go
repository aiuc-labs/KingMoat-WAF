package api

import (
	"fmt"
	"encoding/base64"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kingmoat/kingmoat/internal/ai"
	"github.com/kingmoat/kingmoat/internal/docextract"
	"github.com/kingmoat/kingmoat/internal/ruleexpert"
	"github.com/kingmoat/kingmoat/internal/safefetch"
	"github.com/kingmoat/kingmoat/internal/store"
)

// Rule expert (策略 → 规则专家): one advisory in, one reviewable SecLang rule
// out. Nothing is persisted: the extracted text lives only in the prompt of
// the current request, and neither the input nor the raw model answer is
// written to the audit log or the response.
const (
	// ruleExpertBodyLimit is the transport ceiling for one upload. It is the
	// hard boundary (http.MaxBytesReader) and matches docextract.MaxInputBytes;
	// ai.rule_expert.max_input_bytes can only narrow the pasted-text budget.
	ruleExpertBodyLimit = 8 << 20
	// ruleExpertExtractLimit bounds extraction (URL fetch + document parse).
	ruleExpertExtractLimit = 20 * time.Second
)

// errParseTimeout marks an extraction that outlived ruleExpertExtractLimit.
var errParseTimeout = errors.New("解析超时")

// ruleExpertInput is one parsed request: exactly one of the payload fields is
// populated per source type.
type ruleExpertInput struct {
	SourceType   string
	Text         string
	Filename     string
	Data         []byte
	URL          string
	AllowPrivate bool
	Rows         []byte
}

// writeCodedErr answers with the machine-readable code plus Chinese message
// the console displays verbatim.
func writeCodedErr(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"code": code, "message": message})
}

func isMaxBytesErr(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

// ruleExpertUser is the limiter key: the signed-in console account, or
// "local" on an auth-disabled (dev / all-in-one) console.
func ruleExpertUser(r *http.Request) string {
	if u := userFromContext(r); u != nil && u.Username != "" {
		return u.Username
	}
	return "local"
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// parseRuleExpertInput reads the multipart form (or the JSON shorthand) into
// one ruleExpertInput. It answers the request itself on failure and returns a
// nil input; status/code/message describe the refusal.
func (s *Server) parseRuleExpertInput(w http.ResponseWriter, r *http.Request, textBudget int) (*ruleExpertInput, int, *deny) {
	r.Body = http.MaxBytesReader(w, r.Body, ruleExpertBodyLimit)
	tooLarge := &deny{code: "input_too_large", message: "输入内容超过 8MB 上限，请精简后再试"}
	overBudget := func(n int) bool { return textBudget > 0 && n > textBudget }

	ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if !strings.HasPrefix(ct, "multipart/") {
		// JSON shorthand ({"text","filename"}): the documented quick path for
		// scripts and curl without a hand-built form body.
		var req struct {
			Text     string `json:"text"`
			Filename string `json:"filename"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			if isMaxBytesErr(err) {
				return nil, http.StatusRequestEntityTooLarge, tooLarge
			}
			return nil, http.StatusBadRequest, &deny{code: "parse_failed", message: "请求体解析失败：请提供 text 字段"}
		}
		if overBudget(len(req.Text)) {
			return nil, http.StatusRequestEntityTooLarge, &deny{
				code:    "input_too_large",
				message: "粘贴内容超过上限（" + itoaK(textBudget) + "），请精简后重试或调高 ai.rule_expert.max_input_bytes",
			}
		}
		return &ruleExpertInput{SourceType: docextract.SourceText, Text: req.Text, Filename: req.Filename}, 0, nil
	}

	if err := r.ParseMultipartForm(ruleExpertBodyLimit); err != nil {
		if isMaxBytesErr(err) {
			return nil, http.StatusRequestEntityTooLarge, tooLarge
		}
		return nil, http.StatusBadRequest, &deny{code: "parse_failed", message: "表单解析失败：" + err.Error()}
	}
	// The 8 MiB cap keeps every part in memory; RemoveAll is a defensive
	// cleanup for the (currently impossible) spill-to-tempfile case.
	defer func() { _ = r.MultipartForm.RemoveAll() }()

	in := &ruleExpertInput{
		SourceType: strings.TrimSpace(r.FormValue("source_type")),
		Filename:   strings.TrimSpace(r.FormValue("filename")),
	}
	if in.SourceType == "" {
		in.SourceType = docextract.SourceText
	}
	switch in.SourceType {
	case docextract.SourceText:
		in.Text = r.FormValue("text")
		if overBudget(len(in.Text)) {
			return nil, http.StatusRequestEntityTooLarge, &deny{
				code:    "input_too_large",
				message: "粘贴内容超过上限（" + itoaK(textBudget) + "），请精简后重试或调高 ai.rule_expert.max_input_bytes",
			}
		}
	case docextract.SourceFile:
		f, hdr, err := r.FormFile("file")
		if err != nil {
			return nil, http.StatusBadRequest, &deny{code: "unsupported_file", message: "请选择要解析的文件（PDF / Word(.docx) / Excel(.xlsx) / CSV / HTML / 文本）"}
		}
		defer f.Close()
		data, rerr := io.ReadAll(f)
		if rerr != nil {
			if isMaxBytesErr(rerr) {
				return nil, http.StatusRequestEntityTooLarge, tooLarge
			}
			return nil, http.StatusBadRequest, &deny{code: "parse_failed", message: "读取上传文件失败"}
		}
		in.Data, in.Filename = data, hdr.Filename
	case docextract.SourceURL:
		in.URL = strings.TrimSpace(r.FormValue("url"))
		in.AllowPrivate = truthy(r.FormValue("requires_external"))
		if in.URL == "" {
			return nil, http.StatusBadRequest, &deny{code: "fetch_failed", message: "请填写要抓取的链接"}
		}
	case docextract.SourceTable:
		in.Rows = []byte(r.FormValue("rows_json"))
		// The console also lets the table editor upload a .csv/.xlsx instead
		// of pasting rows; that file wins when present.
		if f, hdr, err := r.FormFile("file"); err == nil {
			defer f.Close()
			data, rerr := io.ReadAll(f)
			if rerr != nil {
				if isMaxBytesErr(rerr) {
					return nil, http.StatusRequestEntityTooLarge, tooLarge
				}
				return nil, http.StatusBadRequest, &deny{code: "parse_failed", message: "读取上传文件失败"}
			}
			in.Data, in.Filename = data, hdr.Filename
			in.Rows = nil
		}
		if len(in.Data) == 0 && len(in.Rows) == 0 {
			return nil, http.StatusBadRequest, &deny{code: "parse_failed", message: "请粘贴表格数据或上传 .csv / .xlsx 文件"}
		}
		if overBudget(len(in.Rows)) {
			return nil, http.StatusRequestEntityTooLarge, &deny{
				code:    "input_too_large",
				message: "表格内容超过上限（" + itoaK(textBudget) + "），请精简后重试",
			}
		}
	default:
		return nil, http.StatusBadRequest, &deny{code: "unsupported_file", message: "不支持的输入类型：" + in.SourceType + "（text|file|url|table）"}
	}
	return in, 0, nil
}

// itoaK renders a byte budget as "NKB" for user-facing messages.
func itoaK(n int) string {
	if n >= 1<<20 && n%(1<<20) == 0 {
		return itoa(n>>20) + "MB"
	}
	if n >= 1<<10 {
		return itoa(n>>10) + "KB"
	}
	return itoa(n) + "B"
}

// extractRuleExpertText runs the extractor under the 20s budget. The work
// happens in a goroutine because document parsing is CPU-bound and cannot be
// cancelled mid-parse; the caller gets a timeout answer while the parse winds
// down (its result is dropped, the channel is buffered).
func (s *Server) extractRuleExpertText(ctx context.Context, in *ruleExpertInput) (docextract.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, ruleExpertExtractLimit)
	defer cancel()

	type outcome struct {
		res docextract.Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := extractRuleExpertNow(ctx, in)
		done <- outcome{res: res, err: err}
	}()

	select {
	case o := <-done:
		return o.res, o.err
	case <-ctx.Done():
		return docextract.Result{}, errParseTimeout
	}
}

// extractRuleExpertNow dispatches on the source type. Pasted text goes through
// the document extractor under a synthetic .md name so it shares the 256KB /
// 500 行 / 8MB budgets instead of growing a second set of limits.
func extractRuleExpertNow(ctx context.Context, in *ruleExpertInput) (docextract.Result, error) {
	switch in.SourceType {
	case docextract.SourceText:
		res, err := docextract.ExtractFile("advisory.md", []byte(in.Text))
		if err != nil {
			return docextract.Result{}, err
		}
		res.SourceType = docextract.SourceText
		res.SourceName = in.Filename
		return res, nil
	case docextract.SourceFile:
		return docextract.ExtractFile(in.Filename, in.Data)
	case docextract.SourceURL:
		return docextract.ExtractURL(ctx, in.URL, in.AllowPrivate)
	case docextract.SourceTable:
		if len(in.Data) > 0 {
			return docextract.ExtractFile(in.Filename, in.Data)
		}
		return docextract.ExtractTable(in.Rows)
	}
	return docextract.Result{}, docextract.ErrUnsupported
}

// writeRuleExpertExtractErr maps an extraction failure to the documented code
// set: 413 input_too_large / 400 unsupported_file / 502 fetch_failed /
// 504 parse_timeout / 422 parse_failed.
func (s *Server) writeRuleExpertExtractErr(w http.ResponseWriter, in *ruleExpertInput, err error) {
	switch {
	case errors.Is(err, errParseTimeout):
		writeCodedErr(w, http.StatusGatewayTimeout, "parse_timeout", "解析超时（超过 20 秒），请精简内容后重试")
	case errors.Is(err, docextract.ErrTooLarge):
		writeCodedErr(w, http.StatusRequestEntityTooLarge, "input_too_large", err.Error())
	case errors.Is(err, docextract.ErrUnsupported),
		errors.Is(err, docextract.ErrDocLegacy),
		errors.Is(err, docextract.ErrXLSXLegacy):
		writeCodedErr(w, http.StatusBadRequest, "unsupported_file", err.Error())
	case errors.Is(err, docextract.ErrJSShell):
		// The page rendered its body client-side: no server-side parser can
		// reach it. Point the operator at the paths that do work.
		writeCodedErr(w, http.StatusUnprocessableEntity, "js_rendered", err.Error())
	case in != nil && in.SourceType == docextract.SourceURL:
		// Every URL failure is a retrieval problem from the operator's point
		// of view: bad link, blocked address, non-page content type or an
		// upstream error status.
		writeCodedErr(w, http.StatusBadGateway, "fetch_failed", "抓取失败："+fetchErrorMessage(err))
	default:
		writeCodedErr(w, http.StatusUnprocessableEntity, "parse_failed", "解析失败："+err.Error())
	}
}

// fetchErrorMessage translates the SSRF-guard sentinels into actionable text.
func fetchErrorMessage(err error) string {
	switch {
	case errors.Is(err, safefetch.ErrBadURL):
		return "链接格式不正确（仅支持 http/https 绝对地址，且不能内嵌账号密码）"
	case errors.Is(err, safefetch.ErrBlockedTarget):
		return "目标地址不被允许（内网/回环/链路本地地址默认拦截；内网源请勾选 requires_external）"
	case errors.Is(err, safefetch.ErrRedirectRejected):
		return "跳转目标被安全策略拒绝"
	case errors.Is(err, safefetch.ErrBodyTooLarge):
		return "目标页面超过大小上限"
	case errors.Is(err, safefetch.ErrContentType):
		return "目标返回的内容不是可解析的网页或文本"
	case errors.Is(err, context.DeadlineExceeded):
		return "抓取超时，请稍后重试"
	}
	return err.Error()
}

// handleRuleExpertExtract serves POST /api/policy/rule-expert/extract: it only
// extracts text (no model call, no AI quota consumed) so the console can show
// the operator what the model will actually see.
func (s *Server) handleRuleExpertExtract(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	_, limits, ok := s.ruleExpertEnabled(w)
	if !ok {
		return
	}
	start := time.Now()
	in, status, refusal := s.parseRuleExpertInput(w, r, limits.MaxInputBytes)
	if in == nil {
		writeCodedErr(w, status, refusal.code, refusal.message)
		return
	}
	if in.SourceType == docextract.SourceURL {
		if d := s.ruleExpertLimit.allowExtractURL(ruleExpertUser(r)); d != nil {
			w.Header().Set("Retry-After", "60")
			writeCodedErr(w, http.StatusTooManyRequests, d.code, d.message)
			return
		}
	}
	// Images have no text layer to preview: the multimodal model reads them
	// inside the generation call itself (no separate OCR stage).
	if in.SourceType == docextract.SourceFile {
		if _, ok := ruleexpert.ImageMIME(in.Filename, in.Data); ok {
			writeCodedErr(w, http.StatusBadRequest, "image_passthrough",
				"图片无需解析：直接点击「生成规则」，由多模态模型直接读取图片内容")
			return
		}
	}
	res, err := s.extractRuleExpertText(r.Context(), in)
	if err != nil {
		slog.Info("rule expert extract failed", "user", ruleExpertUser(r),
			"source_type", in.SourceType, "elapsed_ms", time.Since(start).Milliseconds())
		s.writeRuleExpertExtractErr(w, in, err)
		return
	}
	slog.Info("rule expert extract", "user", ruleExpertUser(r), "source_type", in.SourceType,
		"chars", res.Chars, "truncated", res.Truncated, "elapsed_ms", time.Since(start).Milliseconds())
	writeJSON(w, http.StatusOK, map[string]any{
		"text":        res.Text,
		"source_type": res.SourceType,
		"source_name": res.SourceName,
		"chars":       res.Chars,
		"truncated":   res.Truncated,
		"warnings":    res.Warnings,
	})
}

// retryableAIErr reports whether a model-call failure is worth retrying:
// upstream 5xx / empty completion / quota-churn are transient on aggregation
// pools, while 4xx (bad key, bad request) never heal by retrying.
func retryableAIErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, s := range []string{"upstream_unavailable", "status 502", "status 503", "status 504", "模型未返回内容", "llm status 5"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// handleRuleExpert serves POST /api/policy/rule-expert: advisory → SecLang.
func (s *Server) handleRuleExpert(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	svc, limits, ok := s.ruleExpertEnabled(w)
	if !ok {
		return
	}
	if keySet, _ := svc.Config()["api_key_set"].(bool); !keySet {
		writeCodedErr(w, http.StatusNotFound, "ai_disabled", "规则专家未启用：尚未配置模型 API Key（设置 → AI 助手）")
		return
	}

	start := time.Now()
	in, status, refusal := s.parseRuleExpertInput(w, r, limits.MaxInputBytes)
	if in == nil {
		writeCodedErr(w, status, refusal.code, refusal.message)
		return
	}

	// Image uploads (screenshot / scanned advisory page) skip text extraction
	// entirely: the multimodal model reads the image directly in the SAME
	// generation call (no separate OCR stage). Magic bytes decide, not the
	// extension alone, so a renamed file cannot smuggle a binary through.
	var visionURL string
	if in.SourceType == docextract.SourceFile {
		if mime, ok := ruleexpert.ImageMIME(in.Filename, in.Data); ok {
			visionURL = "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(in.Data)
		}
	}

	// Resolve the advisory text: pasted text is used as-is, images go to the
	// vision path, every other source goes through the shared extractor first.
	text := strings.TrimSpace(in.Text)
	var extracted *docextract.Result
	if visionURL != "" {
		text = ruleexpert.VisionLeadText
		extracted = &docextract.Result{SourceType: docextract.SourceFile, SourceName: in.Filename}
	} else if in.SourceType != docextract.SourceText {
		if in.SourceType == docextract.SourceURL {
			if d := s.ruleExpertLimit.allowExtractURL(ruleExpertUser(r)); d != nil {
				w.Header().Set("Retry-After", "60")
				writeCodedErr(w, http.StatusTooManyRequests, d.code, d.message)
				return
			}
		}
		res, err := s.extractRuleExpertText(r.Context(), in)
		if err != nil {
			slog.Info("rule expert extract failed", "user", ruleExpertUser(r),
				"source_type", in.SourceType, "elapsed_ms", time.Since(start).Milliseconds())
			s.writeRuleExpertExtractErr(w, in, err)
			return
		}
		extracted = &res
		text = res.Text
	}
	if text == "" {
		writeCodedErr(w, http.StatusBadRequest, "parse_failed", "待生成文本为空，请粘贴漏洞通告正文或先解析文件")
		return
	}

	user := ruleExpertUser(r)
	if d := s.ruleExpertLimit.allowGenerate(user, limits); d != nil {
		w.Header().Set("Retry-After", "60")
		writeCodedErr(w, http.StatusTooManyRequests, d.code, d.message)
		return
	}

	system, userPrompt := ruleexpert.BuildPrompt(text)
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(limits.TimeoutSec)*time.Second)
	defer cancel()
	var content string
	var promptTokens, completionTokens int
	var err error
	// Upstream aggregation pools are flaky ("免费资源池额度已用完" 502s and
	// empty completions are transient); retry the model call a couple of times
	// with a short backoff before surfacing the failure to the operator.
	gen := func() (string, int, int, error) {
		if visionURL != "" {
			return svc.CompleteImage(ctx, system, userPrompt, visionURL, ruleexpert.MaxOutputTokens)
		}
		return svc.Complete(ctx, system, userPrompt, ruleexpert.MaxOutputTokens)
	}
	content, promptTokens, completionTokens, err = gen()
	for attempt := 1; attempt <= 2 && err != nil && retryableAIErr(err); attempt++ {
		select {
		case <-time.After(time.Duration(attempt) * 1500 * time.Millisecond):
		case <-ctx.Done():
			break
		}
		slog.Info("rule expert retrying model call", "attempt", attempt, "err", err)
		content, promptTokens, completionTokens, err = gen()
	}
	s.ruleExpertLimit.addTokens(user, int64(promptTokens+completionTokens))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			writeCodedErr(w, http.StatusGatewayTimeout, "ai_timeout",
				"生成超时（超过 "+itoa(limits.TimeoutSec)+" 秒），请稍后重试或精简输入")
			return
		}
		slog.Warn("rule expert generation failed", "user", user, "source_type", in.SourceType,
			"elapsed_ms", time.Since(start).Milliseconds(), "err", err)
		writeCodedErr(w, http.StatusBadGateway, "ai_failed", "模型调用失败："+err.Error())
		return
	}

	rule, notes, warnings, perr := ruleexpert.ParseResponse(content)
	if perr != nil {
		slog.Info("rule expert no rule parsed", "user", user, "source_type", in.SourceType,
			"elapsed_ms", time.Since(start).Milliseconds())
		writeCodedErr(w, http.StatusUnprocessableEntity, "no_rule_generated",
			"未能从模型返回中解析出有效 SecLang 规则，请补充漏洞细节（产品、版本、参数、攻击路径）后重试")
		return
	}
	warnings = append(warnings, ruleexpert.Precheck(rule)...)
	if completionTokens >= ruleexpert.MaxOutputTokens {
		warnings = append(warnings, fmt.Sprintf("模型输出达到上限（%d tokens），规则可能被截断：请精简通告后重试，或分批生成", ruleexpert.MaxOutputTokens))
	}
	needRequests, needTokens := s.ruleExpertLimit.remaining(user, limits)

	resp := map[string]any{
		"rule":     rule,
		"notes":    notes,
		"warnings": warnings,
		"model":    svc.ModelName(),
		"usage": map[string]int{
			"prompt_tokens":     promptTokens,
			"completion_tokens": completionTokens,
		},
		"remaining": map[string]any{
			"requests_today": needRequests,
			"tokens_today":   needTokens,
		},
	}
	if extracted != nil {
		// Metadata only: the extracted body never comes back in the response.
		resp["extracted"] = map[string]any{
			"source_type": extracted.SourceType,
			"source_name": extracted.SourceName,
			"chars":       extracted.Chars,
			"truncated":   extracted.Truncated,
		}
	}
	slog.Info("rule expert generated", "user", user, "source_type", in.SourceType,
		"chars", len(text), "rule_bytes", len(rule),
		"prompt_tokens", promptTokens, "completion_tokens", completionTokens,
		"elapsed_ms", time.Since(start).Milliseconds())
	writeJSON(w, http.StatusOK, resp)
}

// ruleExpertEnabled resolves the live service and its limits, answering 404
// ai_disabled when the assistant is off or the rule expert is switched off.
func (s *Server) ruleExpertEnabled(w http.ResponseWriter) (*ai.Service, ai.RuleExpertSettings, bool) {
	svc := s.ai()
	if svc == nil {
		writeCodedErr(w, http.StatusNotFound, "ai_disabled", "规则专家未启用：请先在设置中启用 AI 助手")
		return nil, ai.RuleExpertSettings{}, false
	}
	limits := svc.RuleExpert()
	if !limits.EnabledOrDefault() {
		writeCodedErr(w, http.StatusNotFound, "ai_disabled", "规则专家已被管理员关闭（ai.rule_expert.enabled）")
		return nil, ai.RuleExpertSettings{}, false
	}
	return svc, limits, true
}
