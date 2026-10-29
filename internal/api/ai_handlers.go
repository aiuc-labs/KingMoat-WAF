package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"io"
	"strings"
	"unicode/utf8"

	"github.com/kingmoat/kingmoat/internal/ai"
	"github.com/kingmoat/kingmoat/internal/docextract"
	"github.com/kingmoat/kingmoat/internal/store"
)

// AI handlers: thin proxies over *ai.Service (nil = module disabled).

func (s *Server) aiDisabled(w http.ResponseWriter) {
	writeErr(w, http.StatusNotFound, simpleError("AI 助手未启用"))
}

// handleAIConfig serves GET /api/ai/config. "enabled" reports EFFECTIVE
// availability: the assistant is configured on AND an API key actually
// resolves (stored cipher / env var / inline literal). Without a usable key
// every chat would fail, so the console must show 未启用 instead of a
// half-working assistant; key_source keeps the resolved source for the
// settings-page badge (stored/env/inline/none).
func (s *Server) handleAIConfig(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "templates": ai.Templates()})
		return
	}
	cfg := s.ai().Config()
	if set, _ := cfg["api_key_set"].(bool); !set {
		cfg["enabled"] = false
	}
	cfg["templates"] = ai.Templates()
	writeJSON(w, http.StatusOK, cfg)
}

// handleAIChat serves POST /api/ai/chat (SSE).
func (s *Server) handleAIChat(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	owner := ""
	if u := userFromContext(r); u != nil {
		owner = u.Username
	}
	s.ai().HandleChat(w, r, owner)
}

// maxChatAttachmentBytes / maxChatAttachmentText bound one chat attachment:
// 8 MiB upload, 64 KiB of prompt text (the model context and the daily token
// budget both thank you). Extraction reuses internal/docextract, the same
// parser set the rule expert uses.
const (
	maxChatAttachmentBytes = 8 << 20
	maxChatAttachmentText  = 64 << 10
)

// handleAIExtract serves POST /api/ai/extract (multipart "file"): documents are
// turned into plain text for the chat composer. Images are NOT handled here —
// they keep riding the vision path (data URLs in /api/ai/chat) because the
// multimodal model reads them directly.
func (s *Server) handleAIExtract(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		writeCodedErr(w, http.StatusBadRequest, "missing_file", "未收到附件文件（需 multipart 上传）")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxChatAttachmentBytes)
	if err := r.ParseMultipartForm(maxChatAttachmentBytes); err != nil {
		writeCodedErr(w, http.StatusRequestEntityTooLarge, "input_too_large", "附件超过 8MB 上限或表单格式错误")
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeCodedErr(w, http.StatusBadRequest, "missing_file", "未收到附件文件")
		return
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxChatAttachmentBytes))
	if err != nil {
		writeCodedErr(w, http.StatusBadRequest, "read_failed", "读取附件失败")
		return
	}
	res, err := docextract.ExtractFile(hdr.Filename, data)
	if err != nil {
		msg := "无法解析该文件：" + err.Error()
		if errors.Is(err, docextract.ErrPDFEncrypted) || errors.Is(err, docextract.ErrPDFNoText) {
			msg = "无法从该 PDF 提取文本（扫描件/加密）；可直接上传图片，由多模态模型识别"
		}
		writeCodedErr(w, http.StatusUnprocessableEntity, "parse_failed", msg)
		return
	}
	text := strings.TrimSpace(res.Text)
	if text == "" {
		writeCodedErr(w, http.StatusUnprocessableEntity, "parse_failed", "未检测到可解析文本")
		return
	}
	truncated := false
	if len(text) > maxChatAttachmentText {
		cut := maxChatAttachmentText
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text = text[:cut] + "\n\n[附件内容过长，已截断]"
		truncated = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":      hdr.Filename,
		"text":      text,
		"chars":     utf8.RuneCountInString(text),
		"truncated": truncated,
	})
}

// canAccessSession reports whether the requester may read/delete the
// session: authless deployments skip the check; admins see everything;
// everyone else only their own sessions (legacy owner='' rows are admin-only).
func (s *Server) canAccessSession(r *http.Request, id string) bool {
	u := userFromContext(r)
	if u == nil || u.Role == store.RoleAdmin {
		return true
	}
	own, err := s.ai().SessionOwner(id)
	return err == nil && own == u.Username
}

// handleAISessions serves GET /api/ai/sessions.
func (s *Server) handleAISessions(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	owner := ""
	if u := userFromContext(r); u != nil && u.Role != store.RoleAdmin {
		owner = u.Username
	}
	sessions, err := s.ai().ListSessions(100, owner)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

// handleAISessionMessages serves GET /api/ai/sessions/{id}/messages.
func (s *Server) handleAISessionMessages(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	if !s.canAccessSession(r, r.PathValue("id")) {
		writeErr(w, http.StatusForbidden, simpleError("无权访问该会话"))
		return
	}
	msgs, err := s.ai().SessionMessages(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, msgs)
}

// handleAISessionDelete serves DELETE /api/ai/sessions/{id}.
func (s *Server) handleAISessionDelete(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	if !s.canAccessSession(r, r.PathValue("id")) {
		writeErr(w, http.StatusForbidden, simpleError("无权访问该会话"))
		return
	}
	if err := s.ai().DeleteSession(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAIReports serves GET /api/ai/reports.
func (s *Server) handleAIReports(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	reports, err := s.ai().ListReports(100)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, reports)
}

// handleAIReportGet serves GET /api/ai/reports/{id}.
func (s *Server) handleAIReportGet(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, simpleError("报告 ID 无效"))
		return
	}
	rep, err := s.ai().GetReport(id)
	if err != nil {
		// Unknown id is the only client-facing fact; a transient store
		// failure must not masquerade as "the report was cleaned up".
		if errors.Is(err, ai.ErrReportNotFound) {
			writeErr(w, http.StatusNotFound, simpleError("报告不存在或已被清理"))
			return
		}
		slog.Error("api: ai report read failed", "id", id, "err", err)
		writeErr(w, http.StatusInternalServerError, simpleError("报告数据读取失败，详情见服务端日志"))
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleAIReportRun serves POST /api/ai/reports/run {"kind": "..."}.
func (s *Server) handleAIReportRun(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	var req struct {
		Kind string `json:"kind"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	window := 24 * time.Hour
	if req.Kind == "attack_summary_weekly" {
		window = 7 * 24 * time.Hour
	}
	id, err := s.ai().RunReport(req.Kind, "manual", window, ai.Delivery{})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

// ai returns the live assistant instance (nil = disabled); the entrypoint
// swaps the instance on hot reload when the ai config toggles.
func (s *Server) ai() *ai.Service {
	if s.aiFn == nil {
		return nil
	}
	return s.aiFn()
}

// handleMCPForward routes MCP requests to the live assistant instance.
func (s *Server) handleMCPForward(w http.ResponseWriter, r *http.Request) {
	svc := s.ai()
	if svc == nil || !svc.MCPEnabled() {
		writeErr(w, http.StatusNotFound, simpleError("AI 助手未启用"))
		return
	}
	svc.MCPHandler(s.opts.Version).ServeHTTP(w, r)
}
