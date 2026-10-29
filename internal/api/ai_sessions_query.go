// AI session audit query API: the console list/detail view reads the central
// AI session store (fleet management plane) or answers unconfigured with an
// empty payload. Auditor+ role required.
package api

import (
	"net/http"
	"strconv"

	"github.com/kingmoat/kingmoat/internal/aisession"
	"github.com/kingmoat/kingmoat/internal/store"
)

// handleAISessionAudit serves GET /api/ai_sessions
// (?site=&provider=&q=&limit=&offset=) — the captured LLM traffic audit list
// (distinct from /api/ai/sessions, the AI assistant's own chat history).
func (s *Server) handleAISessionAudit(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAuditor) {
		return
	}
	central := s.opts.AICentralFn()
	if central == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"items":   []any{},
			"total":   0,
		})
		return
	}
	qp := r.URL.Query()
	limit := 100
	if v := qp.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	offset := 0
	if v := qp.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	items, total, err := central.List(aisession.AIQuery{
		Site:     qp.Get("site"),
		Provider: qp.Get("provider"),
		Keyword:  qp.Get("q"),
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"items":   items,
		"total":   total,
	})
}
