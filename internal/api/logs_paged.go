package api

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/kingmoat/kingmoat/internal/logstore"
)

// logsPageResponse is the paginated console log view payload.
type logsPageResponse struct {
	Items    []logstore.Event `json:"items"`
	Total    int              `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
}

// parseLogQuery extracts the shared filter parameters (action, site, rule,
// ip, q, since, until) from the request.
func parseLogQuery(qp url.Values) (logstore.LogQuery, bool) {
	var q logstore.LogQuery
	filtered := false
	if v := qp.Get("action"); v != "" {
		q.Action, filtered = v, true
	}
	if v := qp.Get("site"); v != "" {
		q.Site, filtered = v, true
	}
	if v := qp.Get("rule"); v != "" {
		q.Rule, filtered = v, true
	}
	if v := qp.Get("ip"); v != "" {
		q.SrcIP, filtered = v, true
	}
	if v := qp.Get("q"); v != "" {
		q.Text, filtered = v, true
	}
	if v := qp.Get("trace_id"); v != "" {
		q.TraceID, filtered = v, true
	}
	if v := qp.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.Since, filtered = t, true
		}
	}
	if v := qp.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.Until, filtered = t, true
		}
	}
	return q, filtered
}

// logsGate wraps the audit-query gate shared by the export handler.
func (s *Server) logsGate(w http.ResponseWriter) (func(), time.Duration, bool) {
	_, cfg := s.opts.Center.Current()
	release, timeout, ok := s.auditQueryGate(cfg)
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":    "log query degraded: audit queries are temporarily disabled (emergency mode); traffic forwarding is unaffected",
			"degraded": true,
		})
		return nil, 0, false
	}
	return release, timeout, true
}

// handleLogsExport streams filtered audit events as NDJSON
// (GET /api/logs/export). Caps at 50k rows so a runaway export cannot pin
// the read pool.
func (s *Server) handleLogsExport(w http.ResponseWriter, r *http.Request) {
	release, timeout, ok := s.logsGate(w)
	if !ok {
		return
	}
	defer release()

	qp := r.URL.Query()
	q, _ := parseLogQuery(qp)
	q.Limit = 1000
	if v := qp.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 50000 {
			q.Limit = n
		}
	}
	srch, _ := s.opts.Logs.(logstore.Searcher)
	if srch == nil {
		writeErr(w, http.StatusNotImplemented, simpleError("当前日志存储不支持导出"))
		return
	}

	type result struct {
		evs []logstore.Event
		err error
	}
	done := make(chan result, 1)
	go func() {
		evs, err := srch.Query(q)
		done <- result{evs, err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			writeErr(w, http.StatusInternalServerError, res.err)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="kingmoat-attacks.ndjson"`)
		w.WriteHeader(http.StatusOK)
		bw := bufio.NewWriter(w)
		enc := json.NewEncoder(bw)
		for _, ev := range res.evs {
			_ = enc.Encode(ev)
		}
		_ = bw.Flush()
	case <-time.After(timeout):
		writeErr(w, http.StatusGatewayTimeout, simpleError("日志导出超时，请重试"))
	}
}

// handleLogshipTest probes the configured log-shipper sink connectivity
// (POST /api/logship/test). Backward-compatible facade: it delegates to the
// unified outbound-test runner with kind pinned to "audit" (the body kind is
// ignored), so both endpoints share the operator gate, the global
// single-flight limit, the ~8s budget and the change-audit entry. The
// response keeps the legacy fields (ok / type / latency_ms / detail) and
// appends the three-state fields (state / reason / checks, see
// outbound_probe.go); ok=true covers ok and degraded, and 401/403 no longer
// pass as healthy.
func (s *Server) handleLogshipTest(w http.ResponseWriter, r *http.Request) {
	s.runOutboundTest(w, r, "audit")
}
