// Policy-page rule-hit analytics: /api/stats/rules ranks the most-hit rules
// over a bounded window (SQL aggregation on the SQLite audit store), feeding
// the micro-engine tab statistics card and one-click drill-down to the log
// view (?rule=<id>).
package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/store"
)

// ruleHitItem is one ranked rule entry of the /api/stats/rules payload.
type ruleHitItem struct {
	Rule  string `json:"rule"`
	Count int    `json:"count"`
}

// rulesStatsResponse is the /api/stats/rules payload: total is the number of
// attack events in the window under the same criteria as items (unbounded by
// the top limit).
type rulesStatsResponse struct {
	Total int64         `json:"total"`
	Items []ruleHitItem `json:"items"`
}

// handleStatsRules serves GET /api/stats/rules?hours=24&limit=10
// (hours: 1..720 default 24; limit: 1..50 default 10).
func (s *Server) handleStatsRules(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n := atoiSafe2(v); n > 0 {
			hours = n
		}
	}
	if hours > 720 {
		hours = 720
	}
	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		if n := atoiSafe2(v); n > 0 {
			limit = n
		}
	}
	if limit > 50 {
		limit = 50
	}
	until := time.Now()
	since := until.Add(-time.Duration(hours) * time.Hour)

	out := rulesStatsResponse{Items: []ruleHitItem{}}
	if s.opts.Logs == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	top, ok := s.opts.Logs.(logstore.RuleTopHitter)
	if !ok {
		writeJSON(w, http.StatusOK, out)
		return
	}
	_, cfg := s.opts.Center.Current()
	release, timeout, gated := s.auditQueryGate(cfg)
	if !gated {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":    "log query degraded: audit queries are temporarily disabled (emergency mode); traffic forwarding is unaffected",
			"degraded": true,
		})
		return
	}
	defer release()
	type ruleResult struct {
		hits  []logstore.TopHit
		total int64
		err   error
	}
	done := make(chan ruleResult, 1)
	go func() {
		hits, total, err := top.RuleTopHits(since, until, limit)
		done <- ruleResult{hits, total, err}
	}()
	var res ruleResult
	select {
	case res = <-done:
	case <-time.After(timeout):
		writeJSON(w, http.StatusGatewayTimeout, map[string]any{
			"error": "rule stats query timed out; narrow the window or ship logs to an external store",
		})
		return
	}
	if res.err != nil {
		writeErr(w, http.StatusInternalServerError, res.err)
		return
	}
	out.Total = res.total
	for _, h := range res.hits {
		out.Items = append(out.Items, ruleHitItem{Rule: h.Key, Count: h.Count})
	}
	writeJSON(w, http.StatusOK, out)
}

// customRuleHitItem is one custom rule's hit count in the window.
type customRuleHitItem struct {
	ID    int    `json:"id"`
	Rule  string `json:"rule"`
	Count int    `json:"count"`
}

// handleCustomRuleHits serves GET /api/policy/custom-rules/hits?hours=24:
// per-rule hit counts for the console's custom rules list (ids inside the
// 100000-199999 console range). Ranking rides the same SQL aggregation the
// micro-engine stats card uses; CRS noise is filtered out by the id window.
func (s *Server) handleCustomRuleHits(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n := atoiSafe2(v); n > 0 {
			hours = n
		}
	}
	if hours > 720 {
		hours = 720
	}
	out := map[string]any{"hours": hours, "total": int64(0), "items": []customRuleHitItem{}}
	if s.opts.Logs == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	until := time.Now()
	since := until.Add(-time.Duration(hours) * time.Hour)
	_, cfg := s.opts.Center.Current()
	release, timeout, gated := s.auditQueryGate(cfg)
	if !gated {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "log query degraded", "degraded": true})
		return
	}
	defer release()
	type res struct {
		hits  []logstore.TopHit
		total int64
		err   error
	}
	done := make(chan res, 1)
	go func() {
		hits, total, err := ruleTopHits(s.opts.Logs, since, until, 500)
		done <- res{hits, total, err}
	}()
	var rr res
	select {
	case rr = <-done:
	case <-time.After(timeout):
		writeJSON(w, http.StatusGatewayTimeout, map[string]any{"error": "rule stats query timed out"})
		return
	}
	if rr.err != nil {
		writeErr(w, http.StatusInternalServerError, rr.err)
		return
	}
	items := []customRuleHitItem{}
	for _, h := range rr.hits {
		id := customRuleIDFromKey(h.Key)
		if id == 0 {
			continue
		}
		items = append(items, customRuleHitItem{ID: id, Rule: h.Key, Count: h.Count})
	}
	out["items"] = items
	out["total"] = rr.total
	writeJSON(w, http.StatusOK, out)
}

// ruleTopHits ranks the window's most-hit rules through the node-scoped
// interface when the store offers it (nodeID "" = every engine this instance
// aggregates) and falls back to the plain 3-argument contract otherwise.
func ruleTopHits(logs logstore.Queryable, since, until time.Time, topN int) ([]logstore.TopHit, int64, error) {
	if nodeTop, ok := logs.(logstore.RuleTopHitterNode); ok {
		return nodeTop.RuleTopHitsNode(since, until, topN, "")
	}
	if top, ok := logs.(logstore.RuleTopHitter); ok {
		return top.RuleTopHits(since, until, topN)
	}
	return nil, 0, nil
}

// customRuleIDFromKey extracts the console id from a rule key such as
// "coraza/rule-100777" (or a bare "rule-100777") and returns 0 for anything
// outside the custom range.
func customRuleIDFromKey(key string) int {
	i := strings.LastIndex(key, "rule-")
	if i < 0 {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(key[i+len("rule-"):]))
	if err != nil || n < 100000 || n > 199999 {
		return 0
	}
	return n
}
