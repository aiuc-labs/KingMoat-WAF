// Strategy-page APIs: false-positive whitelisting (log one-click whitelist →
// micro-engine allow rule), legacy false-positive exceptions (deprecated,
// kept only for migration), IP-group subscription management and
// interception-page copy. Changes publish a new config revision (hot reload,
// rollback-able).
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/coraza"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/ipgroups"
	"github.com/kingmoat/kingmoat/internal/store"
)

// customRuleTestReq is the body of POST /api/policy/custom-rules/test.
type customRuleTestReq struct {
	Rules   string            `json:"rules"`
	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path,omitempty"`
	Query   string            `json:"query,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// handleCustomRuleTest serves POST /api/policy/custom-rules/test: it compiles
// the pasted SecLang twice (rules-only and full CRS) and runs ONE synthetic
// request through each, so an operator can tell "my rule does not fire" from
// "CRS already blocked it upstream of my rule" BEFORE publishing.
func (s *Server) handleCustomRuleTest(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	var req customRuleTestReq
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	res, err := coraza.TestCustomRules(req.Rules, coraza.TestRequest{
		Method: req.Method, Path: req.Path, Query: req.Query,
		Headers: req.Headers, Body: req.Body,
	}, slog.Default())
	if err != nil {
		writeCodedErr(w, http.StatusUnprocessableEntity, "rule_invalid", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// whitelistReq is the body of POST /api/policy/whitelist.
type whitelistReq struct {
	Site    string `json:"site"`            // domain; empty = all sites (legacy entries)
	Path    string `json:"path"`            // exact path or prefix
	Prefix  bool   `json:"prefix,omitempty"` // true → prefix condition
	Comment string `json:"comment,omitempty"`
	// BodyStream additionally declares the path as a deep-inspection-prefix
	// (upload) path on the target site: over-limit bodies then deep-inspect
	// body_limit_bytes and stream the remainder instead of answering 413.
	// Requires a concrete site (the declaration lives in sites[].waf).
	BodyStream bool `json:"body_stream,omitempty"`
}

// streamPrefix normalises a whitelisted request path into a
// body_stream_paths entry: query/fragment are cut (paths are matched without
// them) and leading/trailing space is trimmed. The caller has already
// required a leading "/".
func streamPrefix(path string) string {
	p := strings.TrimSpace(path)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return strings.TrimSpace(p)
}

// siteByDomain returns the site that serves the given domain (case-insensitive
// across all its domains), or nil.
func siteByDomain(sites []config.Site, domain string) *config.Site {
	for i := range sites {
		for _, d := range sites[i].Domains {
			if strings.EqualFold(d, domain) {
				return &sites[i]
			}
		}
	}
	return nil
}

// cloneConfig deep-copies the shared active config via JSON round-trip (the
// same serialization the config center stores) so handlers never mutate the
// shared pointer in place: a failed Publish must leave the live config and
// concurrent Current() readers untouched.
func cloneConfig(cfg *config.Config) (*config.Config, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("配置序列化失败：%w", err)
	}
	out := &config.Config{}
	if err := json.Unmarshal(b, out); err != nil {
		return nil, fmt.Errorf("配置反序列化失败：%w", err)
	}
	return out, nil
}

// isWhitelistDuplicate reports whether an existing allow rule already covers
// site+path+match-mode (idempotency check for POST /api/policy/whitelist).
func isWhitelistDuplicate(rules []config.MatcherRule, site, path string, prefix bool) bool {
	op := config.OpEq
	if prefix {
		op = config.OpPrefix
	}
	for _, m := range rules {
		if m.Action != config.ActionAllow {
			continue
		}
		if len(m.Sites) != 1 || !strings.EqualFold(m.Sites[0], site) {
			continue
		}
		if len(m.Conditions) != 1 {
			continue
		}
		c := m.Conditions[0]
		if c.Field == config.FieldPath && c.Op == op && c.Value == path {
			return true
		}
	}
	return false
}

// whitelistRuleName builds the rule display name, suffixing " #N" when the
// base name already exists (repeated whitelists on one site stay unique).
func whitelistRuleName(rules []config.MatcherRule, site, path string) string {
	base := "误报加白: " + site + path
	taken := map[string]bool{}
	for _, m := range rules {
		taken[m.Name] = true
	}
	if !taken[base] {
		return base
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s #%d", base, n)
		if !taken[candidate] {
			return candidate
		}
	}
}

// handlePolicyWhitelist serves POST /api/policy/whitelist {site, path,
// prefix, comment} (operator+): creates a micro-engine allow rule (site +
// path condition, action=allow → the whole detection chain is skipped for
// that path) and publishes. Idempotent: an existing allow rule with the same
// site+path+match-mode returns {ok, unchanged:true} without a new revision.
// The config is deep-copied before mutation; the shared active config is
// never modified in place.
func (s *Server) handlePolicyWhitelist(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	var req whitelistReq
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	site := strings.ToLower(strings.TrimSpace(req.Site))
	path := strings.TrimSpace(req.Path)
	if path == "" || !strings.HasPrefix(path, "/") {
		writeErr(w, http.StatusBadRequest, simpleError("路径不能为空，且必须以 / 开头"))
		return
	}
	_, cfg := s.opts.Center.Current()
	clone, err := cloneConfig(cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if clone.Policy == nil {
		clone.Policy = &config.Policy{}
	}
	dupRule := isWhitelistDuplicate(clone.Policy.Matchers, site, path, req.Prefix)
	// Body-stream linkage: one publish carries both the allow rule and the
	// site's deep-inspection-prefix declaration, so an upload path stops
	// answering 413 in the same revision the operator whitelisted it.
	var streamSite *config.Site
	streamPath := ""
	streamNeeded := false
	if req.BodyStream {
		if site == "" {
			writeErr(w, http.StatusBadRequest, simpleError("同时设为深检前缀需要指定站点"))
			return
		}
		streamSite = siteByDomain(clone.Sites, site)
		if streamSite == nil {
			writeErr(w, http.StatusNotFound, simpleError("站点不存在："+site))
			return
		}
		streamPath = streamPrefix(path)
		if streamPath == "" || streamPath == "/" {
			writeErr(w, http.StatusBadRequest, simpleError("深检前缀不能为站点根路径 /"))
			return
		}
		if streamSite.WAF != nil {
			present := false
			for _, p := range streamSite.WAF.BodyStreamPaths {
				if p == streamPath {
					present = true
					break
				}
			}
			if !present && len(streamSite.WAF.BodyStreamPaths) >= config.MaxBodyStreamPaths {
				writeErr(w, http.StatusBadRequest, simpleError("该站点深检前缀路径已达上限（64 条）"))
				return
			}
			streamNeeded = !present
		} else {
			streamNeeded = true
		}
	}
	if dupRule && !streamNeeded {
		rev, _ := s.opts.Center.Current()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "unchanged": true, "revision": rev})
		return
	}
	var rule config.MatcherRule
	if !dupRule {
		rule = config.MatcherRule{
			Name:    whitelistRuleName(clone.Policy.Matchers, site, path),
			Enabled: true,
			Action:  config.ActionAllow,
			Logic:   "and",
			Conditions: []config.MatcherCondition{{
				Field: config.FieldPath,
				Op:    config.OpEq,
				Value: path,
			}},
			Comment: "误报加白",
		}
		if req.Prefix {
			rule.Conditions[0].Op = config.OpPrefix
		}
		if site != "" {
			rule.Sites = []string{site}
		} // else Sites stays nil = all sites (legacy exception entries)
		if comment := strings.TrimSpace(req.Comment); comment != "" {
			rule.Comment = "误报加白：" + comment
		}
		if err := rule.Validate(); err != nil {
			writeErr(w, http.StatusBadRequest, wrapConfigErr(err))
			return
		}
		clone.Policy.Matchers = append(clone.Policy.Matchers, rule)
	}
	if streamNeeded {
		if streamSite.WAF == nil {
			streamSite.WAF = &config.WAFSettings{}
		}
		streamSite.WAF.BodyStreamPaths = append(streamSite.WAF.BodyStreamPaths, streamPath)
	}
	note := fmt.Sprintf("whitelist: %s %s", site, path)
	if streamNeeded {
		note += " (+body stream " + streamPath + ")"
	}
	newRev, err := s.opts.Center.Publish(clone, s.author(r), note)
	if err != nil {
		if errors.Is(err, configcenter.ErrNoChanges) {
			rev, _ := s.opts.Center.Current()
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "unchanged": true, "revision": rev})
			return
		}
		writeErr(w, http.StatusBadRequest, wrapConfigErr(err))
		return
	}
	if !dupRule {
		s.recordChange(r, "policy.whitelist", site+path, "micro-engine allow rule created: "+rule.Name)
	}
	if streamNeeded {
		s.recordChange(r, "policy.whitelist", site+streamPath, "body stream prefix declared (413 bypass for uploads): "+streamPath)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "unchanged": false, "revision": newRev, "name": rule.Name, "body_stream": streamNeeded})
}

// handleExceptionList returns the configured false-positive exceptions.
//
// Deprecated: exceptions are superseded by micro-engine allow rules created
// via POST /api/policy/whitelist. Kept (read/write) only so the console can
// migrate legacy entries; new integrations must not use this endpoint.
func (s *Server) handleExceptionList(w http.ResponseWriter, r *http.Request) {
	_, cfg := s.opts.Center.Current()
	var list []config.Exception
	if cfg.Policy != nil {
		list = cfg.Policy.Exceptions
	}
	if list == nil {
		list = []config.Exception{}
	}
	writeJSON(w, http.StatusOK, list)
}

// handleExceptionCreate appends an exception and publishes.
func (s *Server) handleExceptionCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	var e config.Exception
	if err := decodeBody(r, &e); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := e.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, wrapConfigErr(err))
		return
	}
	rev, cfg := s.opts.Center.Current()
	if cfg.Policy == nil {
		cfg.Policy = &config.Policy{}
	}
	cfg.Policy.Exceptions = append(cfg.Policy.Exceptions, e)
	newRev, err := s.opts.Center.Publish(cfg, s.author(r), fmt.Sprintf("exception: %s%s (%s)", e.Site, e.Path, e.RuleID))
	if err != nil {
		writeErr(w, http.StatusBadRequest, wrapConfigErr(err))
		return
	}
	_ = rev
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revision": newRev})
}

// handleExceptionDelete removes an exception by index and publishes.
func (s *Server) handleExceptionDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	idx, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, simpleError("序号无效"))
		return
	}
	_, cfg := s.opts.Center.Current()
	if cfg.Policy == nil || idx < 0 || idx >= len(cfg.Policy.Exceptions) {
		writeErr(w, http.StatusNotFound, simpleError("例外项不存在"))
		return
	}
	removed := cfg.Policy.Exceptions[idx]
	cfg.Policy.Exceptions = append(cfg.Policy.Exceptions[:idx], cfg.Policy.Exceptions[idx+1:]...)
	newRev, err := s.opts.Center.Publish(cfg, s.author(r), fmt.Sprintf("exception removed: %s%s", removed.Site, removed.Path))
	if err != nil {
		writeErr(w, http.StatusBadRequest, wrapConfigErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revision": newRev})
}

// handleIPGroupList returns subscription groups with entry previews.
func (s *Server) handleIPGroupList(w http.ResponseWriter, r *http.Request) {
	if s.groups() == nil {
		writeErr(w, http.StatusNotFound, simpleError("未配置 IP 分组订阅"))
		return
	}
	writeJSON(w, http.StatusOK, s.groups().Describe())
}

// handleIPGroupRefresh forces a synchronous re-fetch of one group.
func (s *Server) handleIPGroupRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	if s.groups() == nil {
		writeErr(w, http.StatusNotFound, simpleError("未配置 IP 分组订阅"))
		return
	}
	if !s.groups().RefreshNow(r.PathValue("name")) {
		writeErr(w, http.StatusNotFound, simpleError("分组不存在"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// author returns the acting console user for publish attribution.
func (s *Server) author(r *http.Request) string {
	if u := userFromContext(r); u != nil {
		return u.Username
	}
	if user, _, ok := r.BasicAuth(); ok && user != "" {
		return user
	}
	return "admin"
}

// groups returns the live IP-group subscription manager (nil when none
// configured). The data plane owns the manager instance.
func (s *Server) groups() *ipgroups.Manager {
	if s.groupsFn == nil {
		return nil
	}
	return s.groupsFn()
}

// author returns the acting console user for publish attribution.

