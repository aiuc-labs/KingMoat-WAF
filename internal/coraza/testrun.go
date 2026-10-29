package coraza

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	coraza "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestRequest is one synthetic request used by the console's rule tester.
type TestRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   string            `json:"query,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// TestMatch is one rule that fired during a pass.
type TestMatch struct {
	ID      int    `json:"id"`
	Message string `json:"message"`
	Custom  bool   `json:"custom"` // id inside the 100000-199999 console range
}

// TestPass is one engine pass result.
type TestPass struct {
	Matched         []TestMatch `json:"matched"`
	Denied          bool        `json:"denied"`
	InterruptRuleID int         `json:"interrupt_rule_id,omitempty"`
	Action          string      `json:"action,omitempty"`
}

// TestResult reports what the custom rules did with the synthetic request.
// Two passes answer two different questions:
//   - RulesOnly: ONLY the pasted rules run (no CRS) — "我的规则本身会不会命中";
//   - FullStack: the normal CRS stack + the rules — CRS may interrupt FIRST
//     (e.g. 949110), in which case the custom rule never gets evaluated.
type TestResult struct {
	RulesOnly TestPass `json:"rules_only"`
	FullStack TestPass `json:"full_stack"`
}

// customRuleIDMin/Max mirror the id window the rule expert prompts for.
const (
	customRuleIDMin = 100000
	customRuleIDMax = 199999
)

// TestCustomRules compiles the pasted SecLang block twice (rules-only and full
// CRS stack) and runs ONE synthetic request through each.
func TestCustomRules(rules string, req TestRequest, logger *slog.Logger) (TestResult, error) {
	if strings.TrimSpace(rules) == "" {
		return TestResult{}, fmt.Errorf("规则内容为空")
	}

	// Pass 1: the pasted rules alone; compile errors surface here with the
	// exact SecLang complaint.
	wafOnly, err := buildRulesOnlyWAF(rules)
	if err != nil {
		return TestResult{}, fmt.Errorf("规则编译失败：%w", err)
	}
	only, err := runTestPass(wafOnly, req)
	if err != nil {
		return TestResult{}, err
	}

	// Pass 2: the real stack (CRS + rules) for preemption awareness.
	enabled := true
	site := &config.Site{Domains: []string{"rule-test.local"}, WAF: &config.WAFSettings{Enabled: &enabled}}
	wafFull, err := buildWAF(site, &config.Policy{CustomRules: rules}, logger)
	if err != nil {
		return TestResult{}, fmt.Errorf("整栈编译失败：%w", err)
	}
	full, err := runTestPass(wafFull, req)
	if err != nil {
		return TestResult{}, err
	}
	return TestResult{RulesOnly: only, FullStack: full}, nil
}

// buildRulesOnlyWAF compiles JUST the pasted rules on top of the recommended
// conf (no CRS include list): the honest "does my rule fire" sandbox.
func buildRulesOnlyWAF(rules string) (coraza.WAF, error) {
	directives := strings.Join([]string{
		"Include @coraza.conf-recommended",
		"SecRuleEngine On",
		rules,
	}, "\n")
	conf := coraza.NewWAFConfig().
		WithRootFS(slashFS{inner: coreruleset.FS}).
		WithDirectives(directives).
		WithRequestBodyAccess()
	return coraza.NewWAF(conf)
}

// runTestPass drives ONE transaction through waf and collects the outcome.
func runTestPass(waf coraza.WAF, req TestRequest) (TestPass, error) {
	tx := waf.NewTransaction()
	defer func() { _ = tx.Close() }()

	method := strings.TrimSpace(req.Method)
	if method == "" {
		method = "GET"
	}
	path := strings.TrimSpace(req.Path)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	uri := path
	if q := strings.TrimPrefix(strings.TrimSpace(req.Query), "?"); q != "" {
		uri = path + "?" + q
	}
	tx.ProcessURI(uri, method, "HTTP/1.1")

	hasHost := false
	for k, v := range req.Headers {
		if strings.EqualFold(k, "Host") {
			hasHost = true
		}
		tx.AddRequestHeader(k, v)
	}
	// A missing Host alone trips CRS 920280 and drowns the report in noise.
	if !hasHost {
		tx.AddRequestHeader("Host", "rule-test.local")
	}
	if req.Body != "" {
		tx.AddRequestHeader("Content-Length", strconv.Itoa(len(req.Body)))
	}

	var it *types.Interruption
	if it = tx.ProcessRequestHeaders(); it == nil {
		if req.Body != "" {
			var werr error
			if it, _, werr = tx.WriteRequestBody([]byte(req.Body)); werr != nil {
				return TestPass{}, fmt.Errorf("请求体处理失败：%w", werr)
			}
		}
		// Phase 2 ALWAYS runs: query-string ARGS live there, so skipping it for
		// bodyless requests would make every ARGS_GET rule look dead.
		if it == nil {
			var perr error
			if it, perr = tx.ProcessRequestBody(); perr != nil {
				return TestPass{}, fmt.Errorf("请求体检测失败：%w", perr)
			}
		}
	}

	out := TestPass{}
	for _, m := range tx.MatchedRules() {
		id := 0
		if r := m.Rule(); r != nil {
			id = r.ID()
		}
		out.Matched = append(out.Matched, TestMatch{
			ID:      id,
			Message: m.Message(),
			Custom:  id >= customRuleIDMin && id <= customRuleIDMax,
		})
	}
	if it != nil {
		out.Denied = true
		out.InterruptRuleID = it.RuleID
		out.Action = it.Action
	}
	tx.ProcessLogging()
	return out, nil
}
