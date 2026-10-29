package ruleexpert

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

const (
	// maxRuleLineBytes bounds one directive line. Long single lines are a
	// classic hand-rolled-rule smell (usually a pasted operator chain) and
	// are far more expensive to compile than the equivalent multi-line form.
	maxRuleLineBytes = 8 << 10 // 8 KiB
	// ruleIDMin / ruleIDMax is the local-rule id band. Coraza itself accepts
	// any positive id; keeping user rules inside 100000-199999 avoids
	// collisions with CRS (9xxxxx) and the built-in ruleset.
	ruleIDMin = 100000
	ruleIDMax = 199999
)

// ruleIDRE matches the "id:<n>" action in any position of a directive.
var ruleIDRE = regexp.MustCompile(`(?i)\bid\s*:\s*(\d+)`)

// Precheck runs the static and compile-time sanity checks the console shows
// next to a generated rule. It NEVER rejects a rule: every finding is a
// warning string, because a heuristic miss must not block an operator from
// reviewing and publishing a rule that Coraza does accept.
func Precheck(rule string) []string {
	warnings := []string{}
	body := strings.TrimSpace(rule)
	if body == "" {
		return append(warnings, "规则为空")
	}

	if !strings.Contains(body, "SecRule") {
		warnings = append(warnings, "规则中未出现 SecRule 指令")
	}
	ids := ruleIDRE.FindAllStringSubmatch(body, -1)
	if len(ids) == 0 {
		warnings = append(warnings, "规则缺少 id: 动作，无法在控制台唯一标识与停用")
	} else {
		for _, m := range ids {
			var id int
			if _, err := fmt.Sscanf(m[1], "%d", &id); err != nil {
				warnings = append(warnings, fmt.Sprintf("规则 ID %q 不是合法数字", m[1]))
				continue
			}
			if id < ruleIDMin || id > ruleIDMax {
				warnings = append(warnings,
					fmt.Sprintf("规则 ID %d 不在 %d-%d 区间，可能与内置/CRS 规则冲突", id, ruleIDMin, ruleIDMax))
			}
		}
	}
	if !strings.Contains(body, "deny") && !strings.Contains(body, "SecAction") {
		warnings = append(warnings, "规则未包含 deny 或 SecAction 动作，可能只记录不拦截")
	}
	if !strings.Contains(body, "msg:") {
		warnings = append(warnings, "规则未包含 msg: 动作，控制台日志将缺少可读说明")
	}
	if strings.Contains(body, "SecRuleEngine") {
		warnings = append(warnings, "规则中出现 SecRuleEngine 指令，全局引擎开关不应写入自定义规则")
	}
	for i, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		if len(line) > maxRuleLineBytes {
			warnings = append(warnings,
				fmt.Sprintf("第 %d 行超过 %dKB，建议拆分为多条更易维护的规则", i+1, maxRuleLineBytes>>10))
		}
	}

	if err := compileCheck(body); err != nil {
		warnings = append(warnings, "语法预检未通过："+err.Error())
	}
	return warnings
}

// compileCheck loads the candidate rule into a throwaway Coraza WAF so syntax
// errors (unknown variable, bad operator, malformed actions) surface before an
// operator publishes it. The engine is created with the engine switch pinned
// ON because a bare directive set would otherwise leave the engine DetectionOnly.
func compileCheck(rule string) error {
	conf := coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\n" + rule + "\n")
	_, err := coraza.NewWAF(conf)
	return err
}