package ruleexpert

import (
	"strings"
	"unicode/utf8"
)

// ruleLinePrefixes are the only line shapes kept from a model response.
var ruleLinePrefixes = []string{"SecRule", "SecAction", "SecMarker", "#"}

func isRuleLine(line string) bool {
	t := strings.TrimSpace(line)
	for _, p := range ruleLinePrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// ParseResponse extracts the first fenced code block (```seclang or ```) from
// a model answer. Without a fence it falls back to collecting SecRule /
// SecAction / SecMarker / # lines from the body. Non-SecLang lines are dropped
// with a warning instead of failing the whole call.
func ParseResponse(raw string) (rule, notes string, warnings []string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", nil, ErrNoRule
	}

	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	blockStart, blockEnd := -1, -1
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "```") {
			if blockStart < 0 {
				blockStart = i
				continue
			}
			blockEnd = i
			break
		}
	}

	var blockLines, tailLines []string
	if blockStart >= 0 && blockEnd > blockStart {
		blockLines = lines[blockStart+1 : blockEnd]
		tailLines = lines[blockEnd+1:]
	} else {
		blockLines = lines
	}

	kept := make([]string, 0, len(blockLines))
	dropped := 0
	for _, line := range blockLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		trimmed := strings.TrimRight(line, " \t")
		// A trailing backslash joins the next line: without this, the
		// multiline SecRule shape the system prompt itself demonstrates
		// (operator on line 1, actions on line 2) would keep only the
		// header and hand Coraza a directive with no actions.
		if n := len(kept); n > 0 && strings.HasSuffix(kept[n-1], "\\") {
			kept[n-1] += "\n" + trimmed
			continue
		}
		if isRuleLine(line) {
			kept = append(kept, trimmed)
			continue
		}
		dropped++
	}
	if dropped > 0 {
		warnings = append(warnings, "已丢弃 "+itoa(dropped)+" 行非 SecLang 内容")
	}

	rule = strings.TrimSpace(strings.Join(kept, "\n"))
	if rule == "" {
		return "", "", warnings, ErrNoRule
	}
	if len(rule) > MaxRuleBytes {
		rule = truncateAtLine(rule, MaxRuleBytes)
		warnings = append(warnings, "规则内容超过 64KB，已截断")
	}

	notes = strings.TrimSpace(strings.Join(tailLines, "\n"))
	if notes == "" {
		// No fenced block: notes may still follow the rule lines.
		var tail []string
		seenRule := false
		for _, line := range lines {
			if isRuleLine(line) {
				seenRule = true
				continue
			}
			if seenRule && strings.TrimSpace(line) != "" {
				tail = append(tail, strings.TrimSpace(line))
			}
		}
		notes = strings.Join(tail, "\n")
	}
	notes = truncateRunes(strings.TrimSpace(notes), MaxNotesRunes)
	if warnings == nil {
		warnings = []string{}
	}
	return rule, notes, warnings, nil
}

func truncateAtLine(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut] != '\n' {
		cut--
	}
	if cut == 0 {
		return s[:n]
	}
	return s[:cut]
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}