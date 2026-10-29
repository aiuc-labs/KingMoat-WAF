package coraza

import (
	"log/slog"
	"os"
	"testing"
)

// TestTestCustomRules pins the two-pass console rule tester:
//   - the rules-only pass reports whether the pasted rule itself fires;
//   - the full-stack pass shows CRS preemption (a rule that would fire can
//     still be beaten to the interruption by 949110);
//   - invalid SecLang fails to compile with an error.
func TestTestCustomRules(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	rules := "SecRule ARGS_GET:cmd \"@rx (?i)(?:;|\\||`|\\$\\(|&&)\" \\\n" +
		"    \"id:100001,phase:2,deny,status:403,log,msg:'cmd 参数含命令拼接特征'\""

	res, err := TestCustomRules(rules, TestRequest{Method: "GET", Path: "/api/v1/exec", Query: "cmd=id;whoami"}, logger)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	found := false
	for _, m := range res.RulesOnly.Matched {
		if m.ID == 100001 && m.Custom {
			found = true
		}
	}
	if !found {
		t.Fatalf("rules-only pass did not report 100001: denied=%v matched=%+v", res.RulesOnly.Denied, res.RulesOnly.Matched)
	}

	benign, err := TestCustomRules(rules, TestRequest{Method: "GET", Path: "/api/v1/exec", Query: "cmd=status"}, logger)
	if err != nil {
		t.Fatalf("compile benign: %v", err)
	}
	for _, m := range benign.RulesOnly.Matched {
		if m.ID == 100001 {
			t.Fatalf("benign request hit the custom rule: %+v", benign.RulesOnly.Matched)
		}
	}

	// Full stack: CRS itself flags `cmd=id;whoami`, so the pass must at least
	// report a denial with the interrupting rule id.
	if !res.FullStack.Denied || res.FullStack.InterruptRuleID == 0 {
		t.Fatalf("full-stack pass should deny with a rule id: %+v", res.FullStack)
	}

	if _, err := TestCustomRules("SecRule ARGS", TestRequest{}, logger); err == nil {
		t.Fatal("invalid rule must fail to compile")
	}
}
