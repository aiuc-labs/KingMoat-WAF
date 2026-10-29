package api

import (
	"sync"
	"time"

	"github.com/kingmoat/kingmoat/internal/ai"
)

// Rule-expert guards: one in-process per-operator bucket, because the console
// is a single-node management plane and a shared Redis would be a dependency
// the WAF does not have. The bucket resets on process restart — the daily
// quota exists to stop a runaway operator (or a stuck browser tab) from
// burning the provider budget, not as a billing ledger.
const (
	// ruleExpertExtractRatePerMin bounds extract-time URL fetches per operator
	// (each one is an outbound request).
	ruleExpertExtractRatePerMin = 10
	// ruleExpertExtractWindow is the sliding window width for the URL fetch cap.
	ruleExpertExtractWindow = time.Minute
)

// ruleExpertUsage is one operator's counters.
type ruleExpertUsage struct {
	minuteStart time.Time
	minuteCount int

	urlMinuteStart time.Time
	urlMinuteCount int

	day      string // YYYY-MM-DD in local time
	dayCount int
	tokens   int64
}

// ruleExpertLimiter enforces the request/rate/token budgets.
type ruleExpertLimiter struct {
	mu    sync.Mutex
	users map[string]*ruleExpertUsage
	now   func() time.Time
}

func newRuleExpertLimiter() *ruleExpertLimiter {
	return &ruleExpertLimiter{users: map[string]*ruleExpertUsage{}, now: time.Now}
}

func (l *ruleExpertLimiter) dayKey(t time.Time) string { return t.Format("2006-01-02") }

// bucket returns the operator's counters, rolling the daily window over at
// midnight (server local time, matching the console's own "today" panels).
func (l *ruleExpertLimiter) bucket(user string, now time.Time) *ruleExpertUsage {
	u := l.users[user]
	if u == nil {
		u = &ruleExpertUsage{day: l.dayKey(now)}
		l.users[user] = u
	}
	if u.day != l.dayKey(now) {
		u.day = l.dayKey(now)
		u.dayCount = 0
		u.tokens = 0
	}
	return u
}

// deny is a user-facing refusal: machine-readable code plus Chinese message.
type deny struct {
	code    string
	message string
}

// allowGenerate consumes one generation slot, or reports why it cannot.
func (l *ruleExpertLimiter) allowGenerate(user string, cfg ai.RuleExpertSettings) *deny {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	u := l.bucket(user, now)

	if cfg.MaxRequestsPerDay > 0 && u.dayCount >= cfg.MaxRequestsPerDay {
		return &deny{code: "quota_exceeded", message: "今日规则生成次数已用尽（上限 " + itoa(cfg.MaxRequestsPerDay) + " 次/日），请明天再试或调整 ai.rule_expert.max_requests_per_day"}
	}
	if cfg.MaxTokensPerDay > 0 && u.tokens >= cfg.MaxTokensPerDay {
		return &deny{code: "quota_exceeded", message: "今日 AI 额度已用尽（上限 " + itoa64(cfg.MaxTokensPerDay) + " token/日），请明天再试或调整 ai.rule_expert.max_tokens_per_day"}
	}
	if cfg.RatePerMin > 0 {
		if u.minuteStart.IsZero() || now.Sub(u.minuteStart) >= time.Minute {
			u.minuteStart = now
			u.minuteCount = 0
		}
		if u.minuteCount >= cfg.RatePerMin {
			return &deny{code: "rate_limited", message: "请求过于频繁（上限 " + itoa(cfg.RatePerMin) + " 次/分钟），请稍后再试"}
		}
		u.minuteCount++
	}
	u.dayCount++
	return nil
}

// allowExtractURL consumes one URL-fetch slot (extract only; it never touches
// the AI quotas because no model call happens).
func (l *ruleExpertLimiter) allowExtractURL(user string) *deny {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	u := l.bucket(user, now)
	if u.urlMinuteStart.IsZero() || now.Sub(u.urlMinuteStart) >= ruleExpertExtractWindow {
		u.urlMinuteStart = now
		u.urlMinuteCount = 0
	}
	if u.urlMinuteCount >= ruleExpertExtractRatePerMin {
		return &deny{code: "rate_limited", message: "链接抓取过于频繁（上限 " + itoa(ruleExpertExtractRatePerMin) + " 次/分钟），请稍后再试"}
	}
	u.urlMinuteCount++
	return nil
}

// addTokens records usage after a successful generation.
func (l *ruleExpertLimiter) addTokens(user string, tokens int64) {
	if tokens <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	u := l.bucket(user, l.now())
	u.tokens += tokens
}

// remaining reports what is left today (never negative).
func (l *ruleExpertLimiter) remaining(user string, cfg ai.RuleExpertSettings) (requestsToday int, tokensToday int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	u := l.bucket(user, l.now())
	requestsToday = cfg.MaxRequestsPerDay - u.dayCount
	if requestsToday < 0 {
		requestsToday = 0
	}
	tokensToday = cfg.MaxTokensPerDay - u.tokens
	if tokensToday < 0 {
		tokensToday = 0
	}
	return requestsToday, tokensToday
}

func itoa(n int) string { return itoa64(int64(n)) }

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
