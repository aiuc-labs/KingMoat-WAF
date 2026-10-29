package aisession

// Conservative secret masking for captured prompt/output content. Only
// high-signal token shapes are masked so auditors keep readable context;
// the placeholder interface aligns with the redact package style and can
// later host enterprise placeholders ([ENT]/[USR]/[NET]/[INF]/[SEC]).

import "regexp"

var sensitivePatterns = []*regexp.Regexp{
	// Bearer / API key shapes: sk-..., Bearer eyJ... (JWT), xoxb-..., AKIA...
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`),
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]{20,}`),
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]{10,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	// common credential JSON fields: "api_key": "..." / "password": "..."
	regexp.MustCompile(`(?i)("(?:api[_-]?key|secret|password|token|authorization)"\s*:\s*")([^"]{4,})(")`),
	// long hex secrets (32+)
	regexp.MustCompile(`\b[a-f0-9]{32,}\b`),
	// Google API keys (Gemini ?key=AIza...) carried in URLs or bodies
	regexp.MustCompile(`AIza[0-9A-Za-z_\-]{30,}`),
	// key=value / key: value plaintext shapes (password=hunter2, token: abc)
	regexp.MustCompile(`(?i)\b(password|passwd|pwd)\s*[=:]\s*\S+`),
}

// querySecretRe masks the value of credential-bearing query parameters while
// keeping the parameter name and the rest of the URL intact.
var querySecretRe = regexp.MustCompile(`(?i)([?&](?:key|api_?key|apikey|access_token|token)=)[^&\s]+`)
