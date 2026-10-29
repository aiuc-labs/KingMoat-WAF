// Query-value masking and field length caps for the LOCAL access-log store
// (access_log_record): the store persists every recorded request's query
// string, and query strings routinely carry credentials and personal
// identifiers (token=..., sid=..., mobile=...). Values of sensitive
// parameters are therefore replaced with "***" at enqueue time (落盘即脱敏)
// while parameter names and non-sensitive values stay verbatim for attack
// forensics. Matching runs on the normalized key: percent-decoded REPEATEDLY
// (bounded — see normQueryKey), lowercased, homoglyph/fullwidth-folded and
// stripped of every non-alphanumeric character, so Token=, api-key,
// session_id, API%2DKEY, %61pi_key and the double-encoded %2561pi_key all
// hit; the stored text keeps the original raw spelling. Chunks are split on
// BOTH "&" and ";" so legacy semicolon-separated backends are covered. A
// query that cannot be parsed as key=value pairs at all takes the
// conservative path: it is truncated and masked as a whole (nothing of its
// content is stored).
//
// This masker is deliberately separate from internal/redact (which scrubs
// credentials out of outbound URLs embedded in log text): different key set
// (adds personal identifiers), raw-preserving output without re-encoding,
// and it must not disturb the redact package's own semantics or tests.
package accesslog

import (
	"net/url"
	"strings"
	"unicode/utf8"
)

// Stored-field length caps (bytes, enforced at enqueue; truncation never
// splits a UTF-8 rune):
//   - query 2048: normal traffic stays far below (browser URL guidance ~2KB)
//     while the LIKE-scanned row payload stays bounded;
//   - user-agent 512: real UAs peak around 300 bytes (long app/version
//     strings); anything beyond is filler;
//   - path 1024: deep REST paths and long resource names fit; attack
//     payloads keep their leading pattern in the kept prefix.
//   - Caps also bound the worst-case row size, which keeps the capacity
//     guard's avg-row estimate (sqlite.go enforceCapacity) stable.
const (
	maxStoredQueryLen = 2048
	maxStoredUALen    = 512
	maxStoredPathLen  = 1024
)

const maskedQueryValue = "***"

// sensitiveQueryKeys holds normalized query parameter names whose values must
// never be stored in clear. Keys are compared against normQueryKey(raw):
// lowercased with every non-alphanumeric character stripped, so
// access-token / access_token / AccessToken / %61pi_key normalize onto the
// same entries. Exact-match entries keep short or collidable names ("at",
// "tt", "tel", "code") from over-matching as substrings.
var sensitiveQueryKeys = map[string]struct{}{
	// token aliases ("at"/"tt" are short API token parameter names; exact
	// match only — a substring "at" would hit "state", "path", ...).
	"at": {}, "tt": {},
	"pass": {},
	"sid":  {},
	"sign": {}, "sig": {},
	"auth": {}, "authorization": {},
	// Bare "key" is the most common short API-key parameter name
	// (?key=<real api key>) with no safe carrier substring (a "key"
	// substring would hit monkey/donkey-shaped names); exact match only.
	"key": {},
	// Single-letter credential shorthands (R3-02 residual closure): ?k=<api
	// key>, ?p=<password> and ?t=<token> are established one-letter
	// conventions and ?p=hunter2 IS a plaintext password — the former
	// "1-char keys are skipped" rule leaked exactly these. Exact set only;
	// every OTHER single-letter key is judged by VALUE SHAPE in
	// maskQueryChunk (looksLikeCredentialValue), so ?q=hello / ?id=7 traffic
	// is untouched. Accepted false positive: a page-number ?p=2 (or a tag
	// ?t=3) is masked — the same 宁掩勿漏 trade-off as the "pass" substring
	// family (compass/passport), pinned by TestMaskQuerySingleLetterKeys.
	"k": {}, "p": {}, "t": {},
	// High-frequency abbreviation shorthands (R-4 short-key closure): ?pw=,
	// ?tok= and ?sess= are established credential/session parameter names
	// too short for any carrier substring; "pwd" is already covered by the
	// "pwd" substring below but is listed here explicitly so the full
	// abbreviation set stays visible in one place. "sid" is already above.
	"pw": {}, "pwd": {}, "tok": {}, "sess": {},
	"otp": {}, "code": {}, "verify": {}, "verification": {}, "verifycode": {}, "otpcode": {},
	"ssn": {}, "idcard": {}, "tel": {}, "mail": {},
	// Legacy session-cookie spelling with no safe carrier substring (an
	// "sid" substring would hit consider/inside/...); exact match only.
	"connectsid": {},
}

// sensitiveQuerySubstrings hit credential-bearing name FAMILIES whose exact
// enumeration is open-ended (accesstoken, refreshtoken, clientsecret,
// phpsessid, ...). Every substring is long/distinct enough to avoid the
// false-positive swamps (no "at", "tel", "sig", "code" here).
// "pass" is the deliberate exception added for the userpass/newpass/
// passphrase/pass1 family, which has no longer carrier substring: it trades
// false positives on compass/passport/bypass-shaped keys for coverage —
// losing forensics value on rare benign keys is preferred over a clear-text
// password landing in the store (宁掩勿漏; pinned by tests).
var sensitiveQuerySubstrings = []string{
	"token", "secret", "password", "passwd", "pwd",
	"pass",
	"apikey", "accesskey", "session", "sessid", "signature",
	"email", "mobile", "phone", "idcard",
}

// homoglyphFold maps the common visually-identical Cyrillic/Greek letters
// onto their Latin counterparts (the dependency-free fix for the
// confusable-key bypass "tоken" spelled with a Cyrillic о — RC-1 ⑤).
// Lowercase forms only: strings.ToLower runs first. Deliberately minimal —
// no digit look-alikes (o/0, l/1), which would corrupt legitimate
// alphanumeric keys.
var homoglyphFold = map[rune]rune{
	// Cyrillic.
	'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
	'к': 'k', 'в': 'b', 'м': 'm', 'н': 'h', 'т': 't',
	// Greek.
	'ο': 'o', 'α': 'a', 'ε': 'e', 'ρ': 'p', 'κ': 'k', 'ν': 'v', 'ι': 'i',
}

// foldQueryRune applies the Unicode folds key matching needs beyond
// lowercasing: the fullwidth ASCII block (U+FF01..U+FF5E, the "ＡＰＩ＿ＫＥＹ"
// shape) collapses onto plain ASCII (the NFKC effect that matters here) and
// confusable letters normalize onto their Latin counterpart. Hand-rolled
// instead of golang.org/x/text/unicode/norm to avoid promoting an indirect
// dependency to direct for this one narrow use.
func foldQueryRune(r rune) rune {
	if r >= 0xFF01 && r <= 0xFF5E {
		return r - 0xFEE0
	}
	if repl, ok := homoglyphFold[r]; ok {
		return repl
	}
	return r
}

// maxSensitiveKeyNormLen bounds the normalization input for very long keys:
// every sensitive name is far shorter, so prefix truncation never splits a
// match, while a megabyte-long poison key cannot burn the decode/fold budget
// (RC-1 ④: keys beyond the former 64-byte gate are no longer skipped, only
// capped here).
const maxSensitiveKeyNormLen = 256

// normQueryKey canonicalizes one raw query key for matching: percent-decode
// REPEATEDLY up to two rounds (the double-encoded bypass %2561pi_key decodes
// to %61pi_key and then api_key; a third encoding is out of threat scope and
// the round cap keeps %252525... bombs bounded), lowercase, fold
// fullwidth/homoglyph runes, and strip every non-alphanumeric rune so the
// "-", "_", "." and space variants collapse. Undecodable keys keep their raw
// spelling.
func normQueryKey(raw string) string {
	raw = strings.TrimSpace(raw)
	for i := 0; i < 2; i++ {
		d, err := url.QueryUnescape(raw)
		if err != nil || d == raw {
			break
		}
		raw = d
	}
	var b strings.Builder
	for _, r := range strings.ToLower(raw) {
		r = foldQueryRune(r)
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isSensitiveQueryKey reports whether a raw query parameter name normalizes
// onto the sensitive set. 1-char keys participate: the single-letter
// credential shorthands k/p/t hit the exact set, and any other 1-char key
// falls through to the value-shape judgment in maskQueryChunk. Keys longer
// than the normalization cap are matched on their capped prefix, so
// log-poisoning keys no longer bypass masking just by being long.
func isSensitiveQueryKey(rawKey string) bool {
	if rawKey == "" {
		return false
	}
	nk := normQueryKey(truncateUTF8(rawKey, maxSensitiveKeyNormLen))
	if nk == "" {
		return false
	}
	if _, ok := sensitiveQueryKeys[nk]; ok {
		return true
	}
	for _, sub := range sensitiveQuerySubstrings {
		if strings.Contains(nk, sub) {
			return true
		}
	}
	return false
}

// maskForStore returns a copy of e with the storage-time privacy treatment
// (credential-shaped path segments, sensitive query values, UA truncation)
// applied. Shared by the local SQLite sink and the in-memory ring so the
// console live tail and the persisted history enforce the same policy —
// a plaintext tail next to a masked store would leak what the store hides.
func maskForStore(e *Entry) Entry {
	ne := *e
	ne.Path = truncateUTF8(MaskPath(ne.Path), maxStoredPathLen)
	ne.Query = MaskQuery(ne.Query)
	ne.UserAgent = truncateUTF8(ne.UserAgent, maxStoredUALen)
	return ne
}

// MaskQuery masks the values of sensitive query parameters and truncates the
// result to the stored-query cap (raw-preserving; see the package comment).
func MaskQuery(raw string) string {
	return maskQuery(raw, maxStoredQueryLen)
}

func maskQuery(raw string, maxLen int) string {
	if raw == "" {
		return raw
	}
	// Pre-truncate to the cap first: it bounds the parse/normalize scan for
	// poison-long queries, and secrets beyond the cap are discarded whole
	// (nothing leaks through the truncation either).
	raw = truncateUTF8(raw, maxLen)
	if !strings.Contains(raw, "=") {
		// Not key=value shaped (free-form junk, binary, URL fragments):
		// conservative whole mask — none of the content can be attributed
		// to a non-sensitive parameter, so nothing is stored.
		return maskedQueryValue
	}
	// Split on BOTH separators ("&" and ";"), mask the sensitive chunks and
	// reassemble byte for byte with the original separators. The scan is
	// byte-based and safe: '&', ';' and '=' are ASCII, so UTF-8 continuation
	// bytes (>= 0x80) can never be mistaken for a separator.
	var b strings.Builder
	b.Grow(len(raw))
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == '&' || raw[i] == ';' {
			b.WriteString(maskQueryChunk(raw[start:i]))
			if i < len(raw) {
				b.WriteByte(raw[i])
			}
			start = i + 1
		}
	}
	// Masking can LENGTHEN the text (t=1 → t=***), so the cap is re-applied
	// AFTER masking (S-11): the stored text never exceeds maxLen no matter
	// how many sensitive parameters the window holds. Truncating
	// already-masked text cannot expose a secret and never splits a rune.
	return truncateUTF8(b.String(), maxLen)
}

// maskQueryChunk masks one "&"/";"-separated chunk: a sensitive key with a
// non-empty value keeps its raw spelling but loses the value (empty values
// carry no secret and stay verbatim, same rule as internal/redact.URL; a
// bare key has no value to leak and stays verbatim). A SHORT key (≤3
// normalized characters) outside the exact sensitive set falls through to
// the value-shape judgment (looksLikeCredentialValue): abbreviation
// shorthands like ?pw=/?tok= carry no name signal a substring could catch,
// but a random-token-shaped value still must not land in clear text.
func maskQueryChunk(c string) string {
	if c == "" {
		return c
	}
	eq := strings.IndexByte(c, '=')
	if eq < 0 {
		return c
	}
	if c[eq+1:] == "" {
		return c // empty value: nothing to leak
	}
	if isSensitiveQueryKey(c[:eq]) {
		return c[:eq] + "=" + maskedQueryValue
	}
	if isShortQueryKey(c[:eq]) && looksLikeCredentialValue(c[eq+1:]) {
		return c[:eq] + "=" + maskedQueryValue
	}
	return c
}

// isShortQueryKey reports whether the raw key normalizes to at most three
// alphanumeric characters (a/P/%70/pw/tok/...): such keys carry no name
// signal, so maskQueryChunk judges them by their value's shape instead.
// Formerly single-letter only; widened to ≤3 because two/three-letter
// abbreviation shorthands (?pw=<plaintext>, ?tok=<JWT>) leak credentials
// just the same — exact sensitive keys like "sid"/"key" stay in the exact
// set above, and the ≥16-byte floor of the value-shape judgment keeps
// ordinary short values (?id=42, ?lang=zh) verbatim.
func isShortQueryKey(rawKey string) bool {
	return len(normQueryKey(truncateUTF8(rawKey, maxSensitiveKeyNormLen))) <= 3
}

// looksLikeCredentialValue reports whether a raw query VALUE matches one of
// the credential shapes of the path-segment judgment list (pathmask.go):
// 32+ hex, canonical UUID, three-segment JWT, sk-/bearer- prefixed, or a
// long mixed-class base64url run. One percent-decode round is attempted
// first so encoded tokens (?t=%73%6B%2D...) still hit; undecodable values
// are judged on their raw bytes. maskPathSegment is reused verbatim — one
// judgment list, one semantics, no drift between path and query masking.
// The ≥16-byte floor of the segment judgment bounds the false-positive
// surface: short ordinary values (hello, abc, 7) never mask.
func looksLikeCredentialValue(v string) bool {
	if d, err := url.QueryUnescape(v); err == nil && d != v {
		v = d
	}
	return maskPathSegment(v) == maskedPathSegment
}

// truncateUTF8 cuts s to at most max bytes without splitting a multi-byte
// rune (the cut point walks back to the last rune boundary; validity of the
// kept prefix is never worse than the input's own).
func truncateUTF8(s string, max int) string {
	if len(s) <= max || max <= 0 {
		if max <= 0 {
			return ""
		}
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
