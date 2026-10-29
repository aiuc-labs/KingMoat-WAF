// Path-segment credential masking for the LOCAL access-log store (RC-2):
// the recorded path used to be only length-capped, so credential-shaped
// segments (reset links, path-style API keys, JWTs) landed in clear text and
// stayed readable through the history endpoint for the whole retention
// window. MaskPath replaces ONLY high-signal credential-shaped segments with
// a fixed placeholder while keeping every other segment verbatim, so the
// path stays forensically navigable: /api/v1/users/<masked>/profile.
//
// Judgment list — masked shapes (whole segment becomes "<masked>"):
//   - 32+ hex characters (md5/sha1/sha256 digests, unhypenated UUIDs,
//     hex session ids), optionally wrapped as a download filename
//     (<32hex>.pdf);
//   - the canonical UUID shape (8-4-4-4-12 hex);
//   - three-dot-separated JWTs (header.payload.signature, all base64url,
//     header with the deterministic "eyJ" prefix);
//   - segments with a credential prefix — "sk-…" (OpenAI-style keys) or
//     "bearer-…"/"bearer%20…" — whose remainder is ≥16 base64url characters;
//   - ≥24 base64url characters mixing upper+lower+digit (random tokens);
//   - ≥32 base64url characters containing a digit (random lowercase/base32
//     tokens).
//
// Kept verbatim (never masked): plain numeric ids (/users/123), lowercase or
// camelCase words without digit+case mixing, version segments (v1, v2.0),
// date-like segments (2026-10-13), ordinary file names (report.pdf), and any
// segment shorter than 16 bytes. Deliberate trade-off: a ≥24-character
// mixed-case-with-digit WORD segment (cdnCache1234567890123) is masked —
// 宁掩勿漏, and the surrounding path structure stays readable.
//
// Implementation note: hand-rolled character scanners, no regexp and no
// allocations on the untouched path — this runs in the request-adjacent
// Write (queue enqueue) of the data plane.
package accesslog

import "strings"

// maskedPathSegment replaces every credential-shaped path segment.
const maskedPathSegment = "<masked>"

// minPathTokenLen is the byte floor below which no segment is even examined:
// the shortest masked shape (prefixed credential) needs 16 meaningful bytes.
const minPathTokenLen = 16

// MaskPath masks credential-shaped segments of a URL path while keeping the
// path structure (and every benign segment) verbatim.
func MaskPath(raw string) string {
	if raw == "" {
		return raw
	}
	segs := strings.Split(raw, "/")
	changed := false
	for i, seg := range segs {
		if m := maskPathSegment(seg); m != seg {
			segs[i] = m
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return strings.Join(segs, "/")
}

// maskPathSegment judges one '/'-separated segment.
func maskPathSegment(seg string) string {
	if len(seg) < minPathTokenLen {
		return seg
	}
	if core, ok := stripPathCredentialPrefix(seg); ok {
		// Prefixed credentials are a strong signal on their own: any token
		// shape (JWT/hex/uuid/base64url) or a plain ≥16-char base64url tail
		// masks the whole segment.
		if looksLikePathToken(core) {
			return maskedPathSegment
		}
		if core = stripPathExtension(core); len(core) >= 16 && isBase64URLRun(core) {
			return maskedPathSegment
		}
	}
	if looksLikePathToken(seg) {
		return maskedPathSegment
	}
	return seg
}

// stripPathCredentialPrefix removes a credential-carrying prefix ("sk-…",
// "bearer-…", "bearer%20…", case-insensitive on the literal) and reports
// whether one was stripped; the remainder is judged as a bare token.
func stripPathCredentialPrefix(seg string) (string, bool) {
	lower := strings.ToLower(seg)
	for _, p := range []string{"bearer%20", "bearer-", "sk-"} {
		if strings.HasPrefix(lower, p) && len(seg) > len(p) {
			return seg[len(p):], true
		}
	}
	return seg, false
}

// stripPathExtension removes one trailing file extension (".pdf", ".json")
// so a token stored as a download filename still matches; only pure-letter
// extensions of at most 5 characters are stripped.
func stripPathExtension(s string) string {
	dot := strings.LastIndexByte(s, '.')
	if dot <= 0 || len(s)-dot-1 > 5 {
		return s
	}
	for i := dot + 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return s
		}
	}
	return s[:dot]
}

// looksLikePathToken reports whether s matches one of the credential shapes
// in the package judgment list.
func looksLikePathToken(s string) bool {
	s = stripPathExtension(s)
	n := len(s)
	if n == 0 {
		return false
	}
	if n >= 32 && isHexRun(s) {
		return true
	}
	if isUUIDShape(s) {
		return true
	}
	if isJWTShape(s) {
		return true
	}
	if isBase64URLRun(s) {
		upper, lower, digit := charClasses(s)
		if n >= 24 && upper && lower && digit {
			return true
		}
		if n >= 32 && digit {
			return true
		}
	}
	return false
}

// isHexRun reports whether every byte of s is a hexadecimal digit.
func isHexRun(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// isUUIDShape recognizes the canonical 8-4-4-4-12 hyphenated hex UUID.
func isUUIDShape(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHexByte(s[i]) {
				return false
			}
		}
	}
	return true
}

// isJWTShape recognizes the three-segment JWT encoding (header.payload.
// signature, all base64url): the header deterministically starts with "eyJ"
// (base64 of '{"'), which keeps ordinary dotted strings from matching.
func isJWTShape(s string) bool {
	first := strings.IndexByte(s, '.')
	if first <= 0 {
		return false
	}
	second := strings.IndexByte(s[first+1:], '.')
	if second < 0 {
		return false
	}
	second += first + 1
	header, payload, sig := s[:first], s[first+1:second], s[second+1:]
	if len(header) < 8 || len(payload) < 8 || len(sig) < 8 {
		return false
	}
	if !strings.HasPrefix(header, "eyJ") || strings.IndexByte(sig, '.') >= 0 {
		return false
	}
	return isBase64URLRun(header) && isBase64URLRun(payload) && isBase64URLRun(sig)
}

// isBase64URLRun reports whether every byte of s is a base64url character
// (A-Za-z0-9, '-', '_'; padding '=' is NOT accepted so unpadded raw tokens
// and ordinary words are judged the same way).
func isBase64URLRun(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// charClasses reports which character classes occur in s (ASCII only).
func charClasses(s string) (upper, lower, digit bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return
}
