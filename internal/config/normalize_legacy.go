// Legacy outbound-form normalization for configs produced by v0.7.13 and
// earlier releases. Those revisions predate two strictness rules that now
// gate Config.Validate — and Validate runs on EVERY load path (config.Load
// for the static file/seed, configcenter.Open for the stored revision), so a
// stored legacy shape would make an upgraded binary refuse to boot.
//
// Two shapes are migrated, at the RAW JSON level (the flat s3 keys are not
// part of the struct schema, so they are silently dropped by unmarshal and
// cannot be recovered at the struct level):
//
//  1. access_log and ai_audit.ship with type "s3" carrying flat endpoint/
//     bucket/prefix/access_key/secret_key/use_ssl fields (the v0.7.13
//     console form; for ai_audit.ship the deprecated flat prefix/use_ssl
//     fields may also appear alone) instead of the nested s3 block the
//     struct and the runtime sink expect.
//  2. Any of the three outbound sections (log_shipper, access_log,
//     ai_audit.ship) with type "syslog" but no syslog sub-block. v0.7.13
//     validated this shape as legal; the runtime sink constructor however
//     rejects a missing block, so delivery silently never started. A
//     synthesized default block (transport derived from the URL scheme,
//     RFC 5424 format) both unblocks the load and makes the delivery the
//     operator configured actually work.
//
// Normalization is deliberately a LOAD-time migration only: Publish keeps
// validating the submitted struct strictly (new configurations must be
// written in the nested/complete form), stored revisions are never rewritten
// (append-only history; every load deterministically re-derives the same
// result), and well-formed configs pass through byte-for-byte unchanged.

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// NormalizeLegacyOutboundJSON migrates legacy outbound shapes in raw config
// JSON (see the package-level comment for the two migrated shapes). It
// returns the (possibly identical) JSON plus a human-readable list of the
// migrations applied, one entry per migrated section, so the caller can log
// which section received which normalization. err is non-nil only when raw
// is not decodable JSON at all (callers report it in their own context);
// anything else passes through untouched and lets the regular decode step
// produce the schema-level error.
func NormalizeLegacyOutboundJSON(raw []byte) (out []byte, applied []string, err error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// UseNumber keeps every number as its original literal (json.Number)
	// instead of the default float64: a field the migration does not touch is
	// then re-encoded byte for byte at ANY magnitude, where the float64 round
	// trip would silently round values at/beyond 2^63 (and the rounded literal
	// would then fail to decode back into an int64 field).
	dec.UseNumber()
	var doc map[string]any
	if uerr := dec.Decode(&doc); uerr != nil {
		return raw, nil, fmt.Errorf("config: normalize: not a JSON object: %w", uerr)
	}
	// json.Unmarshal rejects trailing data; keep that strictness so a file
	// that is not exactly one JSON value is still reported (and never
	// silently rewritten into a valid one).
	if dec.More() {
		return raw, nil, fmt.Errorf("config: normalize: not a JSON object: trailing data after the JSON value")
	}
	changed := false
	if migrateFlatS3IntoNestedBlock(doc, []string{"access_log"}) {
		applied = append(applied, "access_log: migrated flat s3 fields into the s3 block")
		changed = true
	}
	if migrateFlatS3IntoNestedBlock(doc, []string{"ai_audit", "ship"}) {
		applied = append(applied, "ai_audit.ship: migrated flat s3 fields into the s3 block")
		changed = true
	}
	for _, section := range []struct{ path []string }{{[]string{"log_shipper"}}, {[]string{"access_log"}}, {[]string{"ai_audit", "ship"}}} {
		if synth := synthesizeDefaultSyslogBlock(doc, section.path); synth {
			applied = append(applied, strings.Join(section.path, ".")+": synthesized a default syslog block (transport from url scheme, rfc5424)")
			changed = true
		}
	}
	if !changed {
		return raw, nil, nil
	}
	b, merr := json.Marshal(doc)
	if merr != nil {
		return raw, nil, fmt.Errorf("config: normalize: re-encode: %w", merr)
	}
	return b, applied, nil
}

// NormalizeLegacyOutbound is the struct-level counterpart used on seeds
// handed to configcenter.Open as *config.Config (already decoded, so flat s3
// keys are unrecoverable there) and after decoding stored revisions/rolls:
// it synthesizes missing syslog blocks exactly like the JSON level, then
// DEGRADES any outbound section that still fails its own type rules. The
// degradation is the class-level guarantee behind the shape migrations: an
// outbound section that could never ship as configured (the runtime sink
// constructors reject the same shapes) must never deny the boot — it is
// switched off explicitly instead, with the original validation error
// recorded in the returned list so the operator can see why:
//
//   - access_log / ai_audit.ship: Enabled forced to false,
//   - log_shipper (no enabled flag): the section is set to nil (= off).
//
// Before the validation pass, ai_audit.ship's DEPRECATED flat s3 prefix /
// use_ssl pair migrates into the nested s3 block (same rule the JSON level
// applies to the flat-s3 shapes) — without it the shipper's runtime fallback
// would seed the values but Validate would still degrade the section (the
// flat values would also be lost on the next console publish). The
// deprecated fields stay on the struct (omitted from JSON once empty) so a
// section with type other than s3 keeps carrying them for the console to
// round-trip; the runtime fallback in internal/aisession stays in place for
// the static-file path.
//
// Each entry names the section and the action once and then carries the
// error's REASON only: the error's own redundant section prefix (see
// degradationReason) is stripped, so the entry reads as one coherent sentence
// instead of repeating "config: <section>" inside its parentheses.
//
// Publish never goes through here: submitted configurations are validated
// strictly and a section failing its type rules is rejected as before. The
// function is idempotent and leaves already-valid sections untouched.
func NormalizeLegacyOutbound(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var applied []string
	if cfg.AiAudit != nil && cfg.AiAudit.Ship != nil && cfg.AiAudit.Ship.Type == "s3" && cfg.AiAudit.Ship.S3 == nil &&
		(cfg.AiAudit.Ship.Prefix != "" || cfg.AiAudit.Ship.UseSSL != nil) {
		s3 := &S3Settings{Prefix: cfg.AiAudit.Ship.Prefix}
		if cfg.AiAudit.Ship.UseSSL != nil {
			s3.UseSSL = *cfg.AiAudit.Ship.UseSSL
		}
		cfg.AiAudit.Ship.S3 = s3
		// The flat fields are MOVED, not copied (JSON-level rule above):
		// the values now live in the nested block, the deprecated fields
		// stay empty so the migration is idempotent.
		cfg.AiAudit.Ship.Prefix = ""
		cfg.AiAudit.Ship.UseSSL = nil
		applied = append(applied, "ai_audit.ship: migrated flat s3 fields into the s3 block")
	}
	if cfg.LogShipper != nil && cfg.LogShipper.Type == "syslog" && cfg.LogShipper.Syslog == nil {
		cfg.LogShipper.Syslog = defaultSyslogSettings(cfg.LogShipper.URL)
		applied = append(applied, "log_shipper: synthesized a default syslog block (transport from url scheme, rfc5424)")
	}
	if cfg.AccessLog != nil && cfg.AccessLog.Type == "syslog" && cfg.AccessLog.Syslog == nil {
		cfg.AccessLog.Syslog = defaultSyslogSettings(cfg.AccessLog.URL)
		applied = append(applied, "access_log: synthesized a default syslog block (transport from url scheme, rfc5424)")
	}
	if cfg.AiAudit != nil && cfg.AiAudit.Ship != nil && cfg.AiAudit.Ship.Type == "syslog" && cfg.AiAudit.Ship.Syslog == nil {
		cfg.AiAudit.Ship.Syslog = defaultSyslogSettings(cfg.AiAudit.Ship.URL)
		applied = append(applied, "ai_audit.ship: synthesized a default syslog block (transport from url scheme, rfc5424)")
	}
	if cfg.AccessLog != nil && cfg.AccessLog.Enabled {
		if err := cfg.AccessLog.Validate(); err != nil {
			cfg.AccessLog.Enabled = false
			applied = append(applied, fmt.Sprintf("access_log: disabled (unshippable as configured: %s)", degradationReason(err, "config: access_log")))
		}
	}
	if cfg.LogShipper != nil {
		if err := cfg.LogShipper.Validate(); err != nil {
			cfg.LogShipper = nil
			applied = append(applied, fmt.Sprintf("log_shipper: removed (unshippable as configured: %s)", degradationReason(err, "config: log_shipper")))
		}
	}
	if cfg.AiAudit != nil && cfg.AiAudit.Ship != nil && cfg.AiAudit.Ship.Enabled {
		if err := cfg.AiAudit.Ship.Validate(); err != nil {
			cfg.AiAudit.Ship.Enabled = false
			applied = append(applied, fmt.Sprintf("ai_audit.ship: disabled (unshippable as configured: %s)", degradationReason(err, "ai_audit: ship")))
		}
	}
	// Defensive tail (defense, not a legacy shape): a section riding the
	// use_audit_channel switch while its channel (log_shipper) is gone after
	// the degradation above could not ship either. v0.7.13 stores cannot
	// carry the switch (field introduced later), so this only fires on
	// hand-crafted or future shapes — exactly the guarantee wanted here.
	if cfg.AccessLog != nil && cfg.AccessLog.Enabled && cfg.AccessLog.UseAuditChannel && cfg.LogShipper == nil {
		cfg.AccessLog.Enabled = false
		applied = append(applied, "access_log: disabled (use_audit_channel on but the audit-log outbound log_shipper is not configured)")
	}
	if cfg.AiAudit != nil && cfg.AiAudit.Ship != nil && cfg.AiAudit.Ship.Enabled && cfg.AiAudit.Ship.UseAuditChannel && cfg.LogShipper == nil {
		cfg.AiAudit.Ship.Enabled = false
		applied = append(applied, "ai_audit.ship: disabled (use_audit_channel on but the audit-log outbound log_shipper is not configured)")
	}
	return applied
}

// migrateFlatS3IntoNestedBlock moves the flat s3 keys of a nested-object
// section (path, e.g. ["access_log"] or ["ai_audit", "ship"]) into the
// nested "s3" block — only when the section declares type "s3" and carries
// no s3 block (absent or null). Keys are moved only when present; a
// migration that moves at least one key reports true. Sections that already
// carry an s3 object (the current console form) are left untouched.
func migrateFlatS3IntoNestedBlock(doc map[string]any, path []string) bool {
	sec, ok := sectionAt(doc, path)
	if !ok || !isString(sec["type"], "s3") {
		return false
	}
	if _, exists := sec["s3"]; exists && sec["s3"] != nil {
		return false
	}
	flatKeys := []string{"endpoint", "bucket", "prefix", "access_key", "secret_key", "use_ssl"}
	block := map[string]any{}
	moved := 0
	for _, k := range flatKeys {
		if v, ok := sec[k]; ok {
			block[k] = v
			delete(sec, k)
			moved++
		}
	}
	if moved == 0 {
		return false // nothing recoverable: leave the strict s3-block error to Validate
	}
	sec["s3"] = block
	return true
}

// sectionAt walks a dotted section path (["ai_audit", "ship"]) through
// nested JSON objects; ok is false when any hop is missing or not an object.
func sectionAt(doc map[string]any, path []string) (map[string]any, bool) {
	cur := doc
	for _, key := range path {
		next, ok := cur[key].(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// synthesizeDefaultSyslogBlock reports whether a missing/null syslog block
// was synthesized for the section at path (e.g. ["log_shipper"] or
// ["ai_audit","ship"]) when its type is "syslog". The synthesized block keeps
// the load alive and activates the delivery the operator configured: the
// transport derives from the URL scheme (udp/tcp/tls, bare hosts default to
// udp) and the format uses the existing default (rfc5424); every other field
// stays empty so the runtime zero-value defaults apply.
func synthesizeDefaultSyslogBlock(doc map[string]any, path []string) bool {
	secAny, ok := doc[path[0]]
	if !ok {
		return false
	}
	sec, ok := secAny.(map[string]any)
	if !ok {
		return false
	}
	target := sec
	if len(path) > 1 {
		inner, ok := sec[path[1]].(map[string]any)
		if !ok {
			return false
		}
		target = inner
	}
	if !isString(target["type"], "syslog") {
		return false
	}
	if existing, exists := target["syslog"]; exists && existing != nil {
		return false
	}
	protocol := legacySyslogProtocolFromURL(asString(target["url"]))
	block := map[string]any{"format": "rfc5424"}
	if protocol != "" {
		block["protocol"] = protocol
	}
	target["syslog"] = block
	return true
}

// legacySyslogProtocolFromURL derives the syslog transport from a target URL
// scheme: udp://, tcp:// and tls:// map onto themselves, a bare host (or any
// other/absent scheme) defaults to udp — matching the sink's default
// transport. This only normalizes transport for legacy configs already
// stored in the database; it does NOT mean the publish-time validator
// (validateSyslogURL) accepts those forms — bare "host:514" is rejected at
// publish with check 1.
func legacySyslogProtocolFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "udp"
	}
	switch strings.ToLower(u.Scheme) {
	case "tcp":
		return "tcp"
	case "tls":
		return "tls"
	default:
		return "udp"
	}
}

// defaultSyslogSettings builds the struct-level default syslog block for a
// given target URL (same derivation as the JSON level).
func defaultSyslogSettings(targetURL string) *SyslogSettings {
	return &SyslogSettings{Protocol: legacySyslogProtocolFromURL(targetURL), Format: "rfc5424"}
}

// degradationReason reduces one outbound section's own validation error to
// the reason text of a degradation entry. The entry itself already names the
// section and the action ("<section>: disabled/removed (unshippable as
// configured: ...)"), so the error's section prefix — "config: log_shipper",
// "config: access_log" or "ai_audit: ship" — would repeat it and is stripped;
// everything else is kept verbatim so nothing is lost: the per-type qualifier
// ("(kafka): ", "s3.", ...) and the actual reason. The qualifier's
// parentheses are flattened to "kafka: " because the entry already uses
// parentheses for the degradation context. An error carrying no such prefix
// is returned unchanged.
func degradationReason(err error, sectionPrefix string) string {
	msg := err.Error()
	rest, ok := strings.CutPrefix(msg, sectionPrefix)
	if !ok {
		return msg
	}
	// Drop the separator joining the prefix to the detail: "." for the flat
	// field spellings ("log_shipper.url"), a space for the qualified ones
	// ("log_shipper (kafka):").
	rest = strings.TrimLeft(rest, " .:")
	if inner, qualified := strings.CutPrefix(rest, "("); qualified {
		if i := strings.Index(inner, "): "); i > 0 {
			rest = inner[:i] + ": " + inner[i+3:]
		}
	}
	if rest == "" {
		return msg
	}
	return rest
}

func isString(v any, want string) bool {
	s, ok := v.(string)
	return ok && s == want
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
