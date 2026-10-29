package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/kingmoat/kingmoat/internal/config"
)

// credPlaceholder is the write-only sentinel GET /api/config returns for
// configured outbound credentials (log_shipper / access_log / ai_audit.ship
// channels, webhook signing secret, metrics push token, SMTP password).
// Publishing a config that carries the placeholder (or omits/empties the
// field) keeps the stored value; only an explicit new value rewrites it, and
// credEraseSentinel explicitly clears it, so the console never round-trips
// plaintext secrets and auditors cannot read them back. Boundary: a literal
// "******" can therefore never be STORED as a credential through the publish
// API — the sentinel is always interpreted as "keep" (a seed config carrying
// "******" is indistinguishable and stays).
const credPlaceholder = "******"

// credEraseSentinel is the explicit erase signal for outbound credentials:
// a credential field whose value equals this constant clears the stored
// value at publish time. It exists because the write-only contract above
// makes "" and the placeholder mean "keep", which left no way to remove a
// configured credential from the console. The sentinel is defined once here
// (no magic strings elsewhere), must never be persisted as a literal
// credential (restoreOutboundCredentials normalizes every leftover), and
// GET /api/config never returns it — its output only ever contains the
// placeholder or empty strings. Boundary, same shape as credPlaceholder: an
// operator who wants a credential whose literal value IS "__erase__" cannot
// store it through the publish API.
const credEraseSentinel = "__erase__"

// credRedactedMarker is the GET-side stand-in for outbound URLs whose
// credentials MaskURLCredentials cannot splice out (unparseable URLs, or
// user:pass@ forms without the "//" authority marker) — echoing them
// verbatim would leak the embedded password and break the write-only
// contract. It is deliberately in the same sentinel family as
// credPlaceholder/credEraseSentinel: restoreMaskedURL treats it as "keep the
// stored URL" so a GET→PUT round trip cannot overwrite storage with the
// marker, and restoreOutboundCredentials normalizes a marker left without a
// stored counterpart to empty — no sentinel of this family is ever persisted
// as a literal. Boundary, same shape as the other sentinels: an operator who
// wants a URL whose literal value IS "<redacted>" cannot store it through
// the publish API.
const credRedactedMarker = "<redacted>"

// isCredPlaceholder reports whether v is the write-only sentinel.
func isCredPlaceholder(v string) bool {
	return v == credPlaceholder
}

// maskOutboundCredentials replaces every configured outbound credential in c
// with credPlaceholder (empty fields stay empty = "not configured") and
// masks the password component of every outbound URL's user:pass@ userinfo
// with config.URLPasswordMask. A URL the masker cannot splice (parse
// failure, or a user:pass@ form without the "//" authority marker) is
// redacted whole with credRedactedMarker instead of echoing its embedded
// credentials. Callers must pass a private deep copy — the live Center
// config is shared with the running pipelines and must never be mutated.
func maskOutboundCredentials(c *config.Config) {
	for _, p := range credentialPointers(c) {
		if *p != "" {
			*p = credPlaceholder
		}
	}
	for _, p := range urlPointers(c) {
		v := *p
		masked := config.MaskURLCredentials(v)
		if masked == v && strings.Contains(v, "@") {
			// The masker returned the input untouched, yet the URL still
			// carries "@" — a credential-shaped part it could not splice out.
			// Redact the whole value unless the "@" provably sits outside a
			// userinfo: a parse failure, a surviving u.User (userinfo without
			// a password) and the no-"//" forms url.Parse reports as
			// scheme+opaque (user:pass@host) all embed credentials; a legal
			// URL that merely carries "@" in its query (?email=a@b.c) parses
			// without userinfo and stays verbatim.
			if u, err := url.Parse(v); err != nil || u.User != nil || !strings.Contains(v, "//") {
				*p = credRedactedMarker
				continue
			}
		}
		*p = masked
	}
}

// credentialPointers returns pointers to every outbound credential field
// present in c; the pointer is nil-safe per section (a section absent from
// the config contributes no pointers). Username fields are intentionally NOT
// included: they are account identifiers, not secrets, and stay readable.
func credentialPointers(c *config.Config) []*string {
	if c == nil {
		return nil
	}
	var ps []*string
	if s := c.LogShipper; s != nil {
		ps = append(ps, &s.Password, &s.AccessKey, &s.SecretKey)
	}
	if s := c.AccessLog; s != nil {
		ps = append(ps, &s.Password)
		if s.S3 != nil {
			ps = append(ps, &s.S3.AccessKey, &s.S3.SecretKey)
		}
	}
	if a := c.AiAudit; a != nil && a.Ship != nil {
		ps = append(ps, &a.Ship.Password)
		if a.Ship.S3 != nil {
			ps = append(ps, &a.Ship.S3.AccessKey, &a.Ship.S3.SecretKey)
		}
	}
	if s := c.Webhook; s != nil {
		ps = append(ps, &s.Secret)
		if s.S3 != nil {
			ps = append(ps, &s.S3.AccessKey, &s.S3.SecretKey)
		}
	}
	if m := c.Metrics; m != nil && m.Push != nil {
		ps = append(ps, &m.Push.BearerToken)
	}
	if e := c.Email; e != nil {
		ps = append(ps, &e.Password)
	}
	return ps
}

// restoreOutboundCredentials applies the write-only publish contract to the
// incoming revision: a placeholder or empty credential field keeps the value
// currently stored in cur; the erase sentinel clears it; an explicit new
// value is written as-is. Masked URL echoes restore the stored password (a
// pure round-trip restores it byte-for-byte, a host-only edit splices it
// in). Sections absent from the incoming config are untouched here
// (whole-section replace semantics apply downstream), and a placeholder,
// erase sentinel or URL mask token arriving for a section with no stored
// counterpart normalizes to empty — there is no stored value to keep and
// none of these sentinels may be persisted as a literal credential.
func restoreOutboundCredentials(in, cur *config.Config) {
	if in == nil {
		return
	}
	if cur != nil {
		for _, pr := range credentialFieldPairs(in, cur) {
			inP, curP := pr[0], pr[1]
			switch {
			case *inP == "" || isCredPlaceholder(*inP):
				*inP = *curP
			case *inP == credEraseSentinel:
				*inP = ""
			}
		}
		for _, pr := range urlFieldPairs(in, cur) {
			*pr[0] = restoreMaskedURL(*pr[0], *pr[1])
		}
	}
	// Leftover sentinels (their section has no stored counterpart) must not
	// be persisted as literal credentials.
	for _, p := range credentialPointers(in) {
		if isCredPlaceholder(*p) || *p == credEraseSentinel {
			*p = ""
		}
	}
	for _, p := range urlPointers(in) {
		if *p == credRedactedMarker {
			*p = ""
			continue
		}
		*p = normalizeMaskedURLPassword(*p, "")
	}
}

// credentialFieldPairs pairs each outbound credential field of the incoming
// config with the same field of the stored config. Pairing is structural per
// section: a section (or nested block) missing on either side contributes no
// pair, so index drift between differently-shaped configs cannot misrestore
// credentials across sections.
func credentialFieldPairs(in, cur *config.Config) [][2]*string {
	if in == nil || cur == nil {
		return nil
	}
	var pairs [][2]*string
	pair := func(inP, curP *string) {
		if inP != nil && curP != nil {
			pairs = append(pairs, [2]*string{inP, curP})
		}
	}
	if in.LogShipper != nil && cur.LogShipper != nil {
		inS, curS := in.LogShipper, cur.LogShipper
		pair(&inS.Password, &curS.Password)
		pair(&inS.AccessKey, &curS.AccessKey)
		pair(&inS.SecretKey, &curS.SecretKey)
	}
	if in.AccessLog != nil && cur.AccessLog != nil {
		inS, curS := in.AccessLog, cur.AccessLog
		pair(&inS.Password, &curS.Password)
		if inS.S3 != nil && curS.S3 != nil {
			pair(&inS.S3.AccessKey, &curS.S3.AccessKey)
			pair(&inS.S3.SecretKey, &curS.S3.SecretKey)
		}
	}
	if in.AiAudit != nil && cur.AiAudit != nil && in.AiAudit.Ship != nil && cur.AiAudit.Ship != nil {
		inS, curS := in.AiAudit.Ship, cur.AiAudit.Ship
		pair(&inS.Password, &curS.Password)
		if inS.S3 != nil && curS.S3 != nil {
			pair(&inS.S3.AccessKey, &curS.S3.AccessKey)
			pair(&inS.S3.SecretKey, &curS.S3.SecretKey)
		}
	}
	if in.Webhook != nil && cur.Webhook != nil {
		inS, curS := in.Webhook, cur.Webhook
		pair(&inS.Secret, &curS.Secret)
		if inS.S3 != nil && curS.S3 != nil {
			pair(&inS.S3.AccessKey, &curS.S3.AccessKey)
			pair(&inS.S3.SecretKey, &curS.S3.SecretKey)
		}
	}
	if in.Metrics != nil && cur.Metrics != nil && in.Metrics.Push != nil && cur.Metrics.Push != nil {
		pair(&in.Metrics.Push.BearerToken, &cur.Metrics.Push.BearerToken)
	}
	if in.Email != nil && cur.Email != nil {
		pair(&in.Email.Password, &cur.Email.Password)
	}
	return pairs
}

// redactedConfigCopy deep-copies cfg via a JSON round-trip (the config is
// JSON-native and persisted as such, so the round-trip is lossless) and
// masks every configured outbound credential plus the password component of
// every outbound URL's userinfo. The returned copy is safe to serialize to
// API clients while the live config stays untouched.
func redactedConfigCopy(cfg *config.Config) (*config.Config, error) {
	if cfg == nil {
		return nil, nil
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("redact config: %w", err)
	}
	out := new(config.Config)
	if err := json.Unmarshal(b, out); err != nil {
		return nil, fmt.Errorf("redact config: %w", err)
	}
	maskOutboundCredentials(out)
	return out, nil
}

// urlPointers returns pointers to every outbound URL field of c (nil-safe
// per section): the audit/access/AI outbound targets (log_shipper,
// access_log, ai_audit.ship), the webhook endpoint, the metrics push target
// and the IP-group subscriptions. None of these fields carries a rule that
// rejects user:pass@ userinfo on the HTTP(S) forms, so a legacy or
// hand-written target may embed credentials and would otherwise echo them
// verbatim on GET /api/config; syslog targets already reject userinfo at
// publish, but masking their (degraded) residue is harmless and keeps one
// contract for all outbound URLs. Username fields stay readable, matching
// the credential contract.
func urlPointers(c *config.Config) []*string {
	if c == nil {
		return nil
	}
	var ps []*string
	if s := c.LogShipper; s != nil {
		ps = append(ps, &s.URL)
	}
	if s := c.AccessLog; s != nil {
		ps = append(ps, &s.URL)
	}
	if a := c.AiAudit; a != nil && a.Ship != nil {
		ps = append(ps, &a.Ship.URL)
	}
	if s := c.Webhook; s != nil {
		ps = append(ps, &s.URL)
	}
	if m := c.Metrics; m != nil && m.Push != nil {
		ps = append(ps, &m.Push.URL)
	}
	for i := range c.IPGroups {
		ps = append(ps, &c.IPGroups[i].URL)
	}
	return ps
}

// urlFieldPairs pairs each outbound URL field of the incoming config with
// its stored counterpart, using the same structural pairing rules as
// credentialFieldPairs (sections pair as a whole; IP groups pair by name —
// they are an ordered list, so positional pairing could misrestore
// credentials across renamed/reordered entries).
func urlFieldPairs(in, cur *config.Config) [][2]*string {
	if in == nil || cur == nil {
		return nil
	}
	var pairs [][2]*string
	pair := func(inP, curP *string) {
		if inP != nil && curP != nil {
			pairs = append(pairs, [2]*string{inP, curP})
		}
	}
	if in.LogShipper != nil && cur.LogShipper != nil {
		pair(&in.LogShipper.URL, &cur.LogShipper.URL)
	}
	if in.AccessLog != nil && cur.AccessLog != nil {
		pair(&in.AccessLog.URL, &cur.AccessLog.URL)
	}
	if in.AiAudit != nil && cur.AiAudit != nil && in.AiAudit.Ship != nil && cur.AiAudit.Ship != nil {
		pair(&in.AiAudit.Ship.URL, &cur.AiAudit.Ship.URL)
	}
	if in.Webhook != nil && cur.Webhook != nil {
		pair(&in.Webhook.URL, &cur.Webhook.URL)
	}
	if in.Metrics != nil && cur.Metrics != nil && in.Metrics.Push != nil && cur.Metrics.Push != nil {
		pair(&in.Metrics.Push.URL, &cur.Metrics.Push.URL)
	}
	if len(in.IPGroups) > 0 && len(cur.IPGroups) > 0 {
		curByName := make(map[string]*string, len(cur.IPGroups))
		for i := range cur.IPGroups {
			curByName[cur.IPGroups[i].Name] = &cur.IPGroups[i].URL
		}
		for i := range in.IPGroups {
			if curP, ok := curByName[in.IPGroups[i].Name]; ok {
				pair(&in.IPGroups[i].URL, curP)
			}
		}
	}
	return pairs
}

// restoreMaskedURL applies the masked-URL publish contract to one outbound
// URL: an incoming value carrying config.URLPasswordMask as its password
// component is not a fresh credential — it is the redacted echo of the
// stored one, so its password is restored from cur (a pure round-trip
// restores the stored bytes verbatim; a host-only edit keeps the stored
// password). The GET-side credRedactedMarker (a URL whose credentials could
// not be masked precisely) likewise means "keep the stored URL" — the marker
// is an echo, never a replacement. A token or marker with no stored
// counterpart normalizes to empty — no sentinel may persist as a literal
// credential, mirroring the leftover-placeholder rule. Inputs without the
// token are explicit new values and pass through byte-for-byte.
func restoreMaskedURL(inURL, curURL string) string {
	if inURL == credRedactedMarker {
		return curURL
	}
	if !strings.Contains(inURL, config.URLPasswordMask) {
		return inURL
	}
	if masked := config.MaskURLCredentials(curURL); masked == inURL {
		return curURL
	}
	return normalizeMaskedURLPassword(inURL, curURL)
}

// normalizeMaskedURLPassword replaces a config.URLPasswordMask password
// component in inURL with the stored counterpart's password; without a
// usable counterpart (empty stored URL, unparseable, or no password there)
// the token degrades to an empty password. A URL too malformed to parse
// still loses its token (stripped literally): the token is a sentinel and
// must never persist as a literal credential, even when the stored password
// cannot be spliced back in. Inputs without the token are returned
// unchanged.
func normalizeMaskedURLPassword(inURL, curURL string) string {
	u, err := url.Parse(strings.TrimSpace(inURL))
	if err != nil {
		return strings.ReplaceAll(inURL, config.URLPasswordMask, "")
	}
	if u.User == nil {
		return inURL
	}
	pw, hasPw := u.User.Password()
	if !hasPw || pw != config.URLPasswordMask {
		return inURL
	}
	if cu, cerr := url.Parse(strings.TrimSpace(curURL)); cerr == nil && cu.User != nil {
		if cpw, ok := cu.User.Password(); ok {
			u.User = url.UserPassword(u.User.Username(), cpw)
		} else {
			u.User = url.User(u.User.Username())
		}
	} else {
		u.User = url.User(u.User.Username())
	}
	return u.String()
}
