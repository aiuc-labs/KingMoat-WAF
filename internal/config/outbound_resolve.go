// Outbound-channel resolution for the access-log pipeline and the AI-session
// ship behind the use_audit_channel switch: when the switch is on, the
// section takes its CHANNEL parameters (backend type, url, auth, batching,
// the s3/syslog/kafka transports) from the audit outbound (log_shipper),
// while the IDENTITY fields (enabled, use_audit_channel, index, sample_pct,
// the s3 object-key prefix and the syslog APP-NAME) stay owned by the section
// itself. One deliberate exception: the kafka topic is a CHANNEL parameter
// and is shared by the reusing classes — per-class identity on kafka lives
// in the message payload, while on every other backend the index / prefix /
// APP-NAME identity fields keep the audit / access / ai streams apart.
//
// The resolvers turn a section + the channel into the EFFECTIVE section the
// rebuilders compare (sectionTracker snapshots) and build from, which wires
// the channel reuse into the existing C-1 change detection without a new
// explicit dependency edge:
//   - a log_shipper channel change flows into the resolved section, so the
//     reusing pipelines rebuild via the fixed publish order buildOutbound →
//     buildAccess → buildAIShip (the three pipelines stay independent: a
//     failed log_shipper rebuild does not block the reusers);
//   - a change to the section's own channel fields while the switch is on
//     leaves the resolved section unchanged, so unchanged() skips the
//     rebuild (no churn on healthy outbound connections);
//   - the switch off (or the section disabled / absent) returns the section
//     as-is: behavior matches the pre-switch shape byte for byte.
//
// Resolve never fails. Shapes the publish-time cross-validation
// (validateAuditChannelReuse) already rejects — e.g. the switch on
// while log_shipper is absent, reachable only through hand-edited static
// files — are neutralized by the rebuilders with a loud WARN + disable
// instead of silently falling back to the ignored in-section fields.
//
// This file lives in config (moved byte-identically from package main) so
// the runtime rebuilders and the API outbound-probe layer share ONE
// "effective section" semantic — internal/api cannot import package main.

package config

import (
	"net/url"
	"slices"
	"strings"
)

// ResolveAccessOut resolves the effective access-log outbound section.
// nil, disabled sections and switch-off sections pass through unchanged; a
// switch-on section with a channel present returns the overlay copy (channel
// from ls, identity from the section).
func ResolveAccessOut(al *AccessLogSettings, ls *ShipperSettings) *AccessLogSettings {
	if al == nil || !al.Enabled || !al.UseAuditChannel || ls == nil {
		return al
	}
	out := *al
	out.Type = ls.Type
	out.URL = ls.URL
	out.BatchSize = ls.BatchSize
	out.FlushSec = ls.FlushSec
	out.TimeoutSec = ls.TimeoutSec
	out.Username = ls.Username
	out.Password = ls.Password
	out.Brokers = slices.Clone(ls.Brokers)
	out.Topic = ls.Topic
	out.UseTLS = ls.UseTLS
	out.SASL = ls.SASL
	out.TLSSkipVerify = cloneBoolPtr(ls.TLSSkipVerify)
	out.S3 = overlayS3Target(ls, al.S3)
	out.Syslog = overlaySyslogTransport(ls, al.Syslog)
	return &out
}

// ResolveAIShipOut resolves the effective AI-session ship section under the
// same rules as ResolveAccessOut.
func ResolveAIShipOut(ship *AIAuditShipSettings, ls *ShipperSettings) *AIAuditShipSettings {
	if ship == nil || !ship.Enabled || !ship.UseAuditChannel || ls == nil {
		return ship
	}
	out := *ship
	out.Type = ls.Type
	out.URL = ls.URL
	out.BatchSize = ls.BatchSize
	out.FlushSec = ls.FlushSec
	out.TimeoutSec = ls.TimeoutSec
	out.Username = ls.Username
	out.Password = ls.Password
	out.Brokers = slices.Clone(ls.Brokers)
	out.Topic = ls.Topic
	out.UseTLS = ls.UseTLS
	out.SASL = ls.SASL
	out.TLSSkipVerify = cloneBoolPtr(ls.TLSSkipVerify)
	out.S3 = overlayS3ShipTarget(ls, ship.S3, ship.Prefix)
	out.Syslog = overlaySyslogTransport(ls, ship.Syslog)
	return &out
}

// overlayS3Target maps the channel's flat s3 fields (log_shipper shape) onto
// the nested S3Settings the access-log pipeline consumes. The endpoint
// parsing mirrors logshipper.newS3Target (a scheme on the endpoint picks the
// transport, an explicit use_ssl overrides it), so a reused channel talks to
// the same bucket over the same transport as the audit outbound. The
// object-key PREFIX is an identity field and always comes from the section.
func overlayS3Target(ls *ShipperSettings, own *S3Settings) *S3Settings {
	if ls.Type != "s3" {
		return nil // invalid sub-structure for the resolved type
	}
	endpoint, useSSL := s3Transport(ls.Endpoint, ls.UseSSL)
	out := &S3Settings{
		Endpoint:  endpoint,
		Bucket:    ls.Bucket,
		AccessKey: ls.AccessKey,
		SecretKey: ls.SecretKey,
		UseSSL:    useSSL,
	}
	if own != nil {
		out.Prefix = own.Prefix
	}
	return out
}

// overlayS3ShipTarget is the AI-ship variant: the deprecated flat prefix
// seeds the object-key identity when the nested s3 sub-structure is absent
// (T-1 fallback-seed convention; the flat use_ssl field is consumed by the
// AI-ship builder in internal/aisession, not here).
func overlayS3ShipTarget(ls *ShipperSettings, own *S3Settings, flatPrefix string) *S3Settings {
	if ls.Type != "s3" {
		return nil
	}
	endpoint, useSSL := s3Transport(ls.Endpoint, ls.UseSSL)
	out := &S3Settings{
		Endpoint:  endpoint,
		Bucket:    ls.Bucket,
		AccessKey: ls.AccessKey,
		SecretKey: ls.SecretKey,
		UseSSL:    useSSL,
	}
	switch {
	case own != nil:
		out.Prefix = own.Prefix
	case flatPrefix != "":
		out.Prefix = flatPrefix
	}
	return out
}

// s3Transport derives the client transport from the endpoint scheme exactly
// like logshipper.newS3Target: secure by default, http:// downgrades, and an
// explicit use_ssl always wins.
func s3Transport(endpoint string, useSSL *bool) (string, bool) {
	endpoint = strings.TrimSpace(endpoint)
	secure := true
	if u, err := url.Parse(endpoint); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		endpoint = u.Host
		secure = u.Scheme == "https"
	}
	if useSSL != nil {
		secure = *useSSL
	}
	return endpoint, secure
}

// overlaySyslogTransport copies the channel's syslog transport options
// (protocol/format/framing/facility/severity/hostname/tls) and re-owns the
// APP-NAME: the channel's app name is stripped (the audit identity must not
// leak into the access/AI streams) and the section's own app name is kept —
// empty falls back to the section index, then the per-stream constant,
// inside syslogsink. A channel syslog block is optional: a missing one
// yields the all-defaults transport instead of a build failure.
func overlaySyslogTransport(ls *ShipperSettings, own *SyslogSettings) *SyslogSettings {
	if ls.Type != "syslog" {
		return nil
	}
	out := &SyslogSettings{}
	if ls.Syslog != nil {
		*out = *ls.Syslog
	}
	out.AppName = ""
	if own != nil {
		out.AppName = own.AppName
	}
	return out
}

// cloneBoolPtr copies the tri-state kafka tls_skip_verify so the resolved
// section never aliases the channel's memory.
func cloneBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
