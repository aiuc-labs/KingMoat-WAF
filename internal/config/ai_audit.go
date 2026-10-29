package config

import "strings"

// AIAuditSettings configures the AI session-audit pipeline: automatic
// discovery of LLM API calls proxied through the WAF (OpenAI-compatible /
// Anthropic / Gemini) and retention of the prompt + model output for the
// audit page and outbound shipping.
type AIAuditSettings struct {
	Enabled bool `json:"enabled"`
	// SamplePct keeps only N percent of identified sessions (1..100); the
	// identified surface is already narrow, so the default is 100.
	SamplePct int `json:"sample_pct,omitempty"`
	// MaxRequestBytes / MaxResponseBytes cap the captured prompt and model
	// output per session; oversized content is truncated and flagged
	// (trunc_in / trunc_out). Valid range 4096..524288.
	MaxRequestBytes  int `json:"max_request_bytes,omitempty"`
	MaxResponseBytes int `json:"max_response_bytes,omitempty"`
	// RedactContent sanitizes prompt/output before storage and shipping
	// (default true; disabling requires an explicit confirmation in the UI).
	RedactContent *bool `json:"redact_content,omitempty"`
	// IncludeEmbeddings audits embedding calls too (default off: the response
	// is a vector, not an auditable conversation).
	IncludeEmbeddings bool `json:"include_embeddings,omitempty"`
	// IncludeUnknown records unmatched-but-suspicious LLM-shaped calls
	// (path looks like an LLM endpoint and the body carries a model field)
	// as provider=unknown with metadata + truncated raw request only.
	IncludeUnknown bool `json:"include_unknown,omitempty"`
	// RetentionDays is the central-store retention (default 30).
	RetentionDays int `json:"retention_days,omitempty"`
	// Ship configures the central outbound sink for AI session records
	// (same sink matrix as the access-log pipeline).
	Ship *AIAuditShipSettings `json:"ship,omitempty"`
}

// AIAuditShipSettings mirrors AccessLogSettings (same sink matrix and
// transport options) so the central shipper can be built by conversion.
type AIAuditShipSettings struct {
	Enabled bool `json:"enabled"`
	// UseAuditChannel reuses the audit-log outbound (log_shipper) for the
	// AI-session records instead of the section's own channel fields;
	// identity fields (index, sample_pct, s3 prefix, syslog app name) stay
	// owned by this section. Requires log_shipper to be configured (enforced
	// by Config.Validate); the section's own channel fields are ignored
	// while the switch is on but kept so the operator can switch back.
	UseAuditChannel bool   `json:"use_audit_channel,omitempty"`
	Type            string `json:"type"` // clickhouse | elasticsearch | loki | s3 | syslog | kafka
	URL             string `json:"url,omitempty"`
	Index           string `json:"index,omitempty"` // default kingmoat_ai_sessions
	// SamplePct gates shipping independently of capture sampling.
	SamplePct  int `json:"sample_pct,omitempty"`
	BatchSize  int `json:"batch_size,omitempty"`
	FlushSec   int `json:"flush_sec,omitempty"`
	TimeoutSec int `json:"timeout_sec,omitempty"`
	// Username / Password enable HTTP basic authentication for the
	// clickhouse / elasticsearch / loki backends. Empty = no auth header.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// S3 sink settings (type = "s3"; MinIO / OSS / OBS / AWS S3 compatible).
	S3 *S3Settings `json:"s3,omitempty"`
	// Syslog holds the standard-syslog transport options (type "syslog");
	// the APP-NAME defaults to this section's index (kingmoat_ai_sessions)
	// so the three log classes never share a syslog identity.
	Syslog *SyslogSettings `json:"syslog,omitempty"`
	// Kafka (type "kafka"): bootstrap broker list + topic; one JSON message
	// per AI-session record. Ignored while use_audit_channel is on.
	Brokers []string `json:"brokers,omitempty"`
	Topic   string   `json:"topic,omitempty"`
	UseTLS  bool     `json:"use_tls,omitempty"`
	SASL    string   `json:"sasl,omitempty"`
	// TLSSkipVerify controls broker-certificate verification when UseTLS is
	// on; nil keeps the legacy zero-config behavior (self-signed
	// certificates NOT verified).
	TLSSkipVerify *bool `json:"tls_skip_verify,omitempty"`
	// UseSSL defaults to the endpoint scheme (s3 only).
	//
	// Deprecated: legacy flat s3 toggle kept as a fallback seed — when the
	// S3 sub-structure is absent the shipper conversion maps it onto
	// S3.UseSSL. New configurations should use s3.use_ssl.
	UseSSL *bool `json:"use_ssl,omitempty"`
	// Prefix is the object-key prefix (s3 only, default "kingmoat/ai").
	//
	// Deprecated: legacy flat s3 prefix kept as a fallback seed — when the
	// S3 sub-structure is absent the shipper conversion maps it onto
	// S3.Prefix. New configurations should use s3.prefix.
	Prefix string `json:"prefix,omitempty"`
}

// ShipOrDefault returns a non-nil ship section with defaults applied.
func (a *AIAuditSettings) ShipOrDefault() *AIAuditShipSettings {
	if a == nil || a.Ship == nil {
		return nil
	}
	return a.Ship
}

// RedactContentOrDefault reports whether prompt/output sanitization is on
// (default true; an explicit false disables it).
func (a *AIAuditSettings) RedactContentOrDefault() bool {
	if a == nil || a.RedactContent == nil {
		return true
	}
	return *a.RedactContent
}

// SamplePctOrDefault clamps the sampling percentage (default 100).
func (a *AIAuditSettings) SamplePctOrDefault() int {
	if a == nil || a.SamplePct <= 0 || a.SamplePct > 100 {
		return 100
	}
	return a.SamplePct
}

// MaxRequestBytesOrDefault clamps the prompt capture cap (default 32KB).
func (a *AIAuditSettings) MaxRequestBytesOrDefault() int {
	if a == nil || a.MaxRequestBytes <= 0 {
		return 32768
	}
	if a.MaxRequestBytes < 4096 {
		return 4096
	}
	if a.MaxRequestBytes > 524288 {
		return 524288
	}
	return a.MaxRequestBytes
}

// MaxResponseBytesOrDefault clamps the output capture cap (default 64KB).
func (a *AIAuditSettings) MaxResponseBytesOrDefault() int {
	if a == nil || a.MaxResponseBytes <= 0 {
		return 65536
	}
	if a.MaxResponseBytes < 4096 {
		return 4096
	}
	if a.MaxResponseBytes > 524288 {
		return 524288
	}
	return a.MaxResponseBytes
}

// RetentionDaysOrDefault clamps the central retention (default 30).
func (a *AIAuditSettings) RetentionDaysOrDefault() int {
	if a == nil || a.RetentionDays <= 0 {
		return 30
	}
	if a.RetentionDays > 365 {
		return 365
	}
	return a.RetentionDays
}

// Validate enforces the documented ranges for ai_audit fields.
func (a *AIAuditSettings) Validate() error {
	if a == nil {
		return nil
	}
	if a.SamplePct < 0 || a.SamplePct > 100 {
		return errAI("sample_pct must be within 1..100")
	}
	const minB, maxB = 4096, 524288
	if a.MaxRequestBytes != 0 && (a.MaxRequestBytes < minB || a.MaxRequestBytes > maxB) {
		return errAI("max_request_bytes must be within 4096..524288")
	}
	if a.MaxResponseBytes != 0 && (a.MaxResponseBytes < minB || a.MaxResponseBytes > maxB) {
		return errAI("max_response_bytes must be within 4096..524288")
	}
	if a.RetentionDays < 0 || a.RetentionDays > 365 {
		return errAI("retention_days must be within 1..365")
	}
	if s := a.Ship; s != nil {
		if err := s.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate enforces the ship section's own channel rules (extracted verbatim
// from AIAuditSettings.Validate so the publish gate and the load-time
// degradation share one rule set). Disabled sections and the use_audit_channel
// switch are exempt here — the channel parameters then come from log_shipper,
// whose presence is enforced by Config.Validate.
func (s *AIAuditShipSettings) Validate() error {
	if s == nil || !s.Enabled {
		return nil
	}
	if s.UseAuditChannel {
		// The channel parameters come from log_shipper (enforced by
		// Config.Validate); the section's own channel fields are ignored
		// but retained for switching back, so they must not be required
		// here — not even the type.
		return nil
	}
	if !outboundSinkTypeAllowed(s.Type) {
		return errAI("ship.type must be one of " + strings.Join(outboundSinkTypes, "/"))
	}
	switch s.Type {
	case "s3":
		if s.S3 == nil {
			return errAI("ship.type s3 requires the s3 block (endpoint, bucket, keys)")
		}
		if err := s.S3.Validate(); err != nil {
			return errAI("ship." + err.Error())
		}
	case "syslog":
		// SyslogSettings.Validate / validateSyslogURL build their errors
		// with errSecurityf ("config: security: ") because they are shared
		// with the security block; strip that prefix so the ship error
		// reads as one coherent message.
		if s.Syslog == nil {
			// The runtime sink constructor rejects a missing syslog block
			// while the probe silently defaults it, so a nil block must
			// not publish: the config would report applied while delivery
			// never starts.
			return errAI("ship.type syslog requires the syslog block (protocol/format)")
		}
		if err := s.Syslog.Validate(); err != nil {
			return errAI("ship.syslog: " + strings.TrimPrefix(err.Error(), "config: security: "))
		}
		if err := validateSyslogURL(s.URL); err != nil {
			return errAI("ship.syslog: " + strings.TrimPrefix(err.Error(), "config: security: "))
		}
	case "kafka":
		if err := validateKafkaOutbound(s.Brokers, s.Topic, s.SASL, s.Username, s.Password); err != nil {
			return errAI("ship.kafka: " + err.Error())
		}
	default:
		if s.URL == "" {
			return errAI("ship.url is required for http backends")
		}
	}
	return nil
}

func errAI(msg string) error { return &aiConfigError{msg} }

type aiConfigError struct{ msg string }

func (e *aiConfigError) Error() string { return "ai_audit: " + e.msg }
