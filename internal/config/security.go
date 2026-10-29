package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"
)

// SecuritySettings groups the per-site protection stages. Every sub-block is
// optional; omitted means the stage is disabled.
type SecuritySettings struct {
	ACL        *ACLSettings        `json:"acl,omitempty"`
	RateLimit  *RateLimitSettings  `json:"ratelimit,omitempty"`
	BotCheck   *BotSettings        `json:"bot,omitempty"`
	BotDetect  *BotDetectSettings  `json:"bot_detect,omitempty"`
	Captcha    *CaptchaSettings    `json:"captcha,omitempty"`
	Geo        *GeoSettings        `json:"geo,omitempty"`
	Auth       *AuthSettings       `json:"auth,omitempty"`
	Semantic   *SemanticSettings   `json:"semantic,omitempty"`
	RespFilter *RespFilterSettings `json:"resp_filter,omitempty"`
	Dynamic    *DynamicSettings    `json:"dynamic,omitempty"`
}

// SemanticSettings enables the libinjection-based lightweight semantic
// detection layer (SQLi/XSS on path, query, referer headers and buffered
// body), independent of the OWASP CRS rule set.
type SemanticSettings struct {
	Enabled    bool `json:"enabled"`
	CheckBody  bool `json:"check_body,omitempty"`  // default on when buffered
	CheckQuery bool `json:"check_query,omitempty"` // default on
}

// ACLSettings configures IP/CIDR access control. Whitelist hits mark the
// request as trusted and skip the remaining detection stages. Entries may be
// a plain IP, a CIDR block, or "group:<name>" referencing a subscribed
// IPGroup defined at the top level.
type ACLSettings struct {
	Blacklist []string `json:"blacklist,omitempty"`
	Whitelist []string `json:"whitelist,omitempty"`
}

// RateLimitSettings configures CC protection with a fixed-window counter
// per key. Sliding-window refinement is tracked for a later release.
type RateLimitSettings struct {
	Requests  int    `json:"requests"`         // allowed requests per window per key
	WindowSec int    `json:"window_sec"`       // default 60
	Key       string `json:"key,omitempty"`    // "ip" (default) | "ip+uri"
	Action    string `json:"action,omitempty"` // "deny" (403, default) | "throttle" (429)
}

// BotSettings configures the lightweight JS challenge bot check. When a
// site also enables Captcha the slider challenge replaces this stage.
type BotSettings struct {
	Secret     string `json:"secret,omitempty"`      // HMAC secret; empty → random per boot
	CookieName string `json:"cookie_name,omitempty"` // default km_challenge
	TTLMin     int    `json:"ttl_min,omitempty"`     // challenge validity in minutes, default 60
}

// BotDetectSettings configures the observe-first bot classification stage.
// Actions map class → "allow" | "observe" | "deny" | "challenge";
// the default for every class is observe (v0.4 ships with zero interception
// change so operators can review the data first).
type BotDetectSettings struct {
	Enabled bool              `json:"enabled"`
	Actions map[string]string `json:"actions,omitempty"` // good | unknown | bad → action
	// RateThreshold flags clients exceeding requests/window_sec per fingerprint.
	RateThreshold RateThreshold `json:"rate_threshold,omitempty"`
	// GoodBotBypassChallenge lets verified good bots skip the JS challenge.
	GoodBotBypassChallenge bool `json:"good_bot_bypass_challenge,omitempty"`
}

// RateThreshold is a shared requests-per-window rule.
type RateThreshold struct {
	Requests  int `json:"requests"`
	WindowSec int `json:"window_sec,omitempty"` // default 60
}

// Default returns the effective rate threshold (300 req / 60s).
func (t RateThreshold) Defaults() (int, time.Duration) {
	r := t.Requests
	if r <= 0 {
		r = 300
	}
	w := time.Duration(t.WindowSec) * time.Second
	if w <= 0 {
		w = time.Minute
	}
	return r, w
}

// CaptchaSettings configures the slider human-verification challenge.
type CaptchaSettings struct {
	Enabled    bool   `json:"enabled"`
	Secret     string `json:"secret,omitempty"`      // HMAC secret; empty → random per boot
	CookieName string `json:"cookie_name,omitempty"` // default km_captcha
	TTLMin     int    `json:"ttl_min,omitempty"`     // pass validity in minutes, default 60
	Tolerance  int    `json:"tolerance,omitempty"`   // accepted drag offset in px, default 8
}

// GeoSettings configures GeoIP country access control. db_path empty uses
// the embedded DB-IP Country Lite country database (built in, works out of
// the box); a non-empty path points at a user-supplied mmdb (e.g.
// GeoLite2-Country.mmdb) that must exist — a missing/unreadable file fails
// the build (fail-static, publish reports the reason), never a silent
// fallback.
type GeoSettings struct {
	Enabled          bool     `json:"enabled"`
	DBPath           string   `json:"db_path"`             // path to the .mmdb file; empty = embedded DB-IP Country Lite
	Blacklist        []string `json:"blacklist,omitempty"` // ISO 3166-1 alpha-2 codes
	Whitelist        []string `json:"whitelist,omitempty"`
	WhitelistTrusted bool     `json:"whitelist_trusted,omitempty"` // whitelist hit skips later stages
}

// AuthUser is one account for site-level Basic authentication. Either
// Password (plaintext, for quick internal use) or PasswordHash (argon2id,
// via `kmwafctl hash-password`) must be set, not both.
type AuthUser struct {
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
}

// AuthSettings gates the whole site behind HTTP Basic authentication.
type AuthSettings struct {
	Realm string     `json:"realm,omitempty"` // default "Restricted"
	Users []AuthUser `json:"users"`
}

// DynamicSettings enables response dynamic protection: HTML responses are
// encrypted per request and reassembled by injected JavaScript, so the
// wire format changes on every visit. Requires a secure context
// (HTTPS) because the decoder uses WebCrypto.
type DynamicSettings struct {
	Enabled  bool  `json:"enabled"`
	MinBytes int64 `json:"min_bytes,omitempty"` // skip smaller bodies, default 512
	MaxBytes int64 `json:"max_bytes,omitempty"` // skip larger bodies, default 1 MiB
}

// HealthSettings configures upstream pool health: active probing plus
// passive circuit breaking on consecutive failures.
type HealthSettings struct {
	Enabled       bool   `json:"enabled"`
	Path          string `json:"path,omitempty"`           // probe path, default "/"
	IntervalSec   int    `json:"interval_sec,omitempty"`   // active probe interval, default 10
	TimeoutSec    int    `json:"timeout_sec,omitempty"`    // probe timeout, default 3
	Passive       bool   `json:"passive,omitempty"`        // passive circuit breaker, default on
	FailThreshold int    `json:"fail_threshold,omitempty"` // consecutive failures before cooling down, default 3
	CooldownSec   int    `json:"cooldown_sec,omitempty"`   // passive cooldown, default 30
}

// RespPattern is a custom response-body detection pattern.
type RespPattern struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

// RespFilterSettings configures response-body sensitive-information
// filtering. Presets: "phone", "idcard", "secret".
type RespFilterSettings struct {
	Enabled   bool          `json:"enabled"`
	Action    string        `json:"action,omitempty"` // "mask" (default) | "block"
	Presets   []string      `json:"presets,omitempty"`
	Patterns  []RespPattern `json:"patterns,omitempty"`
	BodyLimit int64         `json:"body_limit,omitempty"` // response scan size cap, default 8 MiB
}

// WebhookSettings pushes every blocked/challenged event to an HTTP endpoint
// (POST JSON, asynchronous queue, drops under backpressure).
type WebhookSettings struct {
	URL        string `json:"url"`
	TimeoutSec int    `json:"timeout_sec,omitempty"` // default 5
	// Secret enables HMAC-SHA256 signing: each POST gets a
	// "X-KingMoat-Signature: sha256=<hex>" header over the raw body so the
	// receiver can verify authenticity.
	Secret string `json:"secret,omitempty"`
	// Keyword appends a "keyword" field to the JSON payload (企业微信/
	// 钉钉机器人关键词安全设置)。Empty = no keyword.
	Keyword string `json:"keyword,omitempty"`

	S3 *S3Settings `json:"s3,omitempty"`
}

// ShipperSettings streams audit events to an external log platform or
// S3-compatible object storage.
type ShipperSettings struct {
	Type       string `json:"type"`                  // "clickhouse" | "elasticsearch" | "loki" | "s3" | "syslog" | "kafka"
	URL        string `json:"url,omitempty"`          // base URL for es/loki/ch (http://...), syslog target (udp|tcp|tls://host:514)
	Index      string `json:"index,omitempty"`        // table / index prefix / label app (default kingmoat)
	BatchSize  int    `json:"batch_size,omitempty"`   // default 100
	FlushSec   int    `json:"flush_sec,omitempty"`    // default 5
	TimeoutSec int    `json:"timeout_sec,omitempty"` // default 5
	// S3-compatible object storage (type "s3"): MinIO, Alibaba Cloud OSS,
	// Huawei Cloud OBS, AWS S3, ... Events are shipped as gzipped NDJSON
	// objects; the daily DB snapshots can be uploaded too (upload_archives).
	Endpoint  string `json:"endpoint,omitempty"` // host[:port], e.g. minio.example.com:9000
	Bucket    string `json:"bucket,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	Region    string `json:"region,omitempty"`
	// Username / Password enable HTTP basic authentication for the
	// elasticsearch / loki / clickhouse sinks (internal deployments commonly
	// require it). Empty = no Authorization header sent.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// UseSSL defaults to the endpoint scheme (https → true, no scheme → true).
	UseSSL *bool `json:"use_ssl,omitempty"`
	// Prefix is the object-key prefix (default "kingmoat/audit").
	Prefix string `json:"prefix,omitempty"`
	// UploadArchives also uploads the daily SQLite snapshot files
	// (type "s3" only, default off).
	UploadArchives bool `json:"upload_archives,omitempty"`
	// Syslog holds the standard-syslog transport options (type "syslog").
	Syslog *SyslogSettings `json:"syslog,omitempty"`
	// Kafka (type "kafka"): bootstrap broker list + topic. Events ship as
	// one JSON message per audit event, keyed by trace_id when present.
	Brokers []string `json:"brokers,omitempty"`
	Topic   string   `json:"topic,omitempty"`
	// UseTLS enables TLS for the kafka connection (default plaintext).
	// SASL reuses Username / Password: "plain" or "scram-sha256" (empty =
	// no authentication).
	UseTLS bool `json:"use_tls,omitempty"`
	SASL   string `json:"sasl,omitempty"`
	// TLSSkipVerify controls broker-certificate verification when UseTLS is
	// on (type "kafka"). nil (absent) keeps the legacy zero-config behavior
	// for internal self-signed brokers (certificates NOT verified); an
	// explicit false enables chain verification.
	TLSSkipVerify *bool `json:"tls_skip_verify,omitempty"`
}

// SyslogSettings configures a standard syslog (RFC 5424 / RFC 3164) sink.
// The target address comes from the shipper URL: udp://host:514,
// tcp://host:514 or tls://host:6514 (Protocol overrides the URL scheme).
type SyslogSettings struct {
	// Protocol is the transport: "udp" (default), "tcp" or "tls". Overrides
	// the URL scheme when set.
	Protocol string `json:"protocol,omitempty"`
	// Format is the message format: "rfc5424" (default) or "rfc3164".
	Format string `json:"format,omitempty"`
	// Framing is the TCP/TLS framing: "octet" (RFC 6587 octet counting,
	// default for RFC 5424) or "newline" (legacy, default for RFC 3164).
	Framing string `json:"framing,omitempty"`
	// Facility is the syslog facility 0..23; 0 (kernel) means "unset" and
	// defaults to 16 (local0).
	Facility int `json:"facility,omitempty"`
	// Severity is the default severity 0..7; 0 (emerg) means "unset" and
	// defaults to 6 (info). Blocked and challenged events ship as warning
	// (4) regardless of this setting.
	Severity int `json:"severity,omitempty"`
	// Hostname is the syslog HOSTNAME field (default: local hostname).
	Hostname string `json:"hostname,omitempty"`
	// AppName overrides the program name (APP-NAME / tag); default is the
	// shipper index ("kingmoat" / "kingmoat_access").
	AppName string `json:"app_name,omitempty"`
	// TLSSkipVerify disables certificate verification for tls:// targets.
	TLSSkipVerify bool `json:"tls_skip_verify,omitempty"`
}

// Validate checks the syslog settings; nil is valid (feature unused).
func (s *SyslogSettings) Validate() error {
	if s == nil {
		return nil
	}
	switch s.Protocol {
	case "", "udp", "tcp", "tls":
	default:
		return errSecurityf("syslog: protocol must be udp, tcp or tls, got %q", s.Protocol)
	}
	switch s.Format {
	case "", "rfc5424", "rfc3164":
	default:
		return errSecurityf("syslog: format must be rfc5424 or rfc3164, got %q", s.Format)
	}
	switch s.Framing {
	case "", "octet", "newline":
	default:
		return errSecurityf("syslog: framing must be octet or newline, got %q", s.Framing)
	}
	if s.Facility < 0 || s.Facility > 23 {
		return errSecurityf("syslog: facility must be 0..23, got %d", s.Facility)
	}
	if s.Severity < 0 || s.Severity > 7 {
		return errSecurityf("syslog: severity must be 0..7, got %d", s.Severity)
	}
	return nil
}

// Validate enforces the per-type channel rules for the audit-log outbound
// (log_shipper). Extracted verbatim from Config.Validate so the publish gate
// and the load-time degradation (NormalizeLegacyOutbound) share ONE set of
// rules — a section the publish gate rejects is exactly a section the loader
// degrades instead of refusing to boot on. nil is valid (feature unused).
func (ls *ShipperSettings) Validate() error {
	if ls == nil {
		return nil
	}
	switch ls.Type {
	case "elasticsearch", "loki", "clickhouse":
		if !isHTTPURL(ls.URL) {
			return fmt.Errorf("config: log_shipper.url must be an http(s) URL")
		}
	case "s3":
		if ls.Endpoint == "" || ls.Bucket == "" || ls.AccessKey == "" || ls.SecretKey == "" {
			return fmt.Errorf("config: log_shipper (s3): endpoint, bucket, access_key and secret_key are required")
		}
	case "syslog":
		// The runtime sink constructor (syslogsink.newClient) rejects a
		// missing syslog block, so letting a nil block publish would store
		// a config that reports applied while delivery never starts
		// (fail-static keeps the previous pipeline). Parity: access_log and
		// ai_audit.ship already require the block.
		if ls.Syslog == nil {
			return fmt.Errorf("config: log_shipper (syslog): a syslog block (protocol/format) is required for type \"syslog\"")
		}
		if err := ls.Syslog.Validate(); err != nil {
			return fmt.Errorf("config: log_shipper (syslog): %w", err)
		}
		if err := validateSyslogURL(ls.URL); err != nil {
			return err
		}
	case "kafka":
		if err := validateKafkaOutbound(ls.Brokers, ls.Topic, ls.SASL, ls.Username, ls.Password); err != nil {
			return fmt.Errorf("config: log_shipper (kafka): %w", err)
		}
	default:
		return fmt.Errorf("config: log_shipper.type must be \"elasticsearch\", \"loki\", \"clickhouse\", \"s3\", \"kafka\" or \"syslog\", got %q", ls.Type)
	}
	return nil
}

// AccessLogSettings configures the full access-log pipeline. Entries are
// batched and pushed to ClickHouse/Elasticsearch/Loki asynchronously; the
// request hot path only pays a bounded-queue send (drops under backpressure
// are counted). This section does NOT store anything locally — local
// recording is a separate decision owned by the access_log_record section
// (see accesslog_record.go), and the outbound sample_pct sampling does not
// affect it.
type AccessLogSettings struct {
	Enabled bool `json:"enabled"`
	// UseAuditChannel reuses the audit-log outbound (log_shipper) for this
	// pipeline instead of the section's own channel fields: type/url/auth,
	// batching, the s3/syslog transports and the kafka parameters are taken
	// from log_shipper, while identity fields (index, sample_pct, syslog
	// app_name, s3 prefix) stay owned by this section. Requires log_shipper
	// to be configured (enforced by Config.Validate); the section's own
	// channel fields are ignored while the switch is on but kept so the
	// operator can switch back without retyping them.
	UseAuditChannel bool   `json:"use_audit_channel,omitempty"`
	Type            string `json:"type"`            // "clickhouse" | "elasticsearch" | "loki" | "s3" | "syslog" | "kafka"
	URL             string `json:"url,omitempty"`   // base URL (HTTP backends; syslog target for syslog; unused for s3)
	Index           string `json:"index,omitempty"` // table / index prefix / bucket (default kingmoat_access)
	// SamplePct keeps only N percent of entries (1..100); default 100.
	SamplePct  int `json:"sample_pct,omitempty"`
	BatchSize  int `json:"batch_size,omitempty"`  // default 200
	FlushSec   int `json:"flush_sec,omitempty"`   // default 5
	TimeoutSec int `json:"timeout_sec,omitempty"` // default 5
	// S3 sink settings (type = "s3"; MinIO / OSS / OBS / AWS S3 compatible).
	S3 *S3Settings `json:"s3,omitempty"`
	// Username / Password enable HTTP basic authentication for the
	// clickhouse / elasticsearch / loki backends. Empty = no auth header.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Syslog holds the standard-syslog transport options (type "syslog").
	Syslog *SyslogSettings `json:"syslog,omitempty"`
	// Kafka (type "kafka"): bootstrap broker list + topic; entries ship as
	// one JSON message per access entry. Ignored while use_audit_channel is
	// on (the kafka parameters then come from log_shipper).
	Brokers []string `json:"brokers,omitempty"`
	Topic   string   `json:"topic,omitempty"`
	// UseTLS enables TLS for the kafka connection (default plaintext); SASL
	// reuses Username / Password: "plain" or "scram-sha256" (empty = no
	// authentication). TLSSkipVerify controls broker-certificate
	// verification when UseTLS is on; nil keeps the legacy zero-config
	// behavior (self-signed certificates NOT verified).
	UseTLS        bool   `json:"use_tls,omitempty"`
	SASL          string `json:"sasl,omitempty"`
	TLSSkipVerify *bool  `json:"tls_skip_verify,omitempty"`
}

// SamplePctOrDefault returns the effective sampling percentage (default 100).
func (a *AccessLogSettings) SamplePctOrDefault() int {
	if a == nil || a.SamplePct <= 0 || a.SamplePct > 100 {
		return 100
	}
	return a.SamplePct
}

// Validate enforces the per-type channel rules for a directly configured
// access-log outbound, mirroring AIAuditSettings.Validate for ship: the
// runtime sink constructors reject an incomplete section (fail-static keeps
// the previous pipeline while the console still reports applied), so the
// same rules are enforced at publish time. While use_audit_channel is on the
// channel parameters come from log_shipper (enforced by Config.Validate) and
// the section's own channel fields are ignored but retained for switching
// back — they must not be required here.
func (a *AccessLogSettings) Validate() error {
	if a == nil {
		return nil
	}
	if !a.Enabled || a.UseAuditChannel {
		return nil
	}
	if !outboundSinkTypeAllowed(a.Type) {
		return fmt.Errorf("config: access_log.type must be one of %s, got %q", strings.Join(outboundSinkTypes, "/"), a.Type)
	}
	switch a.Type {
	case "clickhouse", "elasticsearch", "loki":
		if !isHTTPURL(a.URL) {
			return fmt.Errorf("config: access_log.url must be an http(s) URL for type %q", a.Type)
		}
	case "s3":
		if a.S3 == nil {
			return fmt.Errorf("config: access_log.type s3 requires the s3 block (endpoint, bucket, keys)")
		}
		if err := a.S3.Validate(); err != nil {
			return fmt.Errorf("config: access_log.%s", err.Error())
		}
	case "syslog":
		// The runtime sink constructor rejects a missing syslog block while
		// the probe silently defaults it, so a nil block must not publish:
		// the config would report applied while delivery never starts.
		if a.Syslog == nil {
			return fmt.Errorf("config: access_log.type syslog requires the syslog block (protocol/format)")
		}
		// SyslogSettings.Validate / validateSyslogURL build their errors with
		// errSecurityf ("config: security: ") because they are shared with
		// the security block; strip that prefix so the error reads as one
		// coherent access_log message.
		if err := a.Syslog.Validate(); err != nil {
			return fmt.Errorf("config: access_log.syslog: %s", strings.TrimPrefix(err.Error(), "config: security: "))
		}
		if err := validateSyslogURL(a.URL); err != nil {
			return fmt.Errorf("config: access_log.syslog: %s", strings.TrimPrefix(err.Error(), "config: security: "))
		}
	case "kafka":
		if err := validateKafkaOutbound(a.Brokers, a.Topic, a.SASL, a.Username, a.Password); err != nil {
			return fmt.Errorf("config: access_log.kafka: %w", err)
		}
	}
	return nil
}

// validateSyslogURL checks the syslog target address: scheme udp://, tcp://
// or tls:// plus host[:port] (no path, no user:pass@ userinfo). A bare
// "host:514" is rejected (check 1 cannot see a host in it); only the
// scheme-less "//host[:port]" form is accepted and defaults to udp at the
// sink.
//
// The console/API error never echoes the raw input: a syslog URL may embed
// user:pass@host credentials and validation errors are auditor-readable on
// the publish path. The failing check is identified by step number instead;
// the input stays available server-side through slog with the password
// masked (see syslogURLCheckFailed), so triage can correlate without the
// credential ever reaching the log.
func validateSyslogURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return syslogURLCheckFailed(1, raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "udp", "tcp", "tls":
		if u.Path != "" && u.Path != "/" {
			return syslogURLCheckFailed(3, raw)
		}
		if u.User != nil {
			return syslogURLCheckFailed(4, raw)
		}
		return nil
	case "":
		if u.Path != "" && u.Path != "/" {
			return syslogURLCheckFailed(3, raw)
		}
		if u.User != nil {
			return syslogURLCheckFailed(4, raw)
		}
		return nil // scheme-less //host[:port]; transport defaults to udp
	default:
		return syslogURLCheckFailed(2, raw)
	}
}

// syslogURLCheckFailed builds the no-echo failure for one syslog URL check
// step (1 地址形态含主机名，2 协议，3 路径，4 用户名密码) and keeps the input in
// the server-side log for correlation — with the password masked
// (maskURLForLog): log readers have host-level privileges but must never see
// a credential.
func syslogURLCheckFailed(step int, raw string) error {
	slog.Warn("config: syslog url validation failed", "step", step, "input", maskURLForLog(raw))
	switch step {
	case 2:
		return errSecurityf("syslog 地址第 %d 处校验未通过：协议必须是 udp、tcp 或 tls", step)
	case 3:
		return errSecurityf("syslog 地址第 %d 处校验未通过：地址不能包含路径部分", step)
	case 4:
		return errSecurityf("syslog 地址第 %d 处校验未通过：地址不能包含用户名密码（user:pass@）", step)
	default:
		return errSecurityf("syslog 地址第 %d 处校验未通过：地址必须为 udp://host[:514]、tcp://host[:514] 或 tls://host[:6514] 形式，且包含主机名", step)
	}
}

// URLPasswordMask is the token substituted for the password component of a
// URL userinfo wherever a URL must be rendered without revealing its
// credential. Every mask site shares this constant through MaskURLCredentials
// (validation-failure logs below, the redacted GET /api/config view in
// internal/api and the publish-path round-trip detection) so the masked shape
// is defined once and can never drift between log and API.
const URLPasswordMask = "******"

// MaskURLCredentials returns raw with the password component of any
// user:pass@ userinfo replaced by URLPasswordMask. The username and the
// scheme://host:port/path stay intact so a masked URL still identifies its
// target. Inputs without a password-bearing userinfo (or that fail to
// parse) are returned unchanged — masking is deliberately value-preserving:
// the publish path compares masked shapes to detect a redacted round-trip,
// so it must be a pure function of the input. The token is spliced into the
// original text instead of re-serializing via url.URL.String(), which
// percent-escapes the password component (****** would round-trip as
// %2A...) and break the literal mask-token detection on publish. Callers
// that must guarantee no echo of unparseable, potentially credential-shaped
// input (the server log) wrap this with maskURLForLog instead.
func MaskURLCredentials(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, hasPw := u.User.Password(); !hasPw {
		return raw
	}
	// Splice the token into the original bytes. The authority run starts
	// after the "//" marker and ends at the first "/" (or end of input);
	// within it, the last "@" separates userinfo from host and the first
	// ":" separates username from password (literal ":" in a username must
	// be percent-encoded, so the first one is always the separator) — the
	// same split rules url.Parse itself applies.
	ai := strings.Index(raw, "//")
	if ai < 0 {
		return raw
	}
	authority := raw[ai+2:]
	if slash := strings.Index(authority, "/"); slash >= 0 {
		authority = authority[:slash]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return raw
	}
	colon := strings.Index(authority[:at], ":")
	if colon < 0 {
		return raw
	}
	cut := ai + 2 + colon + 1
	return raw[:cut] + URLPasswordMask + raw[ai+2+at:]
}

// maskURLForLog renders raw for the server-side log. A parseable
// password-bearing userinfo gets the precise MaskURLCredentials treatment;
// any other input that still contains "@" is potentially credential-shaped
// but not precisely parseable (e.g. an invalid port defeats url.Parse while
// user:pass@ survives verbatim) and is replaced by a length descriptor —
// the red line is that a password never reaches the log, scheme/host
// details are a nice-to-have, not a guarantee worth risking it for.
func maskURLForLog(raw string) string {
	if masked := MaskURLCredentials(raw); masked != raw {
		return masked
	}
	if strings.Contains(raw, "@") {
		return fmt.Sprintf("<redacted input, %d bytes>", len(raw))
	}
	return raw
}

// outboundSinkTypes is the sink-type set shared by the audit outbound
// (log_shipper) and the access-log / AI-session outbounds, both when the
// latter are directly configured and when they reuse the audit channel
// (use_audit_channel). The three sections must keep this set aligned;
// Config.Validate rejects a channel type the reusing pipeline cannot speak.
var outboundSinkTypes = []string{"clickhouse", "elasticsearch", "loki", "s3", "syslog", "kafka"}

func outboundSinkTypeAllowed(t string) bool {
	return slices.Contains(outboundSinkTypes, t)
}

// validateKafkaOutbound checks the kafka transport parameters shared by
// log_shipper and the access/AI outbounds (same fields, same rules): at
// least one broker, a topic, an optional SASL mechanism and — for plain /
// scram-sha256 — both SASL credentials, so the shipper never fails its
// handshake (or silently stalls) over an incomplete kafka block. The topic
// is a channel parameter: reusing pipelines (use_audit_channel) share the
// audit outbound's topic, and per-class identity is carried in the message
// payload rather than the topic name.
func validateKafkaOutbound(brokers []string, topic, sasl, username, password string) error {
	nBrokers := 0
	for _, b := range brokers {
		if strings.TrimSpace(b) != "" {
			nBrokers++
		}
	}
	if nBrokers == 0 {
		return fmt.Errorf("at least one broker is required")
	}
	if strings.TrimSpace(topic) == "" {
		return fmt.Errorf("topic is required")
	}
	switch sasl {
	case "", "none", "plain", "scram-sha256":
	default:
		return fmt.Errorf("sasl must be \"none\", \"plain\" or \"scram-sha256\", got %q", sasl)
	}
	if sasl == "plain" || sasl == "scram-sha256" {
		if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
			return fmt.Errorf("sasl %q requires both username and password", sasl)
		}
	}
	return nil
}

// IPGroupSettings subscribes an IP list from a URL or a local file. Lists
// may contain comments (#) and one IP/CIDR per line; ACL entries reference
// them as "group:<name>".
type IPGroupSettings struct {
	Name        string `json:"name"`
	URL         string `json:"url,omitempty"`
	File        string `json:"file,omitempty"`
	IntervalMin int    `json:"interval_min,omitempty"` // refresh interval, default 60
	// Members is a manually maintained list (IP/CIDR per entry). When set the
	// group needs no subscription source; it loads once per config revision.
	Members []string `json:"members,omitempty"`
}

// validateGroups checks that every ACL "group:<name>" reference resolves
// to a subscribed IP group defined at the top level.
func (s *SecuritySettings) validateGroups(groups map[string]bool) error {
	if s.ACL == nil {
		return nil
	}
	for _, c := range append(append([]string{}, s.ACL.Blacklist...), s.ACL.Whitelist...) {
		if isGroupRef(c) && !groups[c[6:]] {
			return errSecurityf("acl: %q references an unknown ip_group", c)
		}
	}
	return nil
}

// Validate checks the security sub-blocks (called from Config.Validate).
func (s *SecuritySettings) Validate() error {
	if s.ACL != nil {
		for _, c := range append(append([]string{}, s.ACL.Blacklist...), s.ACL.Whitelist...) {
			if isGroupRef(c) {
				continue // existence checked against ip_groups by Config.Validate
			}
			if !validCIDR(c) {
				return errSecurityf("acl: %q is not a valid IP, CIDR or group reference", c)
			}
		}
	}
	if s.RateLimit != nil {
		rl := s.RateLimit
		if rl.Requests <= 0 {
			return errSecurityf("ratelimit: requests must be > 0")
		}
		switch rl.Key {
		case "", "ip", "ip+uri":
		default:
			return errSecurityf("ratelimit: key must be \"ip\" or \"ip+uri\", got %q", rl.Key)
		}
		switch rl.Action {
		case "", "deny", "throttle":
		default:
			return errSecurityf("ratelimit: action must be \"deny\" or \"throttle\", got %q", rl.Action)
		}
	}
	if s.Captcha != nil && s.Captcha.Enabled && s.Captcha.Tolerance < 0 {
		return errSecurityf("captcha: tolerance must be >= 0")
	}
	if s.Geo != nil && s.Geo.Enabled {
		// db_path empty → use the embedded GeoIP country database
		// (internal/geoip); a custom path always wins.
		for _, cc := range append(append([]string{}, s.Geo.Blacklist...), s.Geo.Whitelist...) {
			if len(cc) < 2 || len(cc) > 3 {
				return errSecurityf("geo: %q is not a valid ISO country code", cc)
			}
		}
	}
	if s.Auth != nil {
		if len(s.Auth.Users) == 0 {
			return errSecurityf("auth: at least one user is required")
		}
		seen := map[string]bool{}
		for _, u := range s.Auth.Users {
			if u.Username == "" {
				return errSecurityf("auth: username is empty")
			}
			if seen[u.Username] {
				return errSecurityf("auth: duplicate user %q", u.Username)
			}
			seen[u.Username] = true
			if (u.Password == "") == (u.PasswordHash == "") {
				return errSecurityf("auth: user %q must set exactly one of password / password_hash", u.Username)
			}
		}
	}
	if s.RespFilter != nil {
		rf := s.RespFilter
		switch rf.Action {
		case "", "mask", "block":
		default:
			return errSecurityf("resp_filter: action must be \"mask\" or \"block\", got %q", rf.Action)
		}
	}
	if s.Dynamic != nil && s.Dynamic.Enabled {
		d := s.Dynamic
		if d.MaxBytes > 0 && d.MinBytes > 0 && d.MaxBytes < d.MinBytes {
			return errSecurityf("dynamic: max_bytes must be >= min_bytes")
		}
	}
	return nil
}

func isGroupRef(s string) bool {
	return len(s) > 6 && s[:6] == "group:"
}

func validCIDR(s string) bool {
	// Accept bare IPs and CIDR blocks alike.
	if !containsByte(s, '/') {
		return isIP(s)
	}
	return isCIDR(s)
}
