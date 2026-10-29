package config

import (
	"strings"
	"testing"
)

// esChannel returns a minimal valid log_shipper (elasticsearch) section.
func esChannel() *ShipperSettings {
	return &ShipperSettings{Type: "elasticsearch", URL: "http://127.0.0.1:9200"}
}

func accessUseChannel() *AccessLogSettings {
	return &AccessLogSettings{Enabled: true, UseAuditChannel: true}
}

func aiUseChannel() *AIAuditSettings {
	return &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, UseAuditChannel: true}}
}

// TestUseAuditChannelRequiresLogShipper: a pipeline reusing the audit
// channel cannot be saved while the audit-log outbound (log_shipper) is
// absent — that state would be silently dead (ShipperSettings has no
// enabled flag, a nil section means the outbound is off).
func TestUseAuditChannelRequiresLogShipper(t *testing.T) {
	c := &Config{ListenHTTP: ":80", AccessLog: accessUseChannel()}
	err := c.Validate()
	if err == nil {
		t.Fatal("access_log.use_audit_channel without log_shipper must be rejected")
	}
	if !strings.Contains(err.Error(), "access_log.use_audit_channel") || !strings.Contains(err.Error(), "log_shipper") {
		t.Fatalf("unfriendly access channel error: %v", err)
	}

	c = &Config{ListenHTTP: ":80", AiAudit: aiUseChannel()}
	err = c.Validate()
	if err == nil {
		t.Fatal("ai_audit.ship.use_audit_channel without log_shipper must be rejected")
	}
	if !strings.Contains(err.Error(), "ai_audit.ship.use_audit_channel") || !strings.Contains(err.Error(), "log_shipper") {
		t.Fatalf("unfriendly ai channel error: %v", err)
	}
}

// TestUseAuditChannelDormantWhenOutboundDisabled: the switch only matters
// while its outbound is enabled — a dormant switch on a disabled section
// must not block a publish (the publish that re-enables shipping
// re-validates the whole config anyway).
func TestUseAuditChannelDormantWhenOutboundDisabled(t *testing.T) {
	c := &Config{
		ListenHTTP: ":80",
		AccessLog:  &AccessLogSettings{Enabled: false, UseAuditChannel: true},
		AiAudit:    &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: false, UseAuditChannel: true}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("dormant switch on disabled outbounds must not be rejected: %v", err)
	}
}

// TestUseAuditChannelWithLogShipperOK: with the audit-log outbound in place
// every sink type is an acceptable channel for both pipelines, and the
// switching section's own channel fields are ignored — not required, not
// validated (empty type, empty url and stale values must all pass).
func TestUseAuditChannelWithLogShipperOK(t *testing.T) {
	cases := []struct {
		name string
		ls   *ShipperSettings
	}{
		{name: "elasticsearch channel", ls: esChannel()},
		{name: "clickhouse channel", ls: &ShipperSettings{Type: "clickhouse", URL: "http://127.0.0.1:8123"}},
		{name: "loki channel", ls: &ShipperSettings{Type: "loki", URL: "http://127.0.0.1:3100"}},
		{name: "s3 channel", ls: &ShipperSettings{Type: "s3", Endpoint: "minio.internal:9000", Bucket: "kingmoat", AccessKey: "k", SecretKey: "s"}},
		{name: "syslog channel", ls: &ShipperSettings{Type: "syslog", URL: "udp://10.0.0.5:514", Syslog: &SyslogSettings{}}},
		{name: "kafka channel", ls: &ShipperSettings{Type: "kafka", Brokers: []string{"broker-1.internal:9092"}, Topic: "kingmoat-audit"}},
	}
	for _, tc := range cases {
		c := &Config{ListenHTTP: ":80", LogShipper: tc.ls, AccessLog: accessUseChannel()}
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: access reuse rejected: %v", tc.name, err)
		}
		ai := aiUseChannel()
		ai.Ship.Type = "bogus" // stale value retained from a previous direct config
		ai.Ship.URL = ""
		c = &Config{ListenHTTP: ":80", LogShipper: tc.ls, AiAudit: ai}
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: ai reuse rejected: %v", tc.name, err)
		}
	}
}

// TestAIAuditShipTypeSet: the direct (switch off) type set must include
// kafka — aligned with the audit outbound — and reject unknown types with
// the full allowed set in the message.
func TestAIAuditShipTypeSet(t *testing.T) {
	ok := []AIAuditShipSettings{
		{Enabled: true, Type: "elasticsearch", URL: "http://127.0.0.1:9200"},
		{Enabled: true, Type: "clickhouse", URL: "http://127.0.0.1:8123"},
		{Enabled: true, Type: "loki", URL: "http://127.0.0.1:3100"},
		{Enabled: true, Type: "s3", S3: &S3Settings{Endpoint: "minio.internal:9000", Bucket: "kingmoat"}},
		{Enabled: true, Type: "syslog", URL: "udp://10.0.0.5:514", Syslog: &SyslogSettings{}},
		{Enabled: true, Type: "kafka", Brokers: []string{"broker-1.internal:9092"}, Topic: "kingmoat-ai"},
	}
	for _, ship := range ok {
		if err := (&AIAuditSettings{Ship: &ship}).Validate(); err != nil {
			t.Fatalf("type %q must be accepted: %v", ship.Type, err)
		}
	}
	err := (&AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "bogus"}}).Validate()
	if err == nil {
		t.Fatal("unknown ship.type must be rejected")
	}
	for _, want := range outboundSinkTypes {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must list allowed type %q: %v", want, err)
		}
	}
}

// TestOutboundSinkTypeAllowed guards the shared sink-type set used by the
// audit-channel cross rule (a log_shipper type the reusing pipeline cannot
// speak must never pass).
func TestOutboundSinkTypeAllowed(t *testing.T) {
	for _, ok := range outboundSinkTypes {
		if !outboundSinkTypeAllowed(ok) {
			t.Fatalf("type %q must be allowed", ok)
		}
	}
	if outboundSinkTypeAllowed("bogus") || outboundSinkTypeAllowed("") {
		t.Fatal("unknown/empty type must not be allowed")
	}
}

// TestAIAuditShipKafkaDirectValidation: a direct kafka sink mirrors the
// log_shipper kafka rules (brokers, topic, SASL mechanism + credentials).
func TestAIAuditShipKafkaDirectValidation(t *testing.T) {
	cases := []struct {
		name string
		ship AIAuditShipSettings
		want string
	}{
		{name: "no brokers", ship: AIAuditShipSettings{Enabled: true, Type: "kafka", Topic: "t"}, want: "at least one broker"},
		{name: "no topic", ship: AIAuditShipSettings{Enabled: true, Type: "kafka", Brokers: []string{"b:9092"}}, want: "topic is required"},
		{name: "bad sasl", ship: AIAuditShipSettings{Enabled: true, Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t", SASL: "md5"}, want: `sasl must be "none", "plain" or "scram-sha256"`},
		{name: "sasl without credentials", ship: AIAuditShipSettings{Enabled: true, Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t", SASL: "plain"}, want: "requires both username and password"},
	}
	for _, tc := range cases {
		err := (&AIAuditSettings{Ship: &tc.ship}).Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: want error %q, got %v", tc.name, tc.want, err)
		}
	}
	ship := AIAuditShipSettings{Enabled: true, Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t", SASL: "plain", Username: "u", Password: "p"}
	if err := (&AIAuditSettings{Ship: &ship}).Validate(); err != nil {
		t.Fatalf("sasl plain with credentials must pass: %v", err)
	}
}

// TestAIAuditShipS3AndSyslogSubstructs: the newly added s3/syslog
// sub-structures are validated for direct configs (the ship section used to
// be unable to express them at all).
func TestAIAuditShipS3AndSyslogSubstructs(t *testing.T) {
	ai := &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "s3"}}
	err := ai.Validate()
	if err == nil || !strings.Contains(err.Error(), "requires the s3 block") {
		t.Fatalf("s3 without s3 block must be rejected, got %v", err)
	}
	ai = &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "s3", S3: &S3Settings{Endpoint: "minio.internal:9000"}}}
	err = ai.Validate()
	if err == nil || !strings.Contains(err.Error(), "endpoint and bucket are required") {
		t.Fatalf("s3 without bucket must be rejected, got %v", err)
	}
	// The legacy flat use_ssl/prefix fields stay valid alongside the block.
	yes := true
	ai = &AIAuditSettings{Ship: &AIAuditShipSettings{
		Enabled: true, Type: "s3", UseSSL: &yes, Prefix: "kingmoat/ai",
		S3: &S3Settings{Endpoint: "minio.internal:9000", Bucket: "kingmoat"},
	}}
	if err := ai.Validate(); err != nil {
		t.Fatalf("flat legacy s3 seeds must still pass: %v", err)
	}

	ai = &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "syslog", URL: "udp://10.0.0.5:514", Syslog: &SyslogSettings{Protocol: "smtp"}}}
	err = ai.Validate()
	if err == nil || !strings.Contains(err.Error(), "protocol must be udp, tcp or tls") {
		t.Fatalf("bad syslog protocol must be rejected, got %v", err)
	}
	ai = &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "syslog", URL: "http://10.0.0.5:514", Syslog: &SyslogSettings{}}}
	err = ai.Validate()
	if err == nil || !strings.Contains(err.Error(), "协议必须是 udp、tcp 或 tls") {
		t.Fatalf("http syslog target must be rejected, got %v", err)
	}
	ai = &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "syslog", Syslog: &SyslogSettings{}}}
	err = ai.Validate()
	if err == nil || !strings.Contains(err.Error(), "第 1 处校验未通过") {
		t.Fatalf("syslog without target url must be rejected, got %v", err)
	}
	ai = &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "syslog", URL: "syslog.internal:514", Syslog: &SyslogSettings{Format: "rfc3164", Framing: "newline"}}}
	err = ai.Validate()
	if err == nil || !strings.Contains(err.Error(), "第 1 处校验未通过") {
		t.Fatalf("bare host:port syslog target must be rejected, got %v", err)
	}
	ai = &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "syslog", URL: "udp://syslog.internal:514", Syslog: &SyslogSettings{Format: "rfc3164", Framing: "newline"}}}
	if err := ai.Validate(); err != nil {
		t.Fatalf("valid direct syslog config rejected: %v", err)
	}
}

// TestAIAuditShipLegacyESOnlyStillValid: configs written by the current
// console (ES-only ship section) must keep validating unchanged.
func TestAIAuditShipLegacyESOnlyStillValid(t *testing.T) {
	c := &Config{
		ListenHTTP: ":80",
		AiAudit: &AIAuditSettings{Ship: &AIAuditShipSettings{
			Enabled: true, Type: "elasticsearch", URL: "http://127.0.0.1:9200",
			Index: "kingmoat_ai_sessions", Username: "u", Password: "p",
		}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("legacy ES-only ai_audit.ship config must stay valid: %v", err)
	}
}

// TestAccessLogDirectChannelValidation: a directly configured (switch off)
// access_log section enforces the same per-type channel rules as
// ai_audit.ship — the runtime sink constructors reject an incomplete
// section, so publishing one used to report applied while delivery silently
// kept the old pipeline. While use_audit_channel is on, the section's own
// channel fields are ignored and must not be required.
func TestAccessLogDirectChannelValidation(t *testing.T) {
	bad := []struct {
		name string
		al   *AccessLogSettings
		want string
	}{
		{name: "unknown type", al: &AccessLogSettings{Enabled: true, Type: "bogus"}, want: "type must be one of"},
		{name: "empty type", al: &AccessLogSettings{Enabled: true}, want: "type must be one of"},
		{name: "elasticsearch no url", al: &AccessLogSettings{Enabled: true, Type: "elasticsearch"}, want: "url must be an http(s) URL"},
		{name: "clickhouse bare host", al: &AccessLogSettings{Enabled: true, Type: "clickhouse", URL: "ch.internal:8123"}, want: "url must be an http(s) URL"},
		{name: "loki ftp url", al: &AccessLogSettings{Enabled: true, Type: "loki", URL: "ftp://l.internal:3100"}, want: "url must be an http(s) URL"},
		{name: "s3 without block", al: &AccessLogSettings{Enabled: true, Type: "s3"}, want: "requires the s3 block"},
		{name: "s3 without bucket", al: &AccessLogSettings{Enabled: true, Type: "s3", S3: &S3Settings{Endpoint: "minio.internal:9000"}}, want: "endpoint and bucket are required"},
		{name: "kafka without topic", al: &AccessLogSettings{Enabled: true, Type: "kafka", Brokers: []string{"b:9092"}}, want: "topic is required"},
		{name: "syslog without block", al: &AccessLogSettings{Enabled: true, Type: "syslog", URL: "udp://10.0.0.5:514"}, want: "requires the syslog block"},
		{name: "syslog bad url", al: &AccessLogSettings{Enabled: true, Type: "syslog", URL: "http://10.0.0.5:514", Syslog: &SyslogSettings{}}, want: "协议必须是 udp、tcp 或 tls"},
	}
	for _, tc := range bad {
		c := &Config{ListenHTTP: ":80", AccessLog: tc.al}
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: want error containing %q, got %v", tc.name, tc.want, err)
		}
		if !strings.Contains(err.Error(), "access_log") {
			t.Fatalf("%s: error must name the section: %v", tc.name, err)
		}
	}

	// A complete direct section publishes.
	ok := []AccessLogSettings{
		{Enabled: true, Type: "elasticsearch", URL: "http://127.0.0.1:9200"},
		{Enabled: true, Type: "syslog", URL: "udp://10.0.0.5:514", Syslog: &SyslogSettings{}},
		{Enabled: true, Type: "s3", S3: &S3Settings{Endpoint: "minio.internal:9000", Bucket: "kingmoat"}},
		{Enabled: true, Type: "kafka", Brokers: []string{"b:9092"}, Topic: "kingmoat_access"},
	}
	for _, al := range ok {
		c := &Config{ListenHTTP: ":80", AccessLog: &al}
		if err := c.Validate(); err != nil {
			t.Fatalf("complete direct %s section must pass: %v", al.Type, err)
		}
	}

	// use_audit_channel on: stale own channel fields are ignored (only the
	// channel itself is validated by the cross rule).
	c := &Config{
		ListenHTTP: ":80",
		LogShipper: esChannel(),
		AccessLog:  &AccessLogSettings{Enabled: true, UseAuditChannel: true, Type: "bogus", URL: ""},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("reuse with stale own channel fields must pass: %v", err)
	}

	// A disabled section with empty channel fields stays valid (dormant).
	c = &Config{ListenHTTP: ":80", AccessLog: &AccessLogSettings{Enabled: false}}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled section with empty channel fields must pass: %v", err)
	}
}

// TestSyslogBlockRequiredAtPublish: type=syslog without the syslog block is
// rejected for all three outbound sections — the runtime sink constructor
// rejects it while the probe silently defaults it, so the old publish-time
// tolerance agreed on a state that could never ship.
func TestSyslogBlockRequiredAtPublish(t *testing.T) {
	c := &Config{ListenHTTP: ":80", AccessLog: &AccessLogSettings{
		Enabled: true, Type: "syslog", URL: "udp://10.0.0.5:514",
	}}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "requires the syslog block") {
		t.Fatalf("access_log syslog without block must be rejected, got %v", err)
	}

	// the audit channel (log_shipper) itself: same rule — the runtime sink
	// it feeds is the same syslogsink constructor
	c = &Config{ListenHTTP: ":80", LogShipper: &ShipperSettings{
		Type: "syslog", URL: "udp://10.0.0.5:514",
	}}
	err = c.Validate()
	if err == nil || !strings.Contains(err.Error(), "a syslog block (protocol/format) is required") {
		t.Fatalf("log_shipper syslog without block must be rejected, got %v", err)
	}
	c.LogShipper.Syslog = &SyslogSettings{}
	if err := c.Validate(); err != nil {
		t.Fatalf("log_shipper syslog with empty block must pass: %v", err)
	}

	ai := &AIAuditSettings{Ship: &AIAuditShipSettings{
		Enabled: true, Type: "syslog", URL: "udp://10.0.0.5:514",
	}}
	err = ai.Validate()
	if err == nil || !strings.Contains(err.Error(), "requires the syslog block") {
		t.Fatalf("ai_audit.ship syslog without block must be rejected, got %v", err)
	}
	ai.Ship.Syslog = &SyslogSettings{}
	if err := ai.Validate(); err != nil {
		t.Fatalf("ship syslog with empty block must pass: %v", err)
	}
}

// TestValidateSyslogURLNoRawEcho pins C3-FIX: the validation error never
// echoes the raw URL (it may embed user:pass@host credentials and surfaces
// on auditor-readable publish paths); each failing check identifies itself
// by step number instead, and the enum checks (protocol/format/framing)
// stay untouched.
func TestValidateSyslogURLNoRawEcho(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string // step fragment identifying the failing check
	}{
		{name: "no host", raw: "udp://admin:secret@", want: "第 1 处校验未通过"},
		{name: "bad scheme with userinfo", raw: "ftp://admin:secret@h:514", want: "第 2 处校验未通过"},
		{name: "path with userinfo", raw: "udp://admin:secret@h:514/log", want: "第 3 处校验未通过"},
		{name: "userinfo on valid udp url", raw: "udp://admin:secret@h:514", want: "第 4 处校验未通过"},
		{name: "user-only userinfo on tcp", raw: "tcp://admin@h:514", want: "第 4 处校验未通过"},
		{name: "userinfo on scheme-less url", raw: "//admin:secret@h:514", want: "第 4 处校验未通过"},
	}
	for _, tc := range cases {
		err := validateSyslogURL(tc.raw)
		if err == nil {
			t.Fatalf("%s: want a validation error", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: error must identify the failing check %q, got %q", tc.name, tc.want, err)
		}
		if strings.Contains(err.Error(), "admin") || strings.Contains(err.Error(), "secret") {
			t.Fatalf("%s: error must not echo the raw url or its userinfo, got %q", tc.name, err)
		}
	}
	// Enum checks keep their verbatim got %q echo (values, never the URL).
	if err := (&SyslogSettings{Protocol: "smtp"}).Validate(); err == nil ||
		!strings.Contains(err.Error(), `got "smtp"`) {
		t.Fatalf("enum echo must stay for protocol, got %v", err)
	}
}
