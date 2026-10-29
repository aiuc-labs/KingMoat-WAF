package config

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

// v0713AccessLogRaw is the exact flat-s3 shape the v0.7.13 console posted
// (Settings.vue access_log branch): flat endpoint/bucket/prefix/access_key/
// secret_key/use_ssl next to type "s3", no nested s3 block.
const v0713AccessLogRaw = `{
  "enabled": true, "type": "s3", "index": "kingmoat_access", "sample_pct": 100,
  "endpoint": "minio.internal:9000", "bucket": "waf-logs", "prefix": "kingmoat",
  "access_key": "ak", "secret_key": "sk", "use_ssl": true
}`

func TestNormalizeMigratesFlatAccessLogS3(t *testing.T) {
	in := []byte(`{"listen_http":":8080","access_log":` + v0713AccessLogRaw + `}`)
	out, applied, err := NormalizeLegacyOutboundJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || !strings.Contains(applied[0], "access_log") || !strings.Contains(applied[0], "s3") {
		t.Fatalf("applied = %v, want one access_log s3 migration", applied)
	}
	var cfg Config
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	al := cfg.AccessLog
	if al == nil || al.S3 == nil {
		t.Fatal("nested s3 block missing after migration")
	}
	if al.S3.Endpoint != "minio.internal:9000" || al.S3.Bucket != "waf-logs" ||
		al.S3.Prefix != "kingmoat" || al.S3.AccessKey != "ak" || al.S3.SecretKey != "sk" || !al.S3.UseSSL {
		t.Fatalf("migrated s3 block wrong: %+v", al.S3)
	}
	// The flat keys must be gone from the section (moved into s3, not copied):
	// decode the output at the JSON level, the struct cannot carry them.
	var probe struct {
		AccessLog struct {
			Endpoint json.RawMessage `json:"endpoint"`
			Bucket   json.RawMessage `json:"bucket"`
			S3       json.RawMessage `json:"s3"`
		} `json:"access_log"`
	}
	if err := json.Unmarshal(out, &probe); err != nil {
		t.Fatal(err)
	}
	if probe.AccessLog.Endpoint != nil || probe.AccessLog.Bucket != nil {
		t.Fatal("flat keys must be moved out of the section, not left in place")
	}
	if probe.AccessLog.S3 == nil {
		t.Fatal("nested s3 block must be present in the output JSON")
	}
	if err := (&Config{ListenHTTP: ":8080", AccessLog: al}).Validate(); err != nil {
		t.Fatalf("migrated config must validate: %v", err)
	}
}

// TestNormalizeKeepsFlatKeysWhenAbsent: a type=s3 access_log with NO s3 data
// at all (neither nested block nor flat keys) is left untouched — synthesizing
// an empty block would only blur the strict validate error.
func TestNormalizeKeepsFlatKeysWhenAbsent(t *testing.T) {
	in := []byte(`{"listen_http":":8080","access_log":{"enabled":true,"type":"s3"}}`)
	out, applied, err := NormalizeLegacyOutboundJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 0 || !bytes.Equal(out, in) {
		t.Fatalf("nothing to migrate must be a byte-identical no-op, applied=%v", applied)
	}
}

func TestNormalizeSynthesizesSyslogBlocks(t *testing.T) {
	in := []byte(`{
		"listen_http":":8080",
		"log_shipper":{"type":"syslog","url":"tcp://siem.example.com:514","index":"kingmoat"},
		"access_log":{"enabled":true,"type":"syslog","url":"tls://siem.example.com:6514","index":"kingmoat_access"},
		"ai_audit":{"ship":{"enabled":true,"type":"syslog","url":"udp://collector.internal:514","index":"kingmoat_ai_sessions"}}
	}`)
	out, applied, err := NormalizeLegacyOutboundJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 3 {
		t.Fatalf("applied = %v, want three syslog syntheses", applied)
	}
	for _, s := range []string{"log_shipper", "access_log", "ai_audit.ship"} {
		if !strings.Contains(strings.Join(applied, "; "), s) {
			t.Fatalf("applied missing %q: %v", s, applied)
		}
	}
	var cfg Config
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		protocol string
		syslog   *SyslogSettings
		url      string
	}{
		{"log_shipper", "tcp", cfg.LogShipper.Syslog, cfg.LogShipper.URL},
		{"access_log", "tls", cfg.AccessLog.Syslog, cfg.AccessLog.URL},
		{"ai_audit.ship", "udp", cfg.AiAudit.Ship.Syslog, cfg.AiAudit.Ship.URL},
	}
	for _, c := range cases {
		if c.syslog == nil {
			t.Fatalf("%s: syslog block not synthesized", c.name)
		}
		if c.syslog.Protocol != c.protocol {
			t.Fatalf("%s: protocol = %q, want %q (from url %q)", c.name, c.syslog.Protocol, c.protocol, c.url)
		}
		if c.syslog.Format != "rfc5424" {
			t.Fatalf("%s: format = %q, want default rfc5424", c.name, c.syslog.Format)
		}
	}
	c2 := &Config{ListenHTTP: ":8080", LogShipper: cfg.LogShipper, AccessLog: cfg.AccessLog, AiAudit: cfg.AiAudit}
	if err := c2.Validate(); err != nil {
		t.Fatalf("synthesized config must validate: %v", err)
	}
}

func TestNormalizeIdempotentAndCompliantUntouched(t *testing.T) {
	// Fully compliant config (nested s3 + syslog blocks everywhere): byte
	// passthrough, zero applied.
	compliant := []byte(`{
		"listen_http":":8080",
		"log_shipper":{"type":"syslog","url":"tcp://siem.example.com:514","syslog":{"protocol":"tcp","format":"rfc5424","framing":"octet"}},
		"access_log":{"enabled":true,"type":"s3","s3":{"endpoint":"minio.internal:9000","bucket":"waf-logs","use_ssl":true}}
	}`)
	out, applied, err := NormalizeLegacyOutboundJSON(compliant)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 0 || !bytes.Equal(out, compliant) {
		t.Fatalf("compliant config must be untouched, applied=%v", applied)
	}
	// A legacy config normalized twice converges: second pass is a no-op.
	legacy := []byte(`{"listen_http":":8080","access_log":` + v0713AccessLogRaw + `,"log_shipper":{"type":"syslog","url":"udp://siem:514"}}`)
	once, applied1, err := NormalizeLegacyOutboundJSON(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied1) == 0 {
		t.Fatal("first pass must report migrations")
	}
	twice, applied2, err := NormalizeLegacyOutboundJSON(once)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied2) != 0 || !bytes.Equal(once, twice) {
		t.Fatalf("second pass must be a no-op, applied=%v", applied2)
	}
}

// TestNormalizeThenValidateRejectsGenuinelyBad: normalization only repairs
// the two legacy shapes; anything else (bogus sink type, kafka without
// brokers) keeps failing the strict validate.
func TestNormalizeThenValidateRejectsGenuinelyBad(t *testing.T) {
	bad := []byte(`{
		"listen_http":":8080",
		"access_log":{"enabled":true,"type":"bogus"},
		"log_shipper":{"type":"kafka","topic":"t"}
	}`)
	out, applied, err := NormalizeLegacyOutboundJSON(bad)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 0 {
		t.Fatalf("nothing legacy to repair, applied=%v", applied)
	}
	var cfg Config
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("bogus/kafka-broken config must still be rejected")
	}
}

// TestNormalizeLegacyOutboundStruct covers the struct-level seed path.
func TestNormalizeLegacyOutboundStruct(t *testing.T) {
	cfg := &Config{
		ListenHTTP: ":8080",
		LogShipper: &ShipperSettings{Type: "syslog", URL: "tls://siem:6514"},
		AccessLog:  &AccessLogSettings{Enabled: true, Type: "syslog", URL: "udp://siem:514"},
	}
	applied := NormalizeLegacyOutbound(cfg)
	if len(applied) != 2 {
		t.Fatalf("applied = %v, want two syntheses", applied)
	}
	if cfg.LogShipper.Syslog == nil || cfg.LogShipper.Syslog.Protocol != "tls" || cfg.LogShipper.Syslog.Format != "rfc5424" {
		t.Fatalf("log_shipper syslog block wrong: %+v", cfg.LogShipper.Syslog)
	}
	if cfg.AccessLog.Syslog == nil || cfg.AccessLog.Syslog.Protocol != "udp" {
		t.Fatalf("access_log syslog block wrong (bare host must default to udp): %+v", cfg.AccessLog.Syslog)
	}
	if again := NormalizeLegacyOutbound(cfg); len(again) != 0 {
		t.Fatalf("struct-level normalization must be idempotent, again=%v", again)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("normalized struct config must validate: %v", err)
	}
}

// --- load-time degradation (NormalizeLegacyOutbound): an outbound section
// that could never ship as configured is switched off with the original
// error reported — never a refusal to boot. Publish stays strict. ---

func TestNormalizeDegradesUnshippableAccessLog(t *testing.T) {
	cases := []struct {
		name    string
		alJSON  string
		want    string // "enabled" | "disabled"
		wantMsg string // substring the degradation message must carry
		verify  func(*testing.T, *AccessLogSettings)
	}{
		{
			name:   "flat s3 complete migrates and stays enabled",
			alJSON: `{"enabled":true,"type":"s3","endpoint":"minio.internal:9000","bucket":"waf-logs","prefix":"kingmoat","access_key":"ak","secret_key":"sk","use_ssl":true}`,
			want:   "enabled",
			verify: func(t *testing.T, al *AccessLogSettings) {
				if al.S3 == nil || al.S3.Endpoint != "minio.internal:9000" || al.S3.Bucket != "waf-logs" || !al.S3.UseSSL {
					t.Fatalf("migrated s3 block wrong: %+v", al.S3)
				}
			},
		},
		{
			name:    "flat s3 keys empty strings degrade to disabled",
			alJSON:  `{"enabled":true,"type":"s3","endpoint":"","bucket":"","access_key":"","secret_key":""}`,
			want:    "disabled",
			wantMsg: "endpoint and bucket are required",
		},
		{
			name:    "s3 without any s3 data degrades to disabled",
			alJSON:  `{"enabled":true,"type":"s3"}`,
			want:    "disabled",
			wantMsg: "requires the s3 block",
		},
		{
			name:    "kafka without brokers degrades to disabled",
			alJSON:  `{"enabled":true,"type":"kafka","topic":"t"}`,
			want:    "disabled",
			wantMsg: "at least one broker",
		},
		{
			name:    "elasticsearch without url degrades to disabled",
			alJSON:  `{"enabled":true,"type":"elasticsearch"}`,
			want:    "disabled",
			wantMsg: "url must be an http(s) URL",
		},
		{
			name:    "bogus type degrades to disabled",
			alJSON:  `{"enabled":true,"type":"bogus"}`,
			want:    "disabled",
			wantMsg: "type must be one of",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := []byte(`{"listen_http":":8080","access_log":` + tc.alJSON + `}`)
			out, _, err := NormalizeLegacyOutboundJSON(in)
			if err != nil {
				t.Fatal(err)
			}
			var cfg Config
			if err := json.Unmarshal(out, &cfg); err != nil {
				t.Fatal(err)
			}
			applied := NormalizeLegacyOutbound(&cfg)
			switch tc.want {
			case "enabled":
				if cfg.AccessLog == nil || !cfg.AccessLog.Enabled {
					t.Fatalf("section must stay enabled, applied=%v", applied)
				}
			case "disabled":
				if cfg.AccessLog == nil || cfg.AccessLog.Enabled {
					t.Fatalf("section must be degraded to disabled, applied=%v", applied)
				}
				msg := strings.Join(applied, "; ")
				if !strings.Contains(msg, "access_log: disabled (unshippable as configured: ") || !strings.Contains(msg, tc.wantMsg) {
					t.Fatalf("degradation message must carry the original error %q, applied=%v", tc.wantMsg, applied)
				}
			}
			if tc.verify != nil {
				tc.verify(t, cfg.AccessLog)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("degraded config must validate: %v", err)
			}
		})
	}
}

func TestNormalizeDegradesUnshippableLogShipper(t *testing.T) {
	cases := []struct {
		name     string
		lsJSON   string
		wantKept bool
		wantMsg  string
	}{
		{"elasticsearch with url stays", `{"type":"elasticsearch","url":"http://es.internal:9200","index":"kingmoat"}`, true, ""},
		{"elasticsearch without url removed", `{"type":"elasticsearch"}`, false, "url must be an http(s) URL"},
		{"s3 complete stays", `{"type":"s3","endpoint":"minio.internal:9000","bucket":"kingmoat","access_key":"ak","secret_key":"sk"}`, true, ""},
		{"s3 missing secret_key removed", `{"type":"s3","endpoint":"minio.internal:9000","bucket":"kingmoat","access_key":"ak"}`, false, "endpoint, bucket, access_key and secret_key are required"},
		{"kafka without brokers removed", `{"type":"kafka","topic":"kingmoat"}`, false, "at least one broker"},
		{"syslog without block synthesized and kept", `{"type":"syslog","url":"tcp://siem.internal:514"}`, true, ""},
		{"bogus type removed", `{"type":"bogus"}`, false, `type must be "elasticsearch"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			if err := json.Unmarshal([]byte(`{"listen_http":":8080","log_shipper":`+tc.lsJSON+`}`), &cfg); err != nil {
				t.Fatal(err)
			}
			applied := NormalizeLegacyOutbound(&cfg)
			if tc.wantKept {
				if cfg.LogShipper == nil {
					t.Fatalf("log_shipper must be kept, applied=%v", applied)
				}
			} else {
				if cfg.LogShipper != nil {
					t.Fatalf("unshippable log_shipper must be removed, applied=%v", applied)
				}
				msg := strings.Join(applied, "; ")
				if !strings.Contains(msg, "log_shipper: removed (unshippable as configured: ") || !strings.Contains(msg, tc.wantMsg) {
					t.Fatalf("removal message must carry the original error %q, applied=%v", tc.wantMsg, applied)
				}
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("degraded config must validate: %v", err)
			}
		})
	}
}

func TestNormalizeDegradesUnshippableAIAuditShip(t *testing.T) {
	cases := []struct {
		name     string
		shipJSON string
		want     string
		wantMsg  string
	}{
		{"s3 without block degrades", `{"enabled":true,"type":"s3"}`, "disabled", "requires the s3 block"},
		{"kafka without brokers degrades", `{"enabled":true,"type":"kafka","topic":"t"}`, "disabled", "at least one broker"},
		{"elasticsearch with url stays", `{"enabled":true,"type":"elasticsearch","url":"http://es.internal:9200"}`, "enabled", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			if err := json.Unmarshal([]byte(`{"listen_http":":8080","ai_audit":{"ship":`+tc.shipJSON+`}}`), &cfg); err != nil {
				t.Fatal(err)
			}
			applied := NormalizeLegacyOutbound(&cfg)
			switch tc.want {
			case "enabled":
				if cfg.AiAudit == nil || cfg.AiAudit.Ship == nil || !cfg.AiAudit.Ship.Enabled {
					t.Fatalf("ship must stay enabled, applied=%v", applied)
				}
			case "disabled":
				if cfg.AiAudit == nil || cfg.AiAudit.Ship == nil || cfg.AiAudit.Ship.Enabled {
					t.Fatalf("ship must be degraded to disabled, applied=%v", applied)
				}
				msg := strings.Join(applied, "; ")
				if !strings.Contains(msg, "ai_audit.ship: disabled (unshippable as configured: ") || !strings.Contains(msg, tc.wantMsg) {
					t.Fatalf("degradation message must carry the original error %q, applied=%v", tc.wantMsg, applied)
				}
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("degraded config must validate: %v", err)
			}
		})
	}
}

// TestNormalizeDefendsAuditChannelWithoutShipper: a section riding the
// use_audit_channel switch while the audit-log outbound (log_shipper) is
// absent — or degraded away in the same pass — cannot ship either; the
// defensive tail disables it instead of leaving a silently dead switch.
func TestNormalizeDefendsAuditChannelWithoutShipper(t *testing.T) {
	cfg := &Config{
		ListenHTTP: ":8080",
		AccessLog:  &AccessLogSettings{Enabled: true, UseAuditChannel: true},
		AiAudit:    &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, UseAuditChannel: true}},
	}
	applied := NormalizeLegacyOutbound(cfg)
	if cfg.AccessLog.Enabled || cfg.AiAudit.Ship.Enabled {
		t.Fatalf("sections riding a dead audit channel must be disabled, applied=%v", applied)
	}
	if msg := strings.Join(applied, "; "); !strings.Contains(msg, "use_audit_channel on but the audit-log outbound log_shipper is not configured") {
		t.Fatalf("defensive degradation must be reported, applied=%v", applied)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defensively degraded config must validate: %v", err)
	}

	// Same defense when the channel exists but is degraded away in the same
	// pass (log_shipper kafka without brokers).
	cfg = &Config{
		ListenHTTP: ":8080",
		LogShipper: &ShipperSettings{Type: "kafka", Topic: "t"},
		AccessLog:  &AccessLogSettings{Enabled: true, UseAuditChannel: true},
	}
	applied = NormalizeLegacyOutbound(cfg)
	if cfg.LogShipper != nil || cfg.AccessLog.Enabled {
		t.Fatalf("broken channel and its rider must both degrade, applied=%v", applied)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defensively degraded config must validate: %v", err)
	}
}

// TestNormalizeLegacyOutboundCompliantUntouchedAndIdempotent: a fully
// compliant struct passes through unmodified, and a second pass over an
// already-normalized/degraded config is a zero-change no-op.
func TestNormalizeLegacyOutboundCompliantUntouchedAndIdempotent(t *testing.T) {
	compliant := &Config{
		ListenHTTP: ":8080",
		LogShipper: &ShipperSettings{Type: "syslog", URL: "tcp://siem.internal:514", Syslog: &SyslogSettings{Protocol: "tcp", Format: "rfc5424"}},
		AccessLog:  &AccessLogSettings{Enabled: true, Type: "s3", S3: &S3Settings{Endpoint: "minio.internal:9000", Bucket: "waf-logs"}},
		AiAudit:    &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "elasticsearch", URL: "http://es.internal:9200"}},
	}
	snapshot, err := json.Marshal(compliant)
	if err != nil {
		t.Fatal(err)
	}
	var untouched Config
	if err := json.Unmarshal(snapshot, &untouched); err != nil {
		t.Fatal(err)
	}
	if applied := NormalizeLegacyOutbound(compliant); len(applied) != 0 {
		t.Fatalf("compliant struct must be untouched, applied=%v", applied)
	}
	if !reflect.DeepEqual(compliant, &untouched) {
		t.Fatal("compliant struct must not be modified by normalization")
	}

	degradable := &Config{
		ListenHTTP: ":8080",
		LogShipper: &ShipperSettings{Type: "kafka", Topic: "t"},
		AccessLog:  &AccessLogSettings{Enabled: true, Type: "syslog", URL: "udp://siem:514"},
	}
	if applied := NormalizeLegacyOutbound(degradable); len(applied) == 0 {
		t.Fatal("first pass must report normalizations/degradations")
	}
	before, _ := json.Marshal(degradable)
	if again := NormalizeLegacyOutbound(degradable); len(again) != 0 {
		t.Fatalf("second pass must be a zero-change no-op, again=%v", again)
	}
	after, _ := json.Marshal(degradable)
	if !bytes.Equal(before, after) {
		t.Fatal("second pass must not change the struct")
	}
	if err := degradable.Validate(); err != nil {
		t.Fatalf("degraded config must validate: %v", err)
	}
}

// TestNormalizePreservesLargeIntegers: normalization decodes at the raw JSON
// level, so a field the migration does not touch must survive the decode /
// re-encode round trip verbatim — including integers at or beyond 2^63, which
// the map[string]any default (float64) would round and whose rounded literal
// would then fail to decode back into an int64 field.
func TestNormalizePreservesLargeIntegers(t *testing.T) {
	const big = `9223372036854775807` // math.MaxInt64
	in := []byte(`{
		"listen_http":":8080",
		"sites":[{"domains":["app.internal"],"waf":{"body_limit_bytes":` + big + `}}],
		"access_log":` + v0713AccessLogRaw + `
	}`)
	out, applied, err := NormalizeLegacyOutboundJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) == 0 {
		t.Fatal("the flat s3 shape must trigger normalization")
	}
	if !bytes.Contains(out, []byte(`"body_limit_bytes":`+big)) {
		t.Fatalf("untouched integer must be re-encoded byte for byte:\n%s", out)
	}
	var cfg Config
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("normalized JSON must decode back into the struct: %v", err)
	}
	if cfg.Sites == nil || cfg.Sites[0].WAF == nil || cfg.Sites[0].WAF.BodyLimitBytes != math.MaxInt64 {
		t.Fatalf("body_limit_bytes must survive as %d, got %+v", int64(math.MaxInt64), cfg.Sites)
	}
}

// TestNormalizeRejectsTrailingData: the decode keeps json.Unmarshal's
// strictness — a payload that is not exactly one JSON value is reported (and
// passed through), never silently normalized into a valid document.
func TestNormalizeRejectsTrailingData(t *testing.T) {
	in := []byte(`{"listen_http":":8080","access_log":` + v0713AccessLogRaw + `} trailing`)
	out, applied, err := NormalizeLegacyOutboundJSON(in)
	if err == nil {
		t.Fatalf("trailing data must be reported, out=%s applied=%v", out, applied)
	}
	if !bytes.Equal(out, in) || applied != nil {
		t.Fatalf("a rejected payload must pass through untouched, out=%s applied=%v", out, applied)
	}
}

// TestDegradationMessagesReadAsOneSentence pins the degradation entry shape:
// the section name and the action appear once at the outer level and the
// entry then carries the underlying error's REASON only (its redundant
// "config: <section>" / "ai_audit: ship" prefix stripped, per-type qualifier
// kept).
func TestDegradationMessagesReadAsOneSentence(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		want string
	}{
		{
			name: "log_shipper kafka without brokers",
			cfg:  &Config{ListenHTTP: ":8080", LogShipper: &ShipperSettings{Type: "kafka", Topic: "t"}},
			want: "log_shipper: removed (unshippable as configured: kafka: at least one broker is required)",
		},
		{
			name: "log_shipper es without url",
			cfg:  &Config{ListenHTTP: ":8080", LogShipper: &ShipperSettings{Type: "elasticsearch"}},
			want: "log_shipper: removed (unshippable as configured: url must be an http(s) URL)",
		},
		{
			name: "access_log s3 incomplete",
			cfg:  &Config{ListenHTTP: ":8080", AccessLog: &AccessLogSettings{Enabled: true, Type: "s3", S3: &S3Settings{}}},
			want: "access_log: disabled (unshippable as configured: s3: endpoint and bucket are required)",
		},
		{
			name: "ai_audit.ship bogus type",
			cfg:  &Config{ListenHTTP: ":8080", AiAudit: &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "bogus"}}},
			want: "ai_audit.ship: disabled (unshippable as configured: type must be one of clickhouse/elasticsearch/loki/s3/syslog/kafka)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := strings.Join(NormalizeLegacyOutbound(tc.cfg), "; ")
			if !strings.Contains(msg, tc.want) {
				t.Fatalf("degradation entry drifted\n got: %s\nwant: %s", msg, tc.want)
			}
			for _, repeated := range []string{"config: log_shipper", "config: access_log", "ai_audit: ship"} {
				if strings.Contains(msg, repeated) {
					t.Fatalf("entry must not repeat the section prefix %q: %s", repeated, msg)
				}
			}
		})
	}
}

// TestOutboundValidateErrorTextsPinned: ShipperSettings.Validate and
// AIAuditShipSettings.Validate were extracted VERBATIM from
// Config.Validate / AIAuditSettings.Validate and their texts reach the
// console (publish gate) and the load-time degradation messages; pin them
// literally so a rewording is a conscious release-surface decision.
func TestOutboundValidateErrorTextsPinned(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"log_shipper bogus type", (&ShipperSettings{Type: "bogus"}).Validate(),
			`config: log_shipper.type must be "elasticsearch", "loki", "clickhouse", "s3", "kafka" or "syslog", got "bogus"`},
		{"log_shipper es without url", (&ShipperSettings{Type: "elasticsearch"}).Validate(),
			`config: log_shipper.url must be an http(s) URL`},
		{"log_shipper s3 incomplete", (&ShipperSettings{Type: "s3"}).Validate(),
			`config: log_shipper (s3): endpoint, bucket, access_key and secret_key are required`},
		{"log_shipper syslog without block", (&ShipperSettings{Type: "syslog", URL: "udp://siem:514"}).Validate(),
			`config: log_shipper (syslog): a syslog block (protocol/format) is required for type "syslog"`},
		{"log_shipper kafka without brokers", (&ShipperSettings{Type: "kafka", Topic: "t"}).Validate(),
			`config: log_shipper (kafka): at least one broker is required`},
		{"config validate passes log_shipper text through", (&Config{ListenHTTP: ":80", LogShipper: &ShipperSettings{Type: "bogus"}}).Validate(),
			`config: log_shipper.type must be "elasticsearch", "loki", "clickhouse", "s3", "kafka" or "syslog", got "bogus"`},
		{"ai ship s3 without block", (&AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "s3"}}).Validate(),
			`ai_audit: ship.type s3 requires the s3 block (endpoint, bucket, keys)`},
		{"ai ship syslog without block", (&AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "syslog", URL: "udp://siem:514"}}).Validate(),
			`ai_audit: ship.type syslog requires the syslog block (protocol/format)`},
		{"ai ship bogus type", (&AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "bogus"}}).Validate(),
			`ai_audit: ship.type must be one of clickhouse/elasticsearch/loki/s3/syslog/kafka`},
	}
	for _, tc := range cases {
		if tc.err == nil || tc.err.Error() != tc.want {
			t.Fatalf("%s: error text drifted\n got: %v\nwant: %s", tc.name, tc.err, tc.want)
		}
	}
}

// --- A5: ai_audit.ship's deprecated flat s3 prefix/use_ssl migrate into the
// nested s3 block at load time (JSON level and struct level), with the same
// move-not-copy and idempotency rules as the access_log migration. ---

// v0713AIShipFlatRaw is the complete flat-s3 ship shape (endpoint/bucket/
// prefix/use_ssl next to type "s3", no nested block).
const v0713AIShipFlatRaw = `{"enabled":true,"type":"s3","index":"kingmoat_ai_sessions","endpoint":"minio.internal:9000","bucket":"ai-logs","prefix":"kingmoat/ai","use_ssl":true}`

func TestNormalizeMigratesFlatAIShipS3(t *testing.T) {
	in := []byte(`{"listen_http":":8080","ai_audit":{"ship":` + v0713AIShipFlatRaw + `}}`)
	out, applied, err := NormalizeLegacyOutboundJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || !strings.Contains(applied[0], "ai_audit.ship") || !strings.Contains(applied[0], "s3") {
		t.Fatalf("applied = %v, want one ai_audit.ship s3 migration", applied)
	}
	var cfg Config
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	ship := cfg.AiAudit.Ship
	if ship == nil || ship.S3 == nil {
		t.Fatal("nested s3 block missing after migration")
	}
	if ship.S3.Endpoint != "minio.internal:9000" || ship.S3.Bucket != "ai-logs" ||
		ship.S3.Prefix != "kingmoat/ai" || !ship.S3.UseSSL {
		t.Fatalf("migrated s3 block wrong: %+v", ship.S3)
	}
	// The flat keys must be gone from the section JSON (moved, not copied).
	var probe struct {
		AiAudit struct {
			Ship struct {
				Endpoint json.RawMessage `json:"endpoint"`
				Prefix   json.RawMessage `json:"prefix"`
				UseSSL   json.RawMessage `json:"use_ssl"`
				S3       json.RawMessage `json:"s3"`
			} `json:"ship"`
		} `json:"ai_audit"`
	}
	if err := json.Unmarshal(out, &probe); err != nil {
		t.Fatal(err)
	}
	if probe.AiAudit.Ship.Endpoint != nil || probe.AiAudit.Ship.Prefix != nil || probe.AiAudit.Ship.UseSSL != nil {
		t.Fatal("flat keys must be moved out of the ship section, not left in place")
	}
	if probe.AiAudit.Ship.S3 == nil {
		t.Fatal("nested s3 block must be present in the output JSON")
	}
	// The migrated section is enabled and validates.
	if !ship.Enabled {
		t.Fatal("a complete flat s3 ship must stay enabled after migration")
	}
	if err := (&Config{ListenHTTP: ":8080", AiAudit: cfg.AiAudit}).Validate(); err != nil {
		t.Fatalf("migrated config must validate: %v", err)
	}
	// Idempotent: a second pass over the migrated JSON is a byte-identical no-op.
	out2, applied2, err := NormalizeLegacyOutboundJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied2) != 0 || !bytes.Equal(out, out2) {
		t.Fatalf("second pass must be a no-op, applied=%v", applied2)
	}
}

func TestNormalizeMigratesFlatAIShipS3StructLevel(t *testing.T) {
	yes := true
	// The struct-level seed path can only carry the deprecated flat
	// prefix/use_ssl pair (AIAuditShipSettings has no flat endpoint/bucket
	// fields), so after the migration the section still degrades — but with
	// the PRECISE error (endpoint and bucket are required) and the flat
	// values preserved in the s3 block instead of the generic "requires the
	// s3 block" and lost values.
	cfg := &Config{
		ListenHTTP: ":8080",
		AiAudit:    &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "s3", Index: "kingmoat_ai_sessions", Prefix: "kingmoat/ai", UseSSL: &yes}},
	}
	applied := NormalizeLegacyOutbound(cfg)
	if len(applied) != 2 {
		t.Fatalf("applied = %v, want the migration plus the degradation", applied)
	}
	if applied[0] != "ai_audit.ship: migrated flat s3 fields into the s3 block" {
		t.Fatalf("first entry must be the migration, got %q", applied[0])
	}
	if !strings.Contains(applied[1], "ai_audit.ship: disabled (unshippable as configured: ") ||
		!strings.Contains(applied[1], "endpoint and bucket are required") {
		t.Fatalf("second entry must be the precise degradation, got %q", applied[1])
	}
	s3 := cfg.AiAudit.Ship.S3
	if s3 == nil || s3.Prefix != "kingmoat/ai" || !s3.UseSSL {
		t.Fatalf("migrated s3 block wrong: %+v", s3)
	}
	if cfg.AiAudit.Ship.Enabled {
		t.Fatal("a prefix/use_ssl-only ship must still degrade (endpoint/bucket missing)")
	}
	// The flat fields are MOVED: empty afterwards, so a second pass is a
	// zero-change no-op (idempotency) and the JSON omits them.
	if cfg.AiAudit.Ship.Prefix != "" || cfg.AiAudit.Ship.UseSSL != nil {
		t.Fatalf("flat fields must be cleared after the migration: prefix=%q use_ssl=%v",
			cfg.AiAudit.Ship.Prefix, cfg.AiAudit.Ship.UseSSL)
	}
	if again := NormalizeLegacyOutbound(cfg); len(again) != 0 {
		t.Fatalf("struct-level migration must be idempotent, again=%v", again)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("degraded config must validate: %v", err)
	}

	// Flat prefix alone (no use_ssl) also migrates; UseSSL defaults to false.
	cfg3 := &Config{
		ListenHTTP: ":8080",
		AiAudit:    &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "s3", Prefix: "p"}},
	}
	applied = NormalizeLegacyOutbound(cfg3)
	if len(applied) != 2 || applied[0] != "ai_audit.ship: migrated flat s3 fields into the s3 block" {
		t.Fatalf("flat prefix alone must migrate (then degrade), applied=%v", applied)
	}
	if cfg3.AiAudit.Ship.S3 == nil || cfg3.AiAudit.Ship.S3.Prefix != "p" || cfg3.AiAudit.Ship.S3.UseSSL {
		t.Fatalf("prefix-only migration wrong: %+v", cfg3.AiAudit.Ship.S3)
	}

	// A non-s3 type keeps the flat fields in place (the console round-trips
	// them; the migration only applies to type "s3" without an s3 block).
	cfg4 := &Config{
		ListenHTTP: ":8080",
		AiAudit:    &AIAuditSettings{Ship: &AIAuditShipSettings{Enabled: true, Type: "syslog", URL: "udp://siem:514", Prefix: "kingmoat/ai", UseSSL: &yes}},
	}
	if applied := NormalizeLegacyOutbound(cfg4); len(applied) != 1 {
		t.Fatalf("only the syslog synthesis should fire, applied=%v", applied)
	}
	if cfg4.AiAudit.Ship.Prefix != "kingmoat/ai" || cfg4.AiAudit.Ship.UseSSL != &yes {
		t.Fatalf("flat fields of a non-s3 section must stay untouched for the console round-trip")
	}
}
