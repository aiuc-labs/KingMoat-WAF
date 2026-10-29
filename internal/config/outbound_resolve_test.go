package config

import (
	"testing"
)

// Anchoring tests for the resolve helpers moved byte-identically from
// cmd/kingmoatwaf/outbound_resolve.go (T-01 sink-down): the same field-level
// assertions and edge inputs the cmd tests pin must hold in this package,
// where the API outbound-probe layer will consume them. The behavioral
// channel-reuse matrix (rebuild-or-skip through the sectionTracker) stays in
// cmd — it drives the rebuilders, which live there.

// resolveChannelBase is the log_shipper section the resolve tests reuse.
func resolveChannelBase() *ShipperSettings {
	return &ShipperSettings{
		Type: "elasticsearch", URL: "http://audit.internal:9200",
		Index: "kingmoat", BatchSize: 50, FlushSec: 7, TimeoutSec: 3,
		Username: "audit-u", Password: "audit-p",
		Brokers: []string{"b1:9092"}, Topic: "audit-topic", UseTLS: true, SASL: "plain",
		Prefix: "kingmoat/audit",
		Syslog: &SyslogSettings{Protocol: "tcp", Format: "rfc3164", AppName: "kingmoat", Facility: 4},
	}
}

func TestResolveAccessOutPassthrough(t *testing.T) {
	al := &AccessLogSettings{Enabled: true, Type: "clickhouse", URL: "http://own:8123"}

	if got := ResolveAccessOut(nil, resolveChannelBase()); got != nil {
		t.Fatalf("nil section must pass through, got %+v", got)
	}
	if got := ResolveAccessOut(al, resolveChannelBase()); got != al {
		t.Fatal("switch-off section must pass through unchanged (same pointer)")
	}
	if got := ResolveAccessOut(&AccessLogSettings{Enabled: false, UseAuditChannel: true}, resolveChannelBase()); got.Enabled {
		t.Fatal("disabled section must pass through (no channel overlay: channel changes never wake a stopped pipeline)")
	}
	if got := ResolveAccessOut(&AccessLogSettings{Enabled: true, UseAuditChannel: true}, nil); !got.UseAuditChannel || got.URL != "" {
		t.Fatal("switch-on section with no channel must pass through (the rebuilder warns and disables)")
	}
}

func TestResolveAccessOutOverlay(t *testing.T) {
	al := &AccessLogSettings{
		Enabled: true, Type: "clickhouse", URL: "http://own:8123",
		Index: "kingmoat_access", SamplePct: 40, BatchSize: 10, FlushSec: 9, TimeoutSec: 9,
		Username: "own-u", Password: "own-p",
		UseAuditChannel: true,
		Brokers:         []string{"own-broker"}, Topic: "own-topic",
	}
	ls := resolveChannelBase()
	got := ResolveAccessOut(al, ls)
	if got == al {
		t.Fatal("switch-on section must resolve into an overlay copy")
	}

	// Channel fields come from log_shipper (ignored in-section fields included).
	if got.Type != "elasticsearch" || got.URL != ls.URL {
		t.Fatalf("resolved type/url = %s/%s, want the channel's", got.Type, got.URL)
	}
	if got.BatchSize != 50 || got.FlushSec != 7 || got.TimeoutSec != 3 {
		t.Fatalf("resolved batching = %d/%d/%d, want the channel's", got.BatchSize, got.FlushSec, got.TimeoutSec)
	}
	if got.Username != "audit-u" || got.Password != "audit-p" {
		t.Fatal("resolved auth must come from the channel")
	}
	if got.Topic != ls.Topic || !got.UseTLS || got.SASL != "plain" {
		t.Fatal("resolved kafka transport must come from the channel")
	}
	if len(got.Brokers) != 1 || got.Brokers[0] != "b1:9092" {
		t.Fatalf("resolved brokers = %v, want the channel's", got.Brokers)
	}
	if got.TLSSkipVerify != nil {
		t.Fatal("nil channel tls_skip_verify must stay nil")
	}

	// Identity fields stay ours.
	if !got.Enabled || !got.UseAuditChannel {
		t.Fatal("lifecycle fields are identity fields and must stay")
	}
	if got.Index != "kingmoat_access" || got.SamplePct != 40 {
		t.Fatalf("resolved index/sample_pct = %s/%d, want the section's own", got.Index, got.SamplePct)
	}

	// Invalid sub-structures for the resolved type are dropped (they are the
	// section's ignored channel fields while the switch is on): a change to
	// them must not flip the resolved section.
	if got.S3 != nil || got.Syslog != nil {
		t.Fatalf("non-s3/syslog resolved type must drop the sub-structures, got S3=%v Syslog=%v", got.S3, got.Syslog)
	}

	// The original section is never polluted.
	if al.Type != "clickhouse" || al.URL != "http://own:8123" || al.Username != "own-u" {
		t.Fatal("resolve must not mutate the section")
	}

	// The resolved section must not alias channel memory (a later in-place
	// mutation of the channel would otherwise corrupt the tracker snapshot).
	ls.Brokers[0] = "changed:9092"
	if got.Brokers[0] != "b1:9092" {
		t.Fatal("resolved brokers must be a copy, not an alias")
	}
}

func TestResolveAccessOutS3Overlay(t *testing.T) {
	ls := resolveChannelBase()
	ls.Type = "s3"
	ls.Endpoint = "http://minio.internal:9000"
	ls.Bucket = "audit-bucket"
	ls.AccessKey, ls.SecretKey = "ak", "sk"

	// No section s3 block: prefix empty, transport derived from the endpoint
	// scheme exactly like logshipper (http → plaintext).
	got := ResolveAccessOut(&AccessLogSettings{Enabled: true, UseAuditChannel: true}, ls)
	if got.S3 == nil {
		t.Fatal("s3 channel must resolve into a nested s3 block")
	}
	if got.S3.Endpoint != "minio.internal:9000" || got.S3.UseSSL {
		t.Fatalf("s3 endpoint/ssl = %s/%v, want scheme-stripped plaintext", got.S3.Endpoint, got.S3.UseSSL)
	}
	if got.S3.Bucket != "audit-bucket" || got.S3.AccessKey != "ak" || got.S3.SecretKey != "sk" {
		t.Fatal("s3 credentials must come from the channel")
	}
	if got.S3.Prefix != "" {
		t.Fatalf("s3 prefix = %q, want empty (section has none)", got.S3.Prefix)
	}

	// The prefix is an identity field: it stays ours even when nested.
	own := &AccessLogSettings{Enabled: true, UseAuditChannel: true, S3: &S3Settings{Endpoint: "own:9000", Bucket: "own-bucket", Prefix: "kingmoat/access"}}
	got = ResolveAccessOut(own, ls)
	if got.S3.Endpoint != "minio.internal:9000" || got.S3.Bucket != "audit-bucket" {
		t.Fatal("s3 endpoint/bucket must come from the channel")
	}
	if got.S3.Prefix != "kingmoat/access" {
		t.Fatalf("s3 prefix = %q, want the section's own identity prefix", got.S3.Prefix)
	}

	// An explicit channel use_ssl overrides the scheme-derived transport.
	ssl := true
	ls.UseSSL = &ssl
	got = ResolveAccessOut(own, ls)
	if !got.S3.UseSSL {
		t.Fatal("explicit channel use_ssl must win over the endpoint scheme")
	}
}

func TestResolveAccessOutSyslogOverlay(t *testing.T) {
	ls := resolveChannelBase()
	ls.Type = "syslog"
	ls.URL = "tcp://collector.internal:514"

	// The transport comes from the channel; the APP-NAME is ours (the
	// channel's "kingmoat" must not leak into the access stream, and an
	// empty app name falls back to the section index inside syslogsink).
	al := &AccessLogSettings{Enabled: true, UseAuditChannel: true, Index: "kingmoat_access"}
	got := ResolveAccessOut(al, ls)
	if got.Syslog == nil {
		t.Fatal("syslog channel must resolve into a syslog block")
	}
	if got.Syslog.Protocol != "tcp" || got.Syslog.Format != "rfc3164" || got.Syslog.Facility != 4 {
		t.Fatalf("syslog transport = %+v, want the channel's", got.Syslog)
	}
	if got.Syslog.AppName != "" {
		t.Fatalf("syslog app_name = %q, want empty (channel identity stripped, section has none)", got.Syslog.AppName)
	}

	// An explicit section app_name wins over the fallbacks.
	al.Syslog = &SyslogSettings{AppName: "waf-access"}
	got = ResolveAccessOut(al, ls)
	if got.Syslog.AppName != "waf-access" || got.Syslog.Protocol != "tcp" {
		t.Fatalf("syslog = %+v, want channel transport + section app name", got.Syslog)
	}

	// A channel without a syslog block still resolves (all-default transport)
	// instead of failing the build later.
	ls.Syslog = nil
	got = ResolveAccessOut(al, ls)
	if got.Syslog == nil || got.Syslog.AppName != "waf-access" {
		t.Fatalf("channel syslog block is optional, got %+v", got.Syslog)
	}
}

func TestResolveAIShipOutOverlay(t *testing.T) {
	ship := &AIAuditShipSettings{
		Enabled: true, Type: "elasticsearch", URL: "http://own:9200",
		Index: "kingmoat_ai_sessions", SamplePct: 25, BatchSize: 10, FlushSec: 9,
		UseAuditChannel: true,
	}
	ls := resolveChannelBase()
	got := ResolveAIShipOut(ship, ls)
	if got == ship {
		t.Fatal("switch-on ship section must resolve into an overlay copy")
	}
	if got.Type != "elasticsearch" || got.URL != ls.URL || got.BatchSize != 50 || got.FlushSec != 7 || got.TimeoutSec != 3 {
		t.Fatalf("resolved channel fields = %s/%s/%d/%d/%d, want the channel's", got.Type, got.URL, got.BatchSize, got.FlushSec, got.TimeoutSec)
	}
	if got.Username != "audit-u" || got.Password != "audit-p" {
		t.Fatal("resolved auth must come from the channel")
	}
	if got.Index != "kingmoat_ai_sessions" || got.SamplePct != 25 {
		t.Fatalf("identity fields = %s/%d, want the section's own", got.Index, got.SamplePct)
	}
	if ship.Type != "elasticsearch" || ship.URL != "http://own:9200" {
		t.Fatal("resolve must not mutate the ship section")
	}

	// Passthrough rules mirror the access resolver.
	if got := ResolveAIShipOut(nil, ls); got != nil {
		t.Fatal("nil ship section must pass through")
	}
	if got := ResolveAIShipOut(ship, nil); got != ship {
		t.Fatal("no channel must pass the section through (the rebuilder warns and disables)")
	}
}

func TestResolveAIShipOutS3FallbackSeed(t *testing.T) {
	ls := resolveChannelBase()
	ls.Type = "s3"
	ls.Endpoint = "minio.internal:9000"
	ls.Bucket = "audit-bucket"

	// Deprecated flat prefix / use_ssl seed the identity when the nested s3
	// sub-structure is absent (T-1 fallback-seed convention).
	useSSL := true
	ship := &AIAuditShipSettings{Enabled: true, UseAuditChannel: true, Prefix: "kingmoat/ai", UseSSL: &useSSL}
	got := ResolveAIShipOut(ship, ls)
	if got.S3 == nil {
		t.Fatal("s3 channel must resolve into a nested s3 block")
	}
	if got.S3.Prefix != "kingmoat/ai" {
		t.Fatalf("s3 prefix = %q, want the flat fallback seed", got.S3.Prefix)
	}
	if got.S3.Endpoint != "minio.internal:9000" || !got.S3.UseSSL {
		t.Fatalf("s3 endpoint/ssl = %s/%v, want the channel's (explicit use_ssl also defaults secure)", got.S3.Endpoint, got.S3.UseSSL)
	}

	// A nested s3 block wins over the flat seed.
	ship.S3 = &S3Settings{Prefix: "kingmoat/ai-nested"}
	got = ResolveAIShipOut(ship, ls)
	if got.S3.Prefix != "kingmoat/ai-nested" {
		t.Fatalf("s3 prefix = %q, want the nested block's", got.S3.Prefix)
	}

	// Non-s3 resolved types drop the sub-structure entirely.
	ls.Type = "loki"
	ls.URL = "http://loki.internal:3100"
	got = ResolveAIShipOut(ship, ls)
	if got.S3 != nil || got.Syslog != nil {
		t.Fatalf("non-s3/syslog resolved type must drop the sub-structures, got S3=%v Syslog=%v", got.S3, got.Syslog)
	}
}

// TestResolveNoChannelAliasing extends the cmd-side pinning with the deep
// copies the golden sink-down proof cannot express: the resolved section
// must not share mutable memory with the channel (TLSSkipVerify, Syslog,
// Brokers) — a later in-place mutation of the channel must not corrupt the
// sectionTracker snapshot.
func TestResolveNoChannelAliasing(t *testing.T) {
	yes := true
	ls := &ShipperSettings{
		Type: "syslog", URL: "tcp://collector.internal:514",
		Brokers:       []string{"b1:9092"},
		TLSSkipVerify: &yes,
		Syslog:        &SyslogSettings{Protocol: "tcp", AppName: "kingmoat"},
	}
	al := &AccessLogSettings{Enabled: true, UseAuditChannel: true}
	got := ResolveAccessOut(al, ls)

	// TLSSkipVerify: value copied, memory not shared.
	if got.TLSSkipVerify == nil || !*got.TLSSkipVerify {
		t.Fatalf("tls_skip_verify = %v, want a copy of true", got.TLSSkipVerify)
	}
	if got.TLSSkipVerify == ls.TLSSkipVerify {
		t.Fatal("tls_skip_verify must be a fresh pointer, not an alias")
	}
	*ls.TLSSkipVerify = false
	if !*got.TLSSkipVerify {
		t.Fatal("resolved tls_skip_verify must not alias the channel's")
	}

	// Syslog: struct copied, APP-NAME re-owned.
	if got.Syslog == nil || got.Syslog == ls.Syslog {
		t.Fatal("resolved syslog must be a fresh struct, not an alias")
	}
	ls.Syslog.Protocol = "udp"
	ls.Syslog.AppName = "leaked"
	if got.Syslog.Protocol != "tcp" || got.Syslog.AppName != "" {
		t.Fatalf("resolved syslog must not alias the channel's, got %+v", got.Syslog)
	}

	// Brokers: slice copied.
	ls.Brokers[0] = "changed:9092"
	if got.Brokers[0] != "b1:9092" {
		t.Fatal("resolved brokers must not alias the channel's")
	}

	// The AI resolver shares the same helpers: spot-check one field.
	ai := ResolveAIShipOut(&AIAuditShipSettings{Enabled: true, UseAuditChannel: true}, ls)
	if ai.TLSSkipVerify == ls.TLSSkipVerify || *ai.TLSSkipVerify {
		t.Fatal("ai resolved tls_skip_verify must be a fresh copy of the pre-mutation value")
	}
}

// TestResolveEdgeShapes is the table-driven boundary pin: nil vs empty
// slices, scheme-less endpoints, whitespace, tri-state use_ssl and the
// dropped sub-structures resolve exactly as the pre-move implementation did
// (the before/after golden dump proved the move; these rows keep it pinned).
func TestResolveEdgeShapes(t *testing.T) {
	b := func(v bool) *bool { return &v }
	kafkaLS := &ShipperSettings{Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t", UseTLS: true, SASL: "plain", TLSSkipVerify: b(false)}

	type accessRow struct {
		name  string
		al    *AccessLogSettings
		ls    *ShipperSettings
		check func(t *testing.T, got *AccessLogSettings)
	}
	accessRows := []accessRow{
		{
			name: "nil brokers stay nil",
			al:   &AccessLogSettings{Enabled: true, UseAuditChannel: true},
			ls:   &ShipperSettings{Type: "elasticsearch", URL: "http://a:9200", Brokers: nil},
			check: func(t *testing.T, got *AccessLogSettings) {
				if got.Brokers != nil {
					t.Fatalf("brokers = %v, want nil", got.Brokers)
				}
			},
		},
		{
			name: "empty brokers stay empty (not nil)",
			al:   &AccessLogSettings{Enabled: true, UseAuditChannel: true},
			ls:   &ShipperSettings{Type: "elasticsearch", URL: "http://a:9200", Brokers: []string{}},
			check: func(t *testing.T, got *AccessLogSettings) {
				if got.Brokers == nil || len(got.Brokers) != 0 {
					t.Fatalf("brokers = %#v, want non-nil empty", got.Brokers)
				}
			},
		},
		{
			name: "http endpoint downgrades to plaintext",
			al:   &AccessLogSettings{Enabled: true, UseAuditChannel: true},
			ls:   &ShipperSettings{Type: "s3", Endpoint: "http://minio:9000", Bucket: "b"},
			check: func(t *testing.T, got *AccessLogSettings) {
				if got.S3.Endpoint != "minio:9000" || got.S3.UseSSL {
					t.Fatalf("s3 = %s/%v, want minio:9000/plain", got.S3.Endpoint, got.S3.UseSSL)
				}
			},
		},
		{
			name: "https endpoint stays secure",
			al:   &AccessLogSettings{Enabled: true, UseAuditChannel: true},
			ls:   &ShipperSettings{Type: "s3", Endpoint: "https://minio:9000", Bucket: "b"},
			check: func(t *testing.T, got *AccessLogSettings) {
				if got.S3.Endpoint != "minio:9000" || !got.S3.UseSSL {
					t.Fatalf("s3 = %s/%v, want minio:9000/secure", got.S3.Endpoint, got.S3.UseSSL)
				}
			},
		},
		{
			name: "bare endpoint defaults secure",
			al:   &AccessLogSettings{Enabled: true, UseAuditChannel: true},
			ls:   &ShipperSettings{Type: "s3", Endpoint: "minio:9000", Bucket: "b"},
			check: func(t *testing.T, got *AccessLogSettings) {
				if got.S3.Endpoint != "minio:9000" || !got.S3.UseSSL {
					t.Fatalf("s3 = %s/%v, want minio:9000/secure", got.S3.Endpoint, got.S3.UseSSL)
				}
			},
		},
		{
			name: "endpoint whitespace trimmed",
			al:   &AccessLogSettings{Enabled: true, UseAuditChannel: true},
			ls:   &ShipperSettings{Type: "s3", Endpoint: "  minio:9000  ", Bucket: "b"},
			check: func(t *testing.T, got *AccessLogSettings) {
				if got.S3.Endpoint != "minio:9000" {
					t.Fatalf("s3 endpoint = %q, want trimmed", got.S3.Endpoint)
				}
			},
		},
		{
			name: "explicit use_ssl=false wins over https scheme",
			al:   &AccessLogSettings{Enabled: true, UseAuditChannel: true},
			ls:   &ShipperSettings{Type: "s3", Endpoint: "https://minio:9000", Bucket: "b", UseSSL: b(false)},
			check: func(t *testing.T, got *AccessLogSettings) {
				if got.S3.UseSSL {
					t.Fatalf("s3 use_ssl = %v, want false (explicit wins)", got.S3.UseSSL)
				}
			},
		},
		{
			name: "non-s3/syslog channel drops sub-structures",
			al: &AccessLogSettings{
				Enabled: true, UseAuditChannel: true,
				S3:     &S3Settings{Endpoint: "own:9000", Bucket: "own-bucket"},
				Syslog: &SyslogSettings{AppName: "waf-access"},
			},
			ls: &ShipperSettings{Type: "loki", URL: "http://loki:3100"},
			check: func(t *testing.T, got *AccessLogSettings) {
				if got.S3 != nil || got.Syslog != nil {
					t.Fatalf("S3=%v Syslog=%v, want both dropped", got.S3, got.Syslog)
				}
			},
		},
		{
			name: "channel app-name stripped, own kept",
			al: &AccessLogSettings{
				Enabled: true, UseAuditChannel: true,
				Syslog: &SyslogSettings{AppName: "waf-access"},
			},
			ls: &ShipperSettings{Type: "syslog", URL: "tcp://c:514", Syslog: &SyslogSettings{AppName: "kingmoat", Facility: 4}},
			check: func(t *testing.T, got *AccessLogSettings) {
				if got.Syslog.AppName != "waf-access" || got.Syslog.Facility != 4 {
					t.Fatalf("syslog = %+v, want channel transport + own app name", got.Syslog)
				}
			},
		},
		{
			name: "channel without syslog block yields defaults",
			al:   &AccessLogSettings{Enabled: true, UseAuditChannel: true},
			ls:   &ShipperSettings{Type: "syslog", URL: "tcp://c:514"},
			check: func(t *testing.T, got *AccessLogSettings) {
				if got.Syslog == nil || *got.Syslog != (SyslogSettings{}) {
					t.Fatalf("syslog = %+v, want all-defaults block", got.Syslog)
				}
			},
		},
	}
	for _, row := range accessRows {
		t.Run("access/"+row.name, func(t *testing.T) {
			got := ResolveAccessOut(row.al, row.ls)
			if got == nil {
				t.Fatal("switch-on enabled section must resolve")
			}
			row.check(t, got)
		})
	}

	type aiRow struct {
		name  string
		ship  *AIAuditShipSettings
		ls    *ShipperSettings
		check func(t *testing.T, got *AIAuditShipSettings)
	}
	aiRows := []aiRow{
		{
			name: "flat prefix seeds when nested absent",
			ship: &AIAuditShipSettings{Enabled: true, UseAuditChannel: true, Prefix: "kingmoat/ai"},
			ls:   &ShipperSettings{Type: "s3", Endpoint: "minio:9000", Bucket: "b"},
			check: func(t *testing.T, got *AIAuditShipSettings) {
				if got.S3 == nil || got.S3.Prefix != "kingmoat/ai" {
					t.Fatalf("s3 = %+v, want flat prefix seed", got.S3)
				}
			},
		},
		{
			name: "flat prefix empty and nested absent leave prefix empty",
			ship: &AIAuditShipSettings{Enabled: true, UseAuditChannel: true},
			ls:   &ShipperSettings{Type: "s3", Endpoint: "minio:9000", Bucket: "b"},
			check: func(t *testing.T, got *AIAuditShipSettings) {
				if got.S3 == nil || got.S3.Prefix != "" {
					t.Fatalf("s3 = %+v, want empty prefix", got.S3)
				}
			},
		},
		{
			name: "non-s3 channel drops flat seeds with the sub-structure",
			ship: &AIAuditShipSettings{
				Enabled: true, UseAuditChannel: true, Prefix: "kingmoat/ai",
				S3:     &S3Settings{Endpoint: "own:9000", Bucket: "own-bucket"},
				Syslog: &SyslogSettings{AppName: "waf-ai"},
			},
			ls: &ShipperSettings{Type: "elasticsearch", URL: "http://a:9200"},
			check: func(t *testing.T, got *AIAuditShipSettings) {
				if got.S3 != nil || got.Syslog != nil {
					t.Fatalf("S3=%v Syslog=%v, want both dropped", got.S3, got.Syslog)
				}
			},
		},
		{
			name: "kafka channel copies transport with deep tls_skip_verify",
			ship: &AIAuditShipSettings{Enabled: true, UseAuditChannel: true, Index: "kingmoat_ai_sessions"},
			ls:   kafkaLS,
			check: func(t *testing.T, got *AIAuditShipSettings) {
				if got.Type != "kafka" || got.Topic != "t" || !got.UseTLS || got.SASL != "plain" {
					t.Fatalf("kafka = %s/%s/%v/%s, want the channel's", got.Type, got.Topic, got.UseTLS, got.SASL)
				}
				if got.TLSSkipVerify == nil || *got.TLSSkipVerify || got.TLSSkipVerify == kafkaLS.TLSSkipVerify {
					t.Fatalf("tls_skip_verify = %v, want a fresh copy of false", got.TLSSkipVerify)
				}
			},
		},
	}
	for _, row := range aiRows {
		t.Run("ai/"+row.name, func(t *testing.T) {
			got := ResolveAIShipOut(row.ship, row.ls)
			if got == nil {
				t.Fatal("switch-on enabled ship must resolve")
			}
			row.check(t, got)
		})
	}
}
