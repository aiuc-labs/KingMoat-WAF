package configcenter

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/store"
)

// v0713RevisionRaw is a stored revision in the exact shape v0.7.13 accepted
// and its console produced: access_log with FLAT s3 fields (no nested s3
// block — the current AccessLogSettings schema drops those keys on unmarshal)
// and a log_shipper of type syslog WITHOUT a syslog block (v0.7.13 validated
// that shape as legal). Under the strict post-v0.7.13 validation both shapes
// are rejected, which would deny an upgraded binary boot (configcenter.Open →
// main exit 1) — normalization must keep the load alive.
const v0713RevisionRaw = `{
	"listen_http": ":8080",
	"sites": [{"domains": ["a.local"], "upstream": {"nodes": [{"address": "127.0.0.1:9001"}]}}],
	"log_shipper": {"type": "syslog", "url": "tcp://siem.example.com:514", "index": "kingmoat"},
	"access_log": {"enabled": true, "type": "s3", "index": "kingmoat_access", "sample_pct": 100,
		"endpoint": "minio.internal:9000", "bucket": "waf-logs", "prefix": "kingmoat",
		"access_key": "ak", "secret_key": "sk", "use_ssl": true}
}`

// seedLegacyDB writes raw as the only revision of a fresh store, mimicking a
// database carried over from a v0.7.13 installation.
func seedLegacyDB(t *testing.T, raw string) string {
	t.Helper()
	path := t.TempDir() + "/cc.db"
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AppendRevision(raw, "console", "v0.7.13 shape"); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestOpenBootsLegacyRevision: the upgrade simulation from the release-gate
// BLOCK item — a v0.7.13-shaped stored revision must NOT make Open fail, and
// the in-memory config must carry the migrated nested s3 block plus the
// synthesized syslog block.
func TestOpenBootsLegacyRevision(t *testing.T) {
	c, err := Open(seedLegacyDB(t, v0713RevisionRaw), seedCfg(), quiet())
	if err != nil {
		t.Fatalf("upgrade must not refuse to boot: %v", err)
	}
	defer c.Close()

	rev, cfg := c.Current()
	if rev != 1 {
		t.Fatalf("revision = %d, want 1", rev)
	}
	al := cfg.AccessLog
	if al == nil || al.S3 == nil {
		t.Fatal("access_log.s3 block missing after load-time migration")
	}
	if al.S3.Endpoint != "minio.internal:9000" || al.S3.Bucket != "waf-logs" ||
		al.S3.Prefix != "kingmoat" || al.S3.AccessKey != "ak" || al.S3.SecretKey != "sk" || !al.S3.UseSSL {
		t.Fatalf("migrated s3 block wrong: %+v", al.S3)
	}
	ls := cfg.LogShipper
	if ls == nil || ls.Syslog == nil {
		t.Fatal("log_shipper.syslog block not synthesized")
	}
	if ls.Syslog.Protocol != "tcp" || ls.Syslog.Format != "rfc5424" {
		t.Fatalf("synthesized syslog block wrong: %+v", ls.Syslog)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("migrated in-memory config must validate: %v", err)
	}

	// The stored revision stays untouched (append-only history): the raw
	// payload on disk still carries the legacy flat form.
	stRaw, err := c.Store().GetRevision(1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stRaw, `"endpoint"`) || strings.Contains(stRaw, `"s3":{`) {
		t.Fatal("stored revision must not be rewritten in place")
	}
}

// TestOpenRejectsGenuinelyBrokenRevision: the load-time tolerance covers
// outbound sections ONLY — a revision broken for reasons the degradation
// does not address (here: an upstream node with an empty address, a site
// field Config.Validate rejects) still refuses to boot (same fail-fast
// contract as before). Any outbound-section breakage, however, is degraded,
// never fatal (see the table-driven test below).
func TestOpenRejectsGenuinelyBrokenRevision(t *testing.T) {
	broken := strings.Replace(v0713RevisionRaw, `"address": "127.0.0.1:9001"`, `"address": ""`, 1)
	if broken == v0713RevisionRaw {
		t.Fatal("test bug: the breakage replacement must actually change the revision")
	}
	if _, err := Open(seedLegacyDB(t, broken), seedCfg(), quiet()); err == nil {
		t.Fatal("a revision invalid outside the outbound sections must still refuse to boot")
	}
}

// TestPublishStaysStrict: the load-time tolerance must not relax the publish
// gate — hand-built invalid outbounds are rejected exactly as before.
func TestPublishStaysStrict(t *testing.T) {
	c, err := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	cases := map[string]*config.Config{
		"access_log s3 without block": {
			ListenHTTP: ":8080",
			Sites:      seedCfg().Sites,
			AccessLog:  &config.AccessLogSettings{Enabled: true, Type: "s3"},
		},
		"access_log bogus type": {
			ListenHTTP: ":8080",
			Sites:      seedCfg().Sites,
			AccessLog:  &config.AccessLogSettings{Enabled: true, Type: "bogus"},
		},
		"access_log syslog without block": {
			ListenHTTP: ":8080",
			Sites:      seedCfg().Sites,
			AccessLog:  &config.AccessLogSettings{Enabled: true, Type: "syslog", URL: "udp://siem:514"},
		},
		"access_log kafka without brokers": {
			ListenHTTP: ":8080",
			Sites:      seedCfg().Sites,
			AccessLog:  &config.AccessLogSettings{Enabled: true, Type: "kafka", Topic: "t"},
		},
		"log_shipper bogus type": {
			ListenHTTP: ":8080",
			Sites:      seedCfg().Sites,
			LogShipper: &config.ShipperSettings{Type: "bogus"},
		},
		"ai_audit.ship s3 without block": {
			ListenHTTP: ":8080",
			Sites:      seedCfg().Sites,
			AiAudit:    &config.AIAuditSettings{Ship: &config.AIAuditShipSettings{Enabled: true, Type: "s3"}},
		},
		"ai_audit.ship bogus type": {
			ListenHTTP: ":8080",
			Sites:      seedCfg().Sites,
			AiAudit:    &config.AIAuditSettings{Ship: &config.AIAuditShipSettings{Enabled: true, Type: "bogus"}},
		},
		"ai_audit.ship syslog without block": {
			ListenHTTP: ":8080",
			Sites:      seedCfg().Sites,
			AiAudit:    &config.AIAuditSettings{Ship: &config.AIAuditShipSettings{Enabled: true, Type: "syslog", URL: "udp://siem:514"}},
		},
		"kafka without brokers": {
			ListenHTTP: ":8080",
			Sites:      seedCfg().Sites,
			LogShipper: &config.ShipperSettings{Type: "kafka", Topic: "t"},
		},
		"syslog without block": {
			ListenHTTP: ":8080",
			Sites:      seedCfg().Sites,
			LogShipper: &config.ShipperSettings{Type: "syslog", URL: "tcp://siem:514"},
		},
	}
	for name, bad := range cases {
		if _, err := c.Publish(bad, "t", name); err == nil {
			t.Fatalf("%s: publish must stay strict", name)
		}
	}
	rev, _ := c.Current()
	if rev != 1 {
		t.Fatalf("current revision changed by rejected publishes: %d", rev)
	}
}

// TestRollbackLegacyRevision: rolling back to a pre-strictness revision
// re-publishes its payload — the legacy shapes are normalized into the new
// revision instead of failing the rollback.
func TestRollbackLegacyRevision(t *testing.T) {
	path := seedLegacyDB(t, v0713RevisionRaw)
	c, err := Open(path, seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.Publish(twoSiteCfg(), "t", "v2 strict shape"); err != nil {
		t.Fatal(err)
	}
	newRev, err := c.Rollback(1, "admin")
	if err != nil {
		t.Fatalf("rollback to legacy revision must succeed after normalization: %v", err)
	}
	_, cfg := c.Current()
	if cfg.AccessLog == nil || cfg.AccessLog.S3 == nil || cfg.LogShipper.Syslog == nil {
		t.Fatalf("rolled-back config missing normalized blocks: %+v", cfg.AccessLog)
	}
	stRaw, err := c.Store().GetRevision(newRev)
	if err != nil {
		t.Fatal(err)
	}
	var probe struct {
		LogShipper struct {
			Syslog *json.RawMessage `json:"syslog"`
		} `json:"log_shipper"`
	}
	if err := json.Unmarshal([]byte(stRaw), &probe); err != nil {
		t.Fatal(err)
	}
	if probe.LogShipper.Syslog == nil {
		t.Fatal("new rollback revision must store the normalized form")
	}
}

// --- gate evidence: v0.7.13 outbound shapes can never deny a boot ----------
//
// v0713OutboundTemplate is the non-outbound skeleton shared by the table
// below; every case injects its outbound sections at %s. The table
// enumerates the outbound shapes v0.7.13 could store (its console validated
// none of the per-type channel rules that are strict today, plus the
// defensive use_audit_channel shapes): for EVERY row Open must succeed —
// the state is degraded, never a refusal to boot — and the stored revision
// must stay byte-identical (append-only; re-derived on every boot).

const v0713OutboundTemplate = `{
	"listen_http": ":8080",
	"sites": [{"domains": ["a.local"], "upstream": {"nodes": [{"address": "127.0.0.1:9001"}]}}]%s
}`

func TestOpenBootsEveryV0713OutboundShape(t *testing.T) {
	tests := []struct {
		name     string
		outbound string // JSON fragment appended after "sites" ("" = none)
		wantAL   string // access_log after load: "enabled" | "disabled" | "absent"
		wantLS   string // log_shipper after load: "kept" | "removed" | "absent"
		wantShip string // ai_audit.ship after load: "enabled" | "disabled" | "absent"
		verify   func(*testing.T, *config.Config)
	}{
		{
			name:     "access_log s3 flat complete (v0.7.13 console form)",
			outbound: `, "access_log": {"enabled": true, "type": "s3", "index": "kingmoat_access", "sample_pct": 100, "endpoint": "minio.internal:9000", "bucket": "waf-logs", "prefix": "kingmoat", "access_key": "ak", "secret_key": "sk", "use_ssl": true}`,
			wantAL:   "enabled", wantLS: "absent", wantShip: "absent",
			verify: func(t *testing.T, cfg *config.Config) {
				if cfg.AccessLog.S3 == nil || cfg.AccessLog.S3.Endpoint != "minio.internal:9000" || !cfg.AccessLog.S3.UseSSL {
					t.Fatalf("flat s3 keys must migrate into the nested block: %+v", cfg.AccessLog.S3)
				}
			},
		},
		{
			name:     "access_log s3 flat keys empty strings",
			outbound: `, "access_log": {"enabled": true, "type": "s3", "endpoint": "", "bucket": "", "access_key": "", "secret_key": ""}`,
			wantAL:   "disabled", wantLS: "absent", wantShip: "absent",
		},
		{
			name:     "access_log s3 without any s3 data",
			outbound: `, "access_log": {"enabled": true, "type": "s3"}`,
			wantAL:   "disabled", wantLS: "absent", wantShip: "absent",
		},
		{
			name:     "access_log s3 nested block (current console form)",
			outbound: `, "access_log": {"enabled": true, "type": "s3", "s3": {"endpoint": "minio.internal:9000", "bucket": "waf-logs", "access_key": "ak", "secret_key": "sk"}}`,
			wantAL:   "enabled", wantLS: "absent", wantShip: "absent",
		},
		{
			name:     "access_log kafka without brokers",
			outbound: `, "access_log": {"enabled": true, "type": "kafka", "topic": "t"}`,
			wantAL:   "disabled", wantLS: "absent", wantShip: "absent",
		},
		{
			name:     "access_log kafka complete",
			outbound: `, "access_log": {"enabled": true, "type": "kafka", "brokers": ["b.internal:9092"], "topic": "kingmoat_access"}`,
			wantAL:   "enabled", wantLS: "absent", wantShip: "absent",
		},
		{
			name:     "access_log elasticsearch without url",
			outbound: `, "access_log": {"enabled": true, "type": "elasticsearch", "index": "kingmoat_access"}`,
			wantAL:   "disabled", wantLS: "absent", wantShip: "absent",
		},
		{
			name:     "access_log clickhouse without url",
			outbound: `, "access_log": {"enabled": true, "type": "clickhouse"}`,
			wantAL:   "disabled", wantLS: "absent", wantShip: "absent",
		},
		{
			name:     "access_log loki without url",
			outbound: `, "access_log": {"enabled": true, "type": "loki"}`,
			wantAL:   "disabled", wantLS: "absent", wantShip: "absent",
		},
		{
			name:     "access_log syslog without block (v0.7.13 legal)",
			outbound: `, "access_log": {"enabled": true, "type": "syslog", "url": "tcp://siem.example.com:514", "index": "kingmoat_access"}`,
			wantAL:   "enabled", wantLS: "absent", wantShip: "absent",
			verify: func(t *testing.T, cfg *config.Config) {
				if cfg.AccessLog.Syslog == nil || cfg.AccessLog.Syslog.Protocol != "tcp" || cfg.AccessLog.Syslog.Format != "rfc5424" {
					t.Fatalf("syslog block must be synthesized: %+v", cfg.AccessLog.Syslog)
				}
			},
		},
		{
			name:     "access_log bogus type",
			outbound: `, "access_log": {"enabled": true, "type": "bogus"}`,
			wantAL:   "disabled", wantLS: "absent", wantShip: "absent",
		},
		{
			// Not a v0.7.13 shape (the switch postdates it); the defensive
			// tail must still keep the boot alive.
			name:     "access_log use_audit_channel without log_shipper (defensive)",
			outbound: `, "access_log": {"enabled": true, "use_audit_channel": true}`,
			wantAL:   "disabled", wantLS: "absent", wantShip: "absent",
		},
		{
			name:     "access_log use_audit_channel over a broken log_shipper (both degrade)",
			outbound: `, "access_log": {"enabled": true, "use_audit_channel": true}, "log_shipper": {"type": "kafka", "topic": "t"}`,
			wantAL:   "disabled", wantLS: "removed", wantShip: "absent",
		},
		{
			name:     "log_shipper elasticsearch without url",
			outbound: `, "log_shipper": {"type": "elasticsearch", "index": "kingmoat"}`,
			wantAL:   "absent", wantLS: "removed", wantShip: "absent",
		},
		{
			name:     "log_shipper clickhouse complete",
			outbound: `, "log_shipper": {"type": "clickhouse", "url": "http://ch.internal:8123", "index": "kingmoat"}`,
			wantAL:   "absent", wantLS: "kept", wantShip: "absent",
		},
		{
			name:     "log_shipper s3 complete",
			outbound: `, "log_shipper": {"type": "s3", "endpoint": "minio.internal:9000", "bucket": "kingmoat", "access_key": "ak", "secret_key": "sk"}`,
			wantAL:   "absent", wantLS: "kept", wantShip: "absent",
		},
		{
			name:     "log_shipper s3 missing secret_key",
			outbound: `, "log_shipper": {"type": "s3", "endpoint": "minio.internal:9000", "bucket": "kingmoat", "access_key": "ak"}`,
			wantAL:   "absent", wantLS: "removed", wantShip: "absent",
		},
		{
			name:     "log_shipper syslog without block (v0.7.13 legal)",
			outbound: `, "log_shipper": {"type": "syslog", "url": "udp://siem.example.com:514", "index": "kingmoat"}`,
			wantAL:   "absent", wantLS: "kept", wantShip: "absent",
			verify: func(t *testing.T, cfg *config.Config) {
				if cfg.LogShipper.Syslog == nil || cfg.LogShipper.Syslog.Protocol != "udp" || cfg.LogShipper.Syslog.Format != "rfc5424" {
					t.Fatalf("syslog block must be synthesized: %+v", cfg.LogShipper.Syslog)
				}
			},
		},
		{
			name:     "log_shipper syslog with http url",
			outbound: `, "log_shipper": {"type": "syslog", "url": "http://siem.example.com:514", "syslog": {"protocol": "tcp", "format": "rfc5424"}}`,
			wantAL:   "absent", wantLS: "removed", wantShip: "absent",
		},
		{
			name:     "log_shipper kafka without brokers",
			outbound: `, "log_shipper": {"type": "kafka", "topic": "kingmoat"}`,
			wantAL:   "absent", wantLS: "removed", wantShip: "absent",
		},
		{
			name:     "log_shipper kafka sasl plain without credentials",
			outbound: `, "log_shipper": {"type": "kafka", "brokers": ["b.internal:9092"], "topic": "kingmoat", "sasl": "plain"}`,
			wantAL:   "absent", wantLS: "removed", wantShip: "absent",
		},
		{
			name:     "log_shipper bogus type",
			outbound: `, "log_shipper": {"type": "bogus"}`,
			wantAL:   "absent", wantLS: "removed", wantShip: "absent",
		},
		{
			name:     "ai_audit.ship s3 without block",
			outbound: `, "ai_audit": {"ship": {"enabled": true, "type": "s3"}}`,
			wantAL:   "absent", wantLS: "absent", wantShip: "disabled",
		},
		{
			name:     "ai_audit.ship kafka without brokers",
			outbound: `, "ai_audit": {"ship": {"enabled": true, "type": "kafka", "topic": "t"}}`,
			wantAL:   "absent", wantLS: "absent", wantShip: "disabled",
		},
		{
			name:     "ai_audit.ship syslog without block (v0.7.13 legal)",
			outbound: `, "ai_audit": {"ship": {"enabled": true, "type": "syslog", "url": "udp://collector.internal:514"}}`,
			wantAL:   "absent", wantLS: "absent", wantShip: "enabled",
			verify: func(t *testing.T, cfg *config.Config) {
				if cfg.AiAudit.Ship.Syslog == nil || cfg.AiAudit.Ship.Syslog.Protocol != "udp" {
					t.Fatalf("syslog block must be synthesized: %+v", cfg.AiAudit.Ship.Syslog)
				}
			},
		},
		{
			name:     "ai_audit.ship elasticsearch with url",
			outbound: `, "ai_audit": {"ship": {"enabled": true, "type": "elasticsearch", "url": "http://es.internal:9200"}}`,
			wantAL:   "absent", wantLS: "absent", wantShip: "enabled",
		},
		{
			// Not a v0.7.13 shape (the switch postdates it); defensive tail.
			name:     "ai_audit.ship use_audit_channel without log_shipper (defensive)",
			outbound: `, "ai_audit": {"ship": {"enabled": true, "use_audit_channel": true}}`,
			wantAL:   "absent", wantLS: "absent", wantShip: "disabled",
		},
		{
			name: "all three sections in legacy shapes at once (kept/enabled)",
			outbound: `, "log_shipper": {"type": "syslog", "url": "tcp://siem.internal:514", "index": "kingmoat"},
	"access_log": {"enabled": true, "type": "s3", "endpoint": "minio.internal:9000", "bucket": "waf-logs", "access_key": "ak", "secret_key": "sk"},
	"ai_audit": {"ship": {"enabled": true, "type": "syslog", "url": "udp://collector.internal:514"}}`,
			wantAL: "enabled", wantLS: "kept", wantShip: "enabled",
		},
		{
			name: "all three sections unshippable at once (degraded, boot survives)",
			outbound: `, "log_shipper": {"type": "kafka"},
	"access_log": {"enabled": true, "type": "s3"},
	"ai_audit": {"ship": {"enabled": true, "type": "s3"}}`,
			wantAL: "disabled", wantLS: "removed", wantShip: "disabled",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Sprintf(v0713OutboundTemplate, tc.outbound)
			c, err := Open(seedLegacyDB(t, raw), seedCfg(), quiet())
			if err != nil {
				t.Fatalf("v0.7.13 outbound shape must never deny boot: %v", err)
			}
			defer c.Close()

			rev, cfg := c.Current()
			if rev != 1 {
				t.Fatalf("revision = %d, want 1", rev)
			}
			assertOutboundState(t, cfg, tc.wantAL, tc.wantLS, tc.wantShip)
			if tc.verify != nil {
				tc.verify(t, cfg)
			}

			// The stored revision stays byte-identical: normalization is
			// re-derived on every boot, never written back (append-only).
			stRaw, err := c.Store().GetRevision(1)
			if err != nil {
				t.Fatal(err)
			}
			if stRaw != raw {
				t.Fatal("stored revision must not be rewritten in place")
			}
		})
	}
}

// assertOutboundState checks the post-load state of the three outbound
// sections: "enabled"/"disabled" for the flagged sections (access_log,
// ai_audit.ship), "kept"/"removed" for log_shipper (a nil section means
// off — ShipperSettings has no enabled flag), "absent" = the section must
// not be there at all.
func assertOutboundState(t *testing.T, cfg *config.Config, wantAL, wantLS, wantShip string) {
	t.Helper()
	switch wantAL {
	case "enabled":
		if cfg.AccessLog == nil || !cfg.AccessLog.Enabled {
			t.Fatalf("access_log must stay enabled: %+v", cfg.AccessLog)
		}
	case "disabled":
		if cfg.AccessLog == nil {
			t.Fatal("access_log section must survive (degraded to disabled), got nil")
		}
		if cfg.AccessLog.Enabled {
			t.Fatal("access_log must be degraded to disabled")
		}
	case "absent":
		if cfg.AccessLog != nil {
			t.Fatalf("access_log must be absent, got %+v", cfg.AccessLog)
		}
	default:
		t.Fatalf("bad wantAL %q", wantAL)
	}
	switch wantLS {
	case "kept":
		if cfg.LogShipper == nil {
			t.Fatal("log_shipper must be kept")
		}
	case "removed", "absent":
		if cfg.LogShipper != nil {
			t.Fatalf("log_shipper must be off, got %+v", cfg.LogShipper)
		}
	default:
		t.Fatalf("bad wantLS %q", wantLS)
	}
	switch wantShip {
	case "enabled":
		if cfg.AiAudit == nil || cfg.AiAudit.Ship == nil || !cfg.AiAudit.Ship.Enabled {
			t.Fatalf("ai_audit.ship must stay enabled: %+v", cfg.AiAudit)
		}
	case "disabled":
		if cfg.AiAudit == nil || cfg.AiAudit.Ship == nil {
			t.Fatal("ai_audit.ship section must survive (degraded to disabled), got nil")
		}
		if cfg.AiAudit.Ship.Enabled {
			t.Fatal("ai_audit.ship must be degraded to disabled")
		}
	case "absent":
		if cfg.AiAudit != nil && cfg.AiAudit.Ship != nil {
			t.Fatalf("ai_audit.ship must be absent, got %+v", cfg.AiAudit.Ship)
		}
	default:
		t.Fatalf("bad wantShip %q", wantShip)
	}
}
