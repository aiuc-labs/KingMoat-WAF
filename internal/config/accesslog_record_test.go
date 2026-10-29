package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recTestCfg is the smallest valid config the Validate call sites run against
// (Validate requires a listener; the site provides the recording target).
func recTestCfg() *Config {
	return &Config{
		ListenHTTP: ":80",
		Sites: []Site{{
			Domains:  []string{"shop.example.com"},
			Upstream: Upstream{Nodes: []UpstreamNode{{Address: "127.0.0.1:9001"}}},
		}},
	}
}

// TestAccessLogRecordAbsentSectionIsZeroChange is the backward-compat proof:
// an old config (no access_log_record key) loads and validates with the
// section nil, which means recording stays off and every runtime path treats
// the config exactly as before this feature.
func TestAccessLogRecordAbsentSectionIsZeroChange(t *testing.T) {
	old := `{"listen_http": ":80", "sites": [{"domains": ["shop.example.com"],
		"upstream": {"nodes": [{"address": "127.0.0.1:9001"}]}}]}`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("legacy config without access_log_record must load unchanged: %v", err)
	}
	if cfg.AccessLogRecord != nil {
		t.Fatalf("AccessLogRecord = %+v, want nil for a legacy config", cfg.AccessLogRecord)
	}
}

// TestAccessLogRecordValidationTable covers every validation branch and both
// happy paths (all / sites) end to end through Config.Validate (the same
// entry point Load and the console publish use).
func TestAccessLogRecordValidationTable(t *testing.T) {
	cases := []struct {
		name    string
		rec     *AccessLogRecordSettings
		wantErr string // "" = accepted
	}{
		{"nil section", nil, ""},
		{"mode off", &AccessLogRecordSettings{Mode: "off"}, ""},
		{"mode empty defaults off", &AccessLogRecordSettings{}, ""},
		{"mode all", &AccessLogRecordSettings{Mode: "all"}, ""},
		{"mode case-insensitive", &AccessLogRecordSettings{Mode: "ALL"}, ""},
		{"mode sites valid", &AccessLogRecordSettings{Mode: "sites", Sites: []string{"shop.example.com"}}, ""},
		{"mode sites padded+upper", &AccessLogRecordSettings{Mode: "sites", Sites: []string{" SHOP.EXAMPLE.COM "}}, ""},
		{"mode bogus", &AccessLogRecordSettings{Mode: "maybe"}, `access_log_record.mode must be "off", "all" or "sites"`},
		{"sites empty", &AccessLogRecordSettings{Mode: "sites"}, "non-empty sites list"},
		{"sites unknown domain", &AccessLogRecordSettings{Mode: "sites", Sites: []string{"ghost.example.com"}}, "unknown site(s): ghost.example.com"},
		{"sites second domain rejected", &AccessLogRecordSettings{Mode: "sites", Sites: []string{"api.shop.example.com"}}, "unknown site(s): api.shop.example.com"},
		{"retention boundary ok", &AccessLogRecordSettings{Mode: "all", RetentionDays: 1}, ""},
		{"retention over range", &AccessLogRecordSettings{Mode: "all", RetentionDays: 91}, "retention_days must be 0 (= default 7) or within 1-90, got 91"},
		{"max_disk_mb under range", &AccessLogRecordSettings{Mode: "all", MaxDiskMB: 127}, "max_disk_mb must be 0 (= default 1024) or within 128-10240, got 127"},
		{"max_disk_mb over range", &AccessLogRecordSettings{Mode: "all", MaxDiskMB: 10241}, "max_disk_mb must be 0 (= default 1024) or within 128-10240, got 10241"},
		{"batch_size under range", &AccessLogRecordSettings{Mode: "all", BatchSize: 63}, "batch_size must be 0 (= default 256) or within 64-2048, got 63"},
		{"batch_size over range", &AccessLogRecordSettings{Mode: "all", BatchSize: 2049}, "batch_size must be 0 (= default 256) or within 64-2048, got 2049"},
		{"flush_sec under range", &AccessLogRecordSettings{Mode: "all", FlushSec: 0}, ""},
		{"flush_sec over range", &AccessLogRecordSettings{Mode: "all", FlushSec: 61}, "flush_sec must be 0 (= default 1) or within 1-60, got 61"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := recTestCfg()
			c.AccessLogRecord = tc.rec
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("config must be accepted, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("config must be rejected, want %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestAccessLogRecordDefaults pins the zero-value defaults (the contract the
// sink and the status endpoint rely on).
func TestAccessLogRecordDefaults(t *testing.T) {
	var nilRec *AccessLogRecordSettings
	if got := nilRec.ModeOrDefault(); got != "off" {
		t.Fatalf("nil mode = %q, want off", got)
	}
	if got := nilRec.RetentionDaysOrDefault(); got != 7 {
		t.Fatalf("nil retention = %d, want 7", got)
	}
	if got := nilRec.MaxDiskMBOrDefault(); got != 1024 {
		t.Fatalf("nil max_disk_mb = %d, want 1024", got)
	}
	if got := nilRec.BatchSizeOrDefault(); got != 256 {
		t.Fatalf("nil batch = %d, want 256", got)
	}
	if got := nilRec.FlushSecOrDefault(); got != 1 {
		t.Fatalf("nil flush = %d, want 1", got)
	}
	rec := &AccessLogRecordSettings{}
	if rec.ModeOrDefault() != "off" || rec.RetentionDaysOrDefault() != 7 ||
		rec.MaxDiskMBOrDefault() != 1024 || rec.BatchSizeOrDefault() != 256 ||
		rec.FlushSecOrDefault() != 1 {
		t.Fatalf("zero-value defaults diverge: %+v", rec)
	}
	custom := &AccessLogRecordSettings{Mode: "SITES ", RetentionDays: 30, MaxDiskMB: 2048, BatchSize: 512, FlushSec: 5}
	if custom.ModeOrDefault() != "sites" || custom.RetentionDaysOrDefault() != 30 ||
		custom.MaxDiskMBOrDefault() != 2048 || custom.BatchSizeOrDefault() != 512 ||
		custom.FlushSecOrDefault() != 5 {
		t.Fatalf("custom values not honored: %+v", custom)
	}
}

// TestAccessLogRecordJSONShape pins the wire format the console publishes.
func TestAccessLogRecordJSONShape(t *testing.T) {
	b, err := json.Marshal(&AccessLogRecordSettings{
		Mode: "sites", Sites: []string{"shop.example.com", "api.example.cn"},
		RetentionDays: 7, MaxDiskMB: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["mode"] != "sites" {
		t.Fatalf("mode = %v", m["mode"])
	}
	sites, ok := m["sites"].([]any)
	if !ok || len(sites) != 2 {
		t.Fatalf("sites = %v", m["sites"])
	}
	if _, ok := m["retention_days"]; !ok {
		t.Fatal("retention_days key missing")
	}
	if _, ok := m["max_disk_mb"]; !ok {
		t.Fatal("max_disk_mb key missing")
	}
}
