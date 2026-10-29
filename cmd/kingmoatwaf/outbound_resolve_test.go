package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/accesslog"
	"github.com/kingmoat/kingmoat/internal/aisession"
	"github.com/kingmoat/kingmoat/internal/config"
)

// --- resolve rules (thin wrappers over config.ResolveAccessOut /
// config.ResolveAIShipOut, implemented in internal/config) ---

// channelBase is the log_shipper section the resolve tests reuse.
func channelBase() *config.ShipperSettings {
	return &config.ShipperSettings{
		Type: "elasticsearch", URL: "http://audit.internal:9200",
		Index: "kingmoat", BatchSize: 50, FlushSec: 7, TimeoutSec: 3,
		Username: "audit-u", Password: "audit-p",
		Brokers: []string{"b1:9092"}, Topic: "audit-topic", UseTLS: true, SASL: "plain",
		Prefix: "kingmoat/audit",
		Syslog: &config.SyslogSettings{Protocol: "tcp", Format: "rfc3164", AppName: "kingmoat", Facility: 4},
	}
}

func TestResolveAccessOutPassthrough(t *testing.T) {
	al := &config.AccessLogSettings{Enabled: true, Type: "clickhouse", URL: "http://own:8123"}

	if got := resolveAccessOut(nil, channelBase()); got != nil {
		t.Fatalf("nil section must pass through, got %+v", got)
	}
	if got := resolveAccessOut(al, channelBase()); got != al {
		t.Fatal("switch-off section must pass through unchanged (same pointer)")
	}
	if got := resolveAccessOut(&config.AccessLogSettings{Enabled: false, UseAuditChannel: true}, channelBase()); got.Enabled {
		t.Fatal("disabled section must pass through (no channel overlay: channel changes never wake a stopped pipeline)")
	}
	if got := resolveAccessOut(&config.AccessLogSettings{Enabled: true, UseAuditChannel: true}, nil); !got.UseAuditChannel || got.URL != "" {
		t.Fatal("switch-on section with no channel must pass through (the rebuilder warns and disables)")
	}
}

func TestResolveAccessOutOverlay(t *testing.T) {
	al := &config.AccessLogSettings{
		Enabled: true, Type: "clickhouse", URL: "http://own:8123",
		Index: "kingmoat_access", SamplePct: 40, BatchSize: 10, FlushSec: 9, TimeoutSec: 9,
		Username: "own-u", Password: "own-p",
		UseAuditChannel: true,
		Brokers:         []string{"own-broker"}, Topic: "own-topic",
	}
	ls := channelBase()
	got := resolveAccessOut(al, ls)
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
	ls := channelBase()
	ls.Type = "s3"
	ls.Endpoint = "http://minio.internal:9000"
	ls.Bucket = "audit-bucket"
	ls.AccessKey, ls.SecretKey = "ak", "sk"

	// No section s3 block: prefix empty, transport derived from the endpoint
	// scheme exactly like logshipper (http → plaintext).
	got := resolveAccessOut(&config.AccessLogSettings{Enabled: true, UseAuditChannel: true}, ls)
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
	own := &config.AccessLogSettings{Enabled: true, UseAuditChannel: true, S3: &config.S3Settings{Endpoint: "own:9000", Bucket: "own-bucket", Prefix: "kingmoat/access"}}
	got = resolveAccessOut(own, ls)
	if got.S3.Endpoint != "minio.internal:9000" || got.S3.Bucket != "audit-bucket" {
		t.Fatal("s3 endpoint/bucket must come from the channel")
	}
	if got.S3.Prefix != "kingmoat/access" {
		t.Fatalf("s3 prefix = %q, want the section's own identity prefix", got.S3.Prefix)
	}

	// An explicit channel use_ssl overrides the scheme-derived transport.
	ssl := true
	ls.UseSSL = &ssl
	got = resolveAccessOut(own, ls)
	if !got.S3.UseSSL {
		t.Fatal("explicit channel use_ssl must win over the endpoint scheme")
	}
}

func TestResolveAccessOutSyslogOverlay(t *testing.T) {
	ls := channelBase()
	ls.Type = "syslog"
	ls.URL = "tcp://collector.internal:514"

	// The transport comes from the channel; the APP-NAME is ours (the
	// channel's "kingmoat" must not leak into the access stream, and an
	// empty app name falls back to the section index inside syslogsink).
	al := &config.AccessLogSettings{Enabled: true, UseAuditChannel: true, Index: "kingmoat_access"}
	got := resolveAccessOut(al, ls)
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
	al.Syslog = &config.SyslogSettings{AppName: "waf-access"}
	got = resolveAccessOut(al, ls)
	if got.Syslog.AppName != "waf-access" || got.Syslog.Protocol != "tcp" {
		t.Fatalf("syslog = %+v, want channel transport + section app name", got.Syslog)
	}

	// A channel without a syslog block still resolves (all-default transport)
	// instead of failing the build later.
	ls.Syslog = nil
	got = resolveAccessOut(al, ls)
	if got.Syslog == nil || got.Syslog.AppName != "waf-access" {
		t.Fatalf("channel syslog block is optional, got %+v", got.Syslog)
	}
}

func TestResolveAIShipOutOverlay(t *testing.T) {
	ship := &config.AIAuditShipSettings{
		Enabled: true, Type: "elasticsearch", URL: "http://own:9200",
		Index: "kingmoat_ai_sessions", SamplePct: 25, BatchSize: 10, FlushSec: 9,
		UseAuditChannel: true,
	}
	ls := channelBase()
	got := resolveAIShipOut(ship, ls)
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
	if got := resolveAIShipOut(nil, ls); got != nil {
		t.Fatal("nil ship section must pass through")
	}
	if got := resolveAIShipOut(ship, nil); got != ship {
		t.Fatal("no channel must pass the section through (the rebuilder warns and disables)")
	}
}

func TestResolveAIShipOutS3FallbackSeed(t *testing.T) {
	ls := channelBase()
	ls.Type = "s3"
	ls.Endpoint = "minio.internal:9000"
	ls.Bucket = "audit-bucket"

	// Deprecated flat prefix / use_ssl seed the identity when the nested s3
	// sub-structure is absent (T-1 fallback-seed convention).
	useSSL := true
	ship := &config.AIAuditShipSettings{Enabled: true, UseAuditChannel: true, Prefix: "kingmoat/ai", UseSSL: &useSSL}
	got := resolveAIShipOut(ship, ls)
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
	ship.S3 = &config.S3Settings{Prefix: "kingmoat/ai-nested"}
	got = resolveAIShipOut(ship, ls)
	if got.S3.Prefix != "kingmoat/ai-nested" {
		t.Fatalf("s3 prefix = %q, want the nested block's", got.S3.Prefix)
	}

	// Non-s3 resolved types drop the sub-structure entirely.
	ls.Type = "loki"
	ls.URL = "http://loki.internal:3100"
	got = resolveAIShipOut(ship, ls)
	if got.S3 != nil || got.Syslog != nil {
		t.Fatalf("non-s3/syslog resolved type must drop the sub-structures, got S3=%v Syslog=%v", got.S3, got.Syslog)
	}
}

// --- the 8-row channel-reuse matrix (task card 2.2), table-driven ---

// TestOutboundChannelReuseMatrix walks every matrix cell: one baseline apply
// per cell, then a single-config-dimension mutation, then the rebuild-or-skip
// verdict. Rows follow the task card matrix; R3/R4 apply to the access
// pipeline only, R5/R6 to the AI ship only.
func TestOutboundChannelReuseMatrix(t *testing.T) {
	const (
		verdictSkip    = "skip"
		verdictRebuild = "rebuild"
		verdictDisable = "disable"
	)

	// channel() returns a fresh log_shipper baseline (ES, so the AI ship can
	// build from it as-is).
	channel := func() *config.ShipperSettings {
		return &config.ShipperSettings{
			Type: "elasticsearch", URL: "http://audit.internal:9200",
			BatchSize: 50, FlushSec: 3600, Username: "audit-u", Password: "audit-p",
			Prefix: "kingmoat/audit",
		}
	}

	t.Run("access", func(t *testing.T) {
		for _, cell := range []struct {
			name   string
			use    bool
			mutate func(al *config.AccessLogSettings, ls *config.ShipperSettings)
			want   string
		}{
			{"R1 log_shipper channel change / use=false", false,
				func(_ *config.AccessLogSettings, ls *config.ShipperSettings) { ls.URL = "http://audit2.internal:9200" }, verdictSkip},
			{"R1 log_shipper channel change / use=true", true,
				func(_ *config.AccessLogSettings, ls *config.ShipperSettings) { ls.URL = "http://audit2.internal:9200" }, verdictRebuild},
			{"R1 log_shipper auth change / use=true", true,
				func(_ *config.AccessLogSettings, ls *config.ShipperSettings) { ls.Password = "new-pw" }, verdictRebuild},
			{"R1 log_shipper batching change / use=true", true,
				func(_ *config.AccessLogSettings, ls *config.ShipperSettings) { ls.BatchSize = 77 }, verdictRebuild},
			{"R2 log_shipper own fields / use=false", false,
				func(_ *config.AccessLogSettings, ls *config.ShipperSettings) {
					ls.Prefix = "other/audit"
					ls.UploadArchives = true
				}, verdictSkip},
			{"R2 log_shipper own fields / use=true", true,
				func(_ *config.AccessLogSettings, ls *config.ShipperSettings) {
					ls.Prefix = "other/audit"
					ls.UploadArchives = true
				}, verdictSkip},
			{"R3 access identity change (index) / use=false", false,
				func(al *config.AccessLogSettings, _ *config.ShipperSettings) { al.Index = "kingmoat_access2" }, verdictRebuild},
			{"R3 access identity change (index) / use=true", true,
				func(al *config.AccessLogSettings, _ *config.ShipperSettings) { al.Index = "kingmoat_access2" }, verdictRebuild},
			{"R3 access identity change (sample_pct) / use=true", true,
				func(al *config.AccessLogSettings, _ *config.ShipperSettings) { al.SamplePct = 10 }, verdictRebuild},
			{"R4 access channel change (url) / use=false", false,
				func(al *config.AccessLogSettings, _ *config.ShipperSettings) { al.URL = "http://own2:8123" }, verdictRebuild},
			{"R4 access channel change (url) / use=true", true,
				func(al *config.AccessLogSettings, _ *config.ShipperSettings) { al.URL = "http://own2:8123" }, verdictSkip},
			{"R4 access channel change (auth) / use=true", true,
				func(al *config.AccessLogSettings, _ *config.ShipperSettings) {
					al.Username = "own2"
					al.Password = "own2pw"
				}, verdictSkip},
			{"R7 switch flip on→off / use=true", true,
				func(al *config.AccessLogSettings, _ *config.ShipperSettings) {
					al.UseAuditChannel = false
					// The switch-back fields are kept by the section while the
					// switch is on (T-1 contract): flipping off re-activates them.
					al.Type, al.URL = "clickhouse", "http://own:8123"
				}, verdictRebuild},
			{"R8 log_shipper removal / use=false", false,
				func(_ *config.AccessLogSettings, _ *config.ShipperSettings) {}, verdictSkip},
			{"R8 log_shipper removal / use=true", true,
				func(_ *config.AccessLogSettings, _ *config.ShipperSettings) {}, verdictDisable},
		} {
			t.Run(cell.name, func(t *testing.T) {
				var cur atomic.Pointer[accesslog.Shipper]
				var tr sectionTracker[config.AccessLogSettings]
				ring := accesslog.NewRing(8)
				sinkCalls := 0
				setSink := func(accesslog.Sink) { sinkCalls++ }

				// The section's own channel fields are left invalid while the
				// switch is on (url empty): a resolve bug that builds from the
				// section instead of the channel fails the baseline apply.
				al := &config.AccessLogSettings{
					Enabled: true, Type: "clickhouse", URL: "http://own:8123",
					Index: "kingmoat_access", BatchSize: 10, FlushSec: 3600,
					Username: "own-u", Password: "own-p",
					UseAuditChannel: cell.use,
				}
				ls := channel()
				if cell.use {
					al.Type, al.URL = "", "" // must come from the channel
					al.Username, al.Password = "", ""
				}
				rebuildAccess(&cur, ring, setSink, &tr, al, ls, testLogger())
				first := cur.Load()
				if first == nil {
					t.Fatal("baseline apply must build the pipeline")
				}
				before := sinkCalls

				// A publish always hands the rebuilder FRESH sections (the
				// config is re-deserialized per revision); clone the baseline
				// so the mutation cannot touch the tracker snapshot.
				al2 := *al
				if al2.S3 != nil {
					s := *al2.S3
					al2.S3 = &s
				}
				if al2.Syslog != nil {
					s := *al2.Syslog
					al2.Syslog = &s
				}
				ls2 := *ls
				if ls2.Syslog != nil {
					s := *ls2.Syslog
					ls2.Syslog = &s
				}
				if ls2.UseSSL != nil {
					v := *ls2.UseSSL
					ls2.UseSSL = &v
				}
				cell.mutate(&al2, &ls2)
				mutatedLS := &ls2
				if cell.name == "R8 log_shipper removal / use=false" || cell.name == "R8 log_shipper removal / use=true" {
					mutatedLS = nil
				}
				rebuildAccess(&cur, ring, setSink, &tr, &al2, mutatedLS, testLogger())

				got := cur.Load()
				switch cell.want {
				case verdictSkip:
					if got != first {
						t.Fatal("resolved section unchanged: the rebuild must be skipped")
					}
					if sinkCalls != before {
						t.Fatalf("SetSink calls = %d, want %d (skip must not re-wire)", sinkCalls, before)
					}
				case verdictRebuild:
					if got == nil || got == first {
						t.Fatal("resolved section changed: the pipeline must rebuild")
					}
					if sinkCalls != before+1 {
						t.Fatalf("SetSink calls = %d, want %d (rebuild re-wires)", sinkCalls, before+1)
					}
				case verdictDisable:
					if got != nil {
						t.Fatal("switch on without a channel must disable the outbound (fallback WARN path)")
					}
				}
			})
		}
	})

	t.Run("ai", func(t *testing.T) {
		for _, cell := range []struct {
			name   string
			use    bool
			mutate func(ship *config.AIAuditShipSettings, ls *config.ShipperSettings)
			want   string
		}{
			{"R1 log_shipper channel change / use=false", false,
				func(_ *config.AIAuditShipSettings, ls *config.ShipperSettings) {
					ls.URL = "http://audit2.internal:9200"
				}, verdictSkip},
			{"R1 log_shipper channel change / use=true", true,
				func(_ *config.AIAuditShipSettings, ls *config.ShipperSettings) {
					ls.URL = "http://audit2.internal:9200"
				}, verdictRebuild},
			{"R1 log_shipper auth change / use=true", true,
				func(_ *config.AIAuditShipSettings, ls *config.ShipperSettings) { ls.Password = "new-pw" }, verdictRebuild},
			{"R2 log_shipper own fields / use=false", false,
				func(_ *config.AIAuditShipSettings, ls *config.ShipperSettings) {
					ls.Prefix = "other/audit"
					ls.UploadArchives = true
				}, verdictSkip},
			{"R2 log_shipper own fields / use=true", true,
				func(_ *config.AIAuditShipSettings, ls *config.ShipperSettings) {
					ls.Prefix = "other/audit"
					ls.UploadArchives = true
				}, verdictSkip},
			{"R5 ai identity change (index) / use=false", false,
				func(ship *config.AIAuditShipSettings, _ *config.ShipperSettings) { ship.Index = "kingmoat_ai_2" }, verdictRebuild},
			{"R5 ai identity change (index) / use=true", true,
				func(ship *config.AIAuditShipSettings, _ *config.ShipperSettings) { ship.Index = "kingmoat_ai_2" }, verdictRebuild},
			{"R5 ai identity change (sample_pct) / use=true", true,
				func(ship *config.AIAuditShipSettings, _ *config.ShipperSettings) { ship.SamplePct = 10 }, verdictRebuild},
			{"R6 ai channel change (url) / use=false", false,
				func(ship *config.AIAuditShipSettings, _ *config.ShipperSettings) { ship.URL = "http://own2:9200" }, verdictRebuild},
			{"R6 ai channel change (url) / use=true", true,
				func(ship *config.AIAuditShipSettings, _ *config.ShipperSettings) { ship.URL = "http://own2:9200" }, verdictSkip},
			{"R6 ai channel change (auth) / use=true", true,
				func(ship *config.AIAuditShipSettings, _ *config.ShipperSettings) {
					ship.Username = "own2"
					ship.Password = "own2pw"
				}, verdictSkip},
			{"R7 switch flip on→off / use=true", true,
				func(ship *config.AIAuditShipSettings, _ *config.ShipperSettings) {
					ship.UseAuditChannel = false
					ship.Type, ship.URL = "elasticsearch", "http://own:9200"
				}, verdictRebuild},
			{"R8 log_shipper removal / use=false", false,
				func(_ *config.AIAuditShipSettings, _ *config.ShipperSettings) {}, verdictSkip},
			{"R8 log_shipper removal / use=true", true,
				func(_ *config.AIAuditShipSettings, _ *config.ShipperSettings) {}, verdictDisable},
		} {
			t.Run(cell.name, func(t *testing.T) {
				var cur atomic.Pointer[aisession.AIOutbound]
				var tr sectionTracker[config.AIAuditShipSettings]
				var sinkCalls []string
				setSink := func(k aisession.AISink) {
					if k == nil {
						sinkCalls = append(sinkCalls, "nil")
					} else {
						sinkCalls = append(sinkCalls, "out")
					}
				}

				ship := &config.AIAuditShipSettings{
					Enabled: true, Type: "elasticsearch", URL: "http://own:9200",
					Index: "kingmoat_ai_sessions", BatchSize: 10, FlushSec: 3600, TimeoutSec: 1,
					Username: "own-u", Password: "own-p",
					UseAuditChannel: cell.use,
				}
				ls := channel()
				if cell.use {
					ship.Type, ship.URL = "", "" // must come from the channel
					ship.Username, ship.Password = "", ""
				}
				rebuildAIShip(&cur, setSink, &tr, ship, ls, testLogger())
				first := cur.Load()
				if first == nil {
					t.Fatal("baseline apply must build the shipper")
				}
				before := len(sinkCalls)

				// A publish always hands the rebuilder FRESH sections (the
				// config is re-deserialized per revision); clone the baseline
				// so the mutation cannot touch the tracker snapshot.
				ship2 := *ship
				if ship2.S3 != nil {
					s := *ship2.S3
					ship2.S3 = &s
				}
				if ship2.Syslog != nil {
					s := *ship2.Syslog
					ship2.Syslog = &s
				}
				if ship2.UseSSL != nil {
					v := *ship2.UseSSL
					ship2.UseSSL = &v
				}
				ls2 := *ls
				if ls2.Syslog != nil {
					s := *ls2.Syslog
					ls2.Syslog = &s
				}
				if ls2.UseSSL != nil {
					v := *ls2.UseSSL
					ls2.UseSSL = &v
				}
				cell.mutate(&ship2, &ls2)
				mutatedLS := &ls2
				if cell.name == "R8 log_shipper removal / use=false" || cell.name == "R8 log_shipper removal / use=true" {
					mutatedLS = nil
				}
				rebuildAIShip(&cur, setSink, &tr, &ship2, mutatedLS, testLogger())

				got := cur.Load()
				switch cell.want {
				case verdictSkip:
					if got != first {
						t.Fatal("resolved section unchanged: the rebuild must be skipped")
					}
					if len(sinkCalls) != before {
						t.Fatalf("SetSink calls = %d, want %d (skip must not re-hook)", len(sinkCalls), before)
					}
				case verdictRebuild:
					if got == nil || got == first {
						t.Fatal("resolved section changed: the shipper must rebuild")
					}
					if len(sinkCalls) != before+1 {
						t.Fatalf("SetSink calls = %d, want %d (rebuild re-hooks)", len(sinkCalls), before+1)
					}
				case verdictDisable:
					if got != nil {
						t.Fatal("switch on without a channel must disable the outbound (fallback WARN path)")
					}
				}
			})
		}
	})
}

// TestRebuildAccessChannelReuseBuildsFromChannel pins the resolve contract
// behaviorally: with the switch on and the section's own channel fields
// empty, the pipeline builds only if the channel's type/url/auth were used.
func TestRebuildAccessChannelReuseBuildsFromChannel(t *testing.T) {
	var bodies struct {
		mu sync.Mutex
		n  int
	}
	got := make(chan struct{}, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodies.mu.Lock()
		bodies.n++
		bodies.mu.Unlock()
		got <- struct{}{}
	}))
	defer ts.Close()

	var cur atomic.Pointer[accesslog.Shipper]
	var tr sectionTracker[config.AccessLogSettings]
	ring := accesslog.NewRing(8)
	setSink := func(accesslog.Sink) {}

	al := &config.AccessLogSettings{Enabled: true, UseAuditChannel: true, Index: "kingmoat_access", FlushSec: 1, TimeoutSec: 2}
	ls := &config.ShipperSettings{Type: "elasticsearch", URL: ts.URL, BatchSize: 1, FlushSec: 1, TimeoutSec: 2}

	rebuildAccess(&cur, ring, setSink, &tr, al, ls, testLogger())
	as := cur.Load()
	if as == nil {
		t.Fatal("switch-on section with valid channel must build (type/url resolved from the channel)")
	}
	// Sample identity: the entry flows through the resolved pipeline to the
	// channel's endpoint (the section had no url of its own to point at).
	as.Write(&accesslog.Entry{TS: "2026-10-12T10:00:00Z", Path: "/x", Outcome: "forwarded"})
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no push to the channel endpoint within 5s")
	}
}

// TestRebuildAIShipChannelReuseBuildsFromChannel is the AI-side twin: the
// ship builds from the channel's elasticsearch endpoint and ships the record
// there (identity index preserved).
func TestRebuildAIShipChannelReuseBuildsFromChannel(t *testing.T) {
	var bodies struct {
		mu sync.Mutex
		s  []string
	}
	got := make(chan struct{}, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies.mu.Lock()
		bodies.s = append(bodies.s, string(b))
		bodies.mu.Unlock()
		got <- struct{}{}
	}))
	defer ts.Close()

	var cur atomic.Pointer[aisession.AIOutbound]
	var tr sectionTracker[config.AIAuditShipSettings]
	sinkCalls := 0
	setSink := func(aisession.AISink) { sinkCalls++ }

	ship := &config.AIAuditShipSettings{Enabled: true, UseAuditChannel: true, Index: "kingmoat_ai_sessions", FlushSec: 1, TimeoutSec: 2}
	ls := &config.ShipperSettings{Type: "elasticsearch", URL: ts.URL, BatchSize: 1, FlushSec: 1, TimeoutSec: 2}

	rebuildAIShip(&cur, setSink, &tr, ship, ls, testLogger())
	sh := cur.Load()
	if sh == nil {
		t.Fatal("switch-on ship with valid channel must build (type/url resolved from the channel)")
	}
	(*sh).WriteAIRecord(aisession.Record{ID: "r-1", TraceID: "t-1", TS: "2026-10-12T10:00:00Z", Provider: "openai", Model: "gpt-test"})
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no push to the channel endpoint within 5s")
	}
	bodies.mu.Lock()
	defer bodies.mu.Unlock()
	line := bodies.s[len(bodies.s)-1]
	if !strings.Contains(line, `"provider":"openai"`) || !strings.Contains(line, `"model":"gpt-test"`) {
		t.Fatalf("AI record bulk body lost the AI semantics: %s", line)
	}
	if !strings.Contains(line, `"_index":"kingmoat_ai_sessions-`) {
		t.Fatalf("bulk meta must keep the section's identity index (daily-suffixed): %s", line)
	}
}

// TestRebuildAIShipBuildsAllBackendTypes: every resolved backend type builds
// through rebuildAIShip from the effective section (the old "non-ES types
// store but never ship" divergence is closed), and the disable path swaps to
// nil and unhooks the sink.
func TestRebuildAIShipBuildsAllBackendTypes(t *testing.T) {
	for _, tc := range []struct {
		name string
		ship config.AIAuditShipSettings
	}{
		{"clickhouse", config.AIAuditShipSettings{Type: "clickhouse", URL: "http://127.0.0.1:1", Index: "kingmoat_ai_sessions"}},
		{"elasticsearch", config.AIAuditShipSettings{Type: "elasticsearch", URL: "http://127.0.0.1:1", Index: "kingmoat_ai_sessions"}},
		{"loki", config.AIAuditShipSettings{Type: "loki", URL: "http://127.0.0.1:1", Index: "kingmoat_ai_sessions"}},
		{"s3", config.AIAuditShipSettings{Type: "s3", Index: "kingmoat_ai_sessions", S3: &config.S3Settings{Endpoint: "127.0.0.1:1", Bucket: "b"}}},
		{"syslog", config.AIAuditShipSettings{Type: "syslog", URL: "udp://127.0.0.1:1", Syslog: &config.SyslogSettings{}}},
		{"kafka", config.AIAuditShipSettings{Type: "kafka", Brokers: []string{"127.0.0.1:1"}, Topic: "kingmoat-test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cur atomic.Pointer[aisession.AIOutbound]
			var tr sectionTracker[config.AIAuditShipSettings]
			sinkCalls := 0
			setSink := func(aisession.AISink) { sinkCalls++ }

			ship := tc.ship
			ship.Enabled = true
			ship.FlushSec = 3600
			ship.TimeoutSec = 1
			rebuildAIShip(&cur, setSink, &tr, &ship, nil, testLogger())
			if cur.Load() == nil {
				t.Fatal("a valid backend section must build the shipper")
			}
			if sinkCalls != 1 {
				t.Fatalf("SetSink calls = %d, want 1 (rebuild hooks the sink)", sinkCalls)
			}

			// Unchanged section: skip.
			first := cur.Load()
			rebuildAIShip(&cur, setSink, &tr, &ship, nil, testLogger())
			if cur.Load() != first || sinkCalls != 1 {
				t.Fatal("unchanged section must not rebuild nor re-hook")
			}

			// Disable: swap to nil and unhook once (a fresh section value —
			// passing the same pointer would make the tracker self-compare and
			// skip).
			disabled := tc.ship
			disabled.Enabled = false
			rebuildAIShip(&cur, setSink, &tr, &disabled, nil, testLogger())
			if cur.Load() != nil || sinkCalls != 2 {
				t.Fatalf("disable: shipper=%v sinkCalls=%d, want nil/2", cur.Load(), sinkCalls)
			}
		})
	}
}

// TestRebuildOutboundFallbackWarnPaths covers the runtime fallbacks for
// shapes the publish-time cross-validation rejects (hand-edited static
// files): the switch on without a channel disables loudly, and a repeated
// publish of the same broken form stays silent. Invalid backend sections
// fail the build and keep the previous instance (TestRebuildAIShipBuildsAll-
// BackendTypes covers the six valid types).
func TestRebuildOutboundFallbackWarnPaths(t *testing.T) {
	t.Run("access switch on without channel", func(t *testing.T) {
		var cur atomic.Pointer[accesslog.Shipper]
		var tr sectionTracker[config.AccessLogSettings]
		ring := accesslog.NewRing(8)
		sinkCalls := 0
		setSink := func(accesslog.Sink) { sinkCalls++ }

		al := &config.AccessLogSettings{Enabled: true, Type: "clickhouse", URL: "http://127.0.0.1:1", FlushSec: 3600}
		rebuildAccess(&cur, ring, setSink, &tr, al, nil, testLogger())
		if cur.Load() == nil || sinkCalls != 1 {
			t.Fatalf("baseline direct build: shipper=%v sinkCalls=%d, want non-nil/1", cur.Load(), sinkCalls)
		}

		// Flip the switch on while the channel is absent: the outbound is
		// disabled and the data plane re-wires to the resident ring.
		al2 := *al
		al2.UseAuditChannel = true
		al2.Type, al2.URL = "", ""
		rebuildAccess(&cur, ring, setSink, &tr, &al2, nil, testLogger())
		if cur.Load() != nil {
			t.Fatal("switch on without a channel must disable the outbound")
		}
		if sinkCalls != 2 {
			t.Fatalf("SetSink calls = %d, want 2 (disable re-wires the resident ring)", sinkCalls)
		}

		// The tracker keeps the resolved broken form: a repeated publish of
		// the same shape stays silent (no second disable churn).
		rebuildAccess(&cur, ring, setSink, &tr, &al2, nil, testLogger())
		if sinkCalls != 2 {
			t.Fatalf("SetSink calls = %d, want 2 (same broken form must not re-disable)", sinkCalls)
		}

		// The switch off recovers the direct shape.
		al3 := al2
		al3.UseAuditChannel = false
		al3.Type, al3.URL = "clickhouse", "http://127.0.0.1:2"
		rebuildAccess(&cur, ring, setSink, &tr, &al3, nil, testLogger())
		if cur.Load() == nil {
			t.Fatal("switch-off section must build from its own fields again")
		}
		t.Cleanup(func() { _ = cur.Load().Close() })
	})

	t.Run("ai switch on without channel", func(t *testing.T) {
		var cur atomic.Pointer[aisession.AIOutbound]
		var tr sectionTracker[config.AIAuditShipSettings]
		sinkCalls := 0
		setSink := func(aisession.AISink) { sinkCalls++ }

		ship := &config.AIAuditShipSettings{Enabled: true, Type: "elasticsearch", URL: "http://own:9200", UseAuditChannel: true}
		rebuildAIShip(&cur, setSink, &tr, ship, nil, testLogger())
		if cur.Load() != nil || sinkCalls != 1 {
			t.Fatalf("fallback disable: shipper=%v sinkCalls=%d, want nil/1", cur.Load(), sinkCalls)
		}
		rebuildAIShip(&cur, setSink, &tr, ship, nil, testLogger())
		if sinkCalls != 1 {
			t.Fatalf("SetSink calls = %d, want 1 (same broken form must not re-disable)", sinkCalls)
		}
	})

	t.Run("ai invalid backend config", func(t *testing.T) {
		var cur atomic.Pointer[aisession.AIOutbound]
		var tr sectionTracker[config.AIAuditShipSettings]
		sinkCalls := 0
		setSink := func(aisession.AISink) { sinkCalls++ }

		// Baseline: a valid direct ES section builds.
		ship := &config.AIAuditShipSettings{Enabled: true, Type: "elasticsearch", URL: "http://own:9200", FlushSec: 3600, TimeoutSec: 1}
		rebuildAIShip(&cur, setSink, &tr, ship, nil, testLogger())
		baseline := cur.Load()
		if baseline == nil || sinkCalls != 1 {
			t.Fatalf("baseline ES build: shipper=%v sinkCalls=%d, want non-nil/1", cur.Load(), sinkCalls)
		}

		// An INVALID backend section fails the build and keeps the previous
		// instance (fail-static, tracker unpolluted): kafka without brokers.
		broken := &config.AIAuditShipSettings{Enabled: true, Type: "kafka", FlushSec: 3600, TimeoutSec: 1}
		rebuildAIShip(&cur, setSink, &tr, broken, nil, testLogger())
		if cur.Load() != baseline {
			t.Fatal("a failed build must keep the previous instance")
		}
		if sinkCalls != 1 {
			t.Fatalf("SetSink calls = %d, want 1 (failed build must not re-hook)", sinkCalls)
		}
		// A repeated publish of the same broken shape stays silent.
		rebuildAIShip(&cur, setSink, &tr, broken, nil, testLogger())
		if sinkCalls != 1 {
			t.Fatalf("SetSink calls = %d, want 1 (same broken form must not re-attempt)", sinkCalls)
		}

		// Every supported backend type builds (the old non-ES loud disable
		// is gone): loki over its own URL.
		loki := &config.AIAuditShipSettings{Enabled: true, Type: "loki", URL: "http://loki:3100", FlushSec: 3600, TimeoutSec: 1}
		rebuildAIShip(&cur, setSink, &tr, loki, nil, testLogger())
		if cur.Load() == nil || cur.Load() == baseline {
			t.Fatal("a valid non-ES backend must build (the non-ES disable fallback is retired)")
		}
		if sinkCalls != 2 {
			t.Fatalf("SetSink calls = %d, want 2 (rebuild re-hooks)", sinkCalls)
		}
		t.Cleanup(func() {
			if old := cur.Load(); old != nil {
				_ = (*old).Close()
			}
		})

		// Channel reuse with an invalid channel payload fails the same way:
		// kafka channel without brokers, switch on.
		var cur2 atomic.Pointer[aisession.AIOutbound]
		var tr2 sectionTracker[config.AIAuditShipSettings]
		ship2 := &config.AIAuditShipSettings{Enabled: true, UseAuditChannel: true, Index: "kingmoat_ai_sessions"}
		ls := &config.ShipperSettings{Type: "kafka"}
		rebuildAIShip(&cur2, setSink, &tr2, ship2, ls, testLogger())
		if cur2.Load() != nil {
			t.Fatal("a channel-reuse section whose resolved kafka block is invalid must not build")
		}
	})
}
