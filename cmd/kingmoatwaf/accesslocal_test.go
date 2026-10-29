package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/accesslog"
	"github.com/kingmoat/kingmoat/internal/config"
)

// newTestLocalSink builds a local recorder sink for rebuild tests; batch=1
// commits immediately so no flush waits are needed.
func newTestLocalSink(t *testing.T, cfg config.AccessLogRecordSettings) *accesslog.SQLiteSink {
	t.Helper()
	s, err := accesslog.NewSQLiteSink(filepath.Join(t.TempDir(), "access-logs.db"), cfg, testLogger())
	if err != nil {
		t.Fatalf("NewSQLiteSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestRebuildLocalAccessLifecycle covers enable → unchanged-skip → mode
// change → disable: only actual section changes swap/close/re-wire.
func TestRebuildLocalAccessLifecycle(t *testing.T) {
	var cur atomic.Pointer[accesslog.SQLiteSink]
	var tr sectionTracker[config.AccessLogRecordSettings]
	dbPath := filepath.Join(t.TempDir(), "access-logs.db")
	t.Cleanup(func() {
		if s := cur.Load(); s != nil {
			_ = s.Close()
		}
	})
	var sinks []accesslog.Sink
	setSink := func(s accesslog.Sink) { sinks = append(sinks, s) }

	// Boot starts disabled (nil section, tracker unseeded): a publish
	// enabling mode=all builds the store and recomposes the chain.
	rec := &config.AccessLogRecordSettings{Mode: "all", BatchSize: 64}
	rebuildLocalAccess(&cur, setSink, &tr, rec, dbPath, testLogger(), nil)
	first := cur.Load()
	if first == nil {
		t.Fatal("mode=all publish must build the local store")
	}
	if len(sinks) != 1 {
		t.Fatalf("SetSink calls after enable = %d, want 1", len(sinks))
	}
	if !tr.unchanged(rec) {
		t.Fatal("tracker must be seeded with the applied section (a repeat publish must skip the rebuild)")
	}

	// Unchanged section (same value, fresh pointer — what every unrelated
	// publish looks like): no swap, no close, no SetSink churn.
	rebuildLocalAccess(&cur, setSink, &tr, &config.AccessLogRecordSettings{Mode: "all", BatchSize: 64}, dbPath, testLogger(), nil)
	if cur.Load() != first {
		t.Fatal("unchanged section must NOT rebuild the local store")
	}
	if len(sinks) != 1 {
		t.Fatalf("unchanged publish must not re-wire the sink, got %d SetSink calls", len(sinks)-1)
	}

	// Mode change all → sites: new instance, filter applied.
	recSites := &config.AccessLogRecordSettings{Mode: "sites", Sites: []string{"a.local"}, BatchSize: 64}
	rebuildLocalAccess(&cur, setSink, &tr, recSites, dbPath, testLogger(), nil)
	second := cur.Load()
	if second == nil || second == first {
		t.Fatal("mode change must swap in a new local store instance")
	}
	if len(sinks) != 2 {
		t.Fatalf("SetSink calls after mode change = %d, want 2", len(sinks))
	}
	second.Write(&accesslog.Entry{Site: "b.local", Path: "/filtered"})
	if err := second.Flush(2 * time.Second); err != nil {
		t.Fatalf("flush: %v", err)
	}
	page, err := second.History(accesslog.HistoryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 {
		t.Fatalf("sites-mode store recorded a non-listed site: %d rows", page.Total)
	}
	second.Write(&accesslog.Entry{Site: "a.local", Path: "/kept"})
	if err := second.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	if page, err = second.History(accesslog.HistoryQuery{}); err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 {
		t.Fatalf("listed site must be recorded, got %d rows", page.Total)
	}

	// Disable (nil section): store detached and closed, chain recomposed.
	rebuildLocalAccess(&cur, setSink, &tr, nil, dbPath, testLogger(), nil)
	if cur.Load() != nil {
		t.Fatal("nil section must detach the local store")
	}
	if len(sinks) != 3 {
		t.Fatalf("SetSink calls after disable = %d, want 3", len(sinks))
	}
	// mode=off behaves like a removed section.
	rebuildLocalAccess(&cur, setSink, &tr, &config.AccessLogRecordSettings{Mode: "off"}, dbPath, testLogger(), nil)
	if cur.Load() != nil {
		t.Fatal("mode=off must keep the store detached")
	}
	if len(sinks) != 3 {
		t.Fatal("disable of a detached store must not re-wire the sink")
	}
}

// TestRebuildLocalAccessBuildFailureKeepsPrevious: a store that cannot be
// opened (db path parented by an existing FILE) keeps the previous instance
// and never touches the data-plane sink.
func TestRebuildLocalAccessBuildFailureKeepsPrevious(t *testing.T) {
	var cur atomic.Pointer[accesslog.SQLiteSink]
	var tr sectionTracker[config.AccessLogRecordSettings]
	dbPath := filepath.Join(t.TempDir(), "access-logs.db")
	t.Cleanup(func() {
		if s := cur.Load(); s != nil {
			_ = s.Close()
		}
	})
	var sinkCalls int
	setSink := func(accesslog.Sink) { sinkCalls++ }

	good := &config.AccessLogRecordSettings{Mode: "all", BatchSize: 64}
	rebuildLocalAccess(&cur, setSink, &tr, good, dbPath, testLogger(), nil)
	keep := cur.Load()
	if keep == nil {
		t.Fatal("enable must build the store")
	}
	if sinkCalls != 1 {
		t.Fatalf("SetSink calls after enable = %d, want 1", sinkCalls)
	}

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(blocker, "nested", "access-logs.db")
	bad := &config.AccessLogRecordSettings{Mode: "all", MaxDiskMB: 4096}
	rebuildLocalAccess(&cur, setSink, &tr, bad, badPath, testLogger(), nil)
	if cur.Load() != keep {
		t.Fatal("failed rebuild must keep the previous store instance")
	}
	if sinkCalls != 1 {
		t.Fatalf("SetSink called %d times after failed rebuild, want 0", sinkCalls-1)
	}
}

// TestComposeAccessSinkChainShape: the chain is ring → local → shipper, all
// members receive entries, and — the PM-flagged pitfall — closing the
// composed Tee only closes its SECOND member (the shipper): the local store
// is never closed by a nested Tee and must keep working after the chain is
// torn down.
func TestComposeAccessSinkChainShape(t *testing.T) {
	ring := accesslog.NewRing(8)
	local := newTestLocalSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1})
	ship := newTestAccessShipper(t, "http://127.0.0.1:1")

	// ring-only composition (recording off, shipping off).
	if _, isRing := composeAccessSink(ring, nil, nil).(*accesslog.Ring); !isRing {
		t.Fatal("ring-only chain must be the bare ring (live tail keeps working)")
	}

	// full chain: every member receives the entry.
	chain := composeAccessSink(ring, local, ship)
	tee, ok := chain.(*accesslog.Tee)
	if !ok {
		t.Fatalf("full chain = %T, want *accesslog.Tee", chain)
	}
	chain.Write(&accesslog.Entry{Site: "a.local", Path: "/chain", Outcome: "forwarded"})
	if ring.Count() != 1 {
		t.Fatalf("ring count = %d, want 1", ring.Count())
	}
	if err := local.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	page, err := local.History(accesslog.HistoryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 {
		t.Fatalf("local rows = %d, want 1", page.Total)
	}

	// Close the chain exactly like an accidental whole-chain teardown would:
	// the outer Tee closes its second (the shipper) only — the nested
	// Tee(ring, local) is the outer FIRST and is never closed.
	_ = tee.Close()
	ship.Write(&accesslog.Entry{Site: "a.local", Path: "/after-close"}) // closed: silent no-op
	local.Write(&accesslog.Entry{Site: "a.local", Path: "/still-alive"})
	if err := local.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	page, err = local.History(accesslog.HistoryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 {
		t.Fatalf("local store must survive the chain Tee close, rows = %d, want 2", page.Total)
	}
}

// TestRebuildLocalAccessFailureReportsLoadNote: a failed rebuild keeps the
// previous instance AND reports the degradation through noteFn (the config
// center's load_notes — the console degradation banner); the success path
// appends nothing (publish clear-notes semantics stay in charge).
func TestRebuildLocalAccessFailureReportsLoadNote(t *testing.T) {
	var cur atomic.Pointer[accesslog.SQLiteSink]
	var tr sectionTracker[config.AccessLogRecordSettings]
	dbPath := filepath.Join(t.TempDir(), "access-logs.db")
	t.Cleanup(func() {
		if s := cur.Load(); s != nil {
			_ = s.Close()
		}
	})
	setSink := func(accesslog.Sink) {}
	var notes []string
	noteFn := func(reason string) { notes = append(notes, reason) }

	// Successful enable: no note (publish success stays honest).
	good := &config.AccessLogRecordSettings{Mode: "all", BatchSize: 64}
	rebuildLocalAccess(&cur, setSink, &tr, good, dbPath, testLogger(), noteFn)
	keep := cur.Load()
	if keep == nil {
		t.Fatal("enable must build the store")
	}
	if len(notes) != 0 {
		t.Fatalf("success path must not append a note, got %v", notes)
	}

	// Forced rebuild failure (db path parented by an existing FILE): the
	// previous instance stays and exactly one actionable note lands.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(blocker, "nested", "access-logs.db")
	bad := &config.AccessLogRecordSettings{Mode: "all", MaxDiskMB: 4096}
	rebuildLocalAccess(&cur, setSink, &tr, bad, badPath, testLogger(), noteFn)
	if cur.Load() != keep {
		t.Fatal("failed rebuild must keep the previous store instance")
	}
	if len(notes) != 1 {
		t.Fatalf("failed rebuild must append exactly one note, got %v", notes)
	}
	for _, want := range []string{"访问日志本地记录应用失败", "已保持上一配置", "audit_log_dir", "重新发布", "服务端日志"} {
		if !strings.Contains(notes[0], want) {
			t.Fatalf("note must carry %q, got %q", want, notes[0])
		}
	}
	// RC-4: the banner must stay generic — the full error (which carries the
	// database path) belongs to the server log only.
	if strings.Contains(notes[0], badPath) || strings.Contains(notes[0], "blocker") {
		t.Fatalf("note must not carry the database path (RC-4): %q", notes[0])
	}

	// The kept instance still records (recording was never interrupted).
	keep.Write(&accesslog.Entry{Site: "a.local", Path: "/still-recording"})
	if err := keep.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	page, err := keep.History(accesslog.HistoryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 {
		t.Fatalf("kept store must still record, rows = %d, want 1", page.Total)
	}
}
