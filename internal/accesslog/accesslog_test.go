package accesslog

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestRingMasksStoredEntries pins R3-01: the in-memory live tail enforces the
// same storage-time privacy policy as the local SQLite sink — a plaintext
// token in the tail next to a masked store would leak what the store hides.
func TestRingMasksStoredEntries(t *testing.T) {
	r := NewRing(4)
	r.Write(&Entry{Site: "t.local", Path: "/download/0123456789abcdef0123456789abcdef01234567/file", Query: "token=abc123&page=2", UserAgent: "ua"})
	got := r.Recent(10, "", "", "")
	if len(got) != 1 {
		t.Fatalf("recent entries = %d, want 1", len(got))
	}
	e := got[0]
	if e.Query != "token=***&page=2" {
		t.Errorf("ring query = %q, want masked token=***&page=2", e.Query)
	}
	if strings.Contains(e.Path, "0123456789abcdef0123456789abcdef01234567") {
		t.Errorf("ring path = %q, want credential-shaped segment masked", e.Path)
	}
}

// TestRingAndStoreMaskingAgree pins the R3-01 consistency contract: the
// live tail (Ring) and the durable local store (SQLiteSink) apply the SAME
// storage-time privacy treatment — one entry recorded through both surfaces
// yields identical path/query/UA text, so the console never shows what the
// store masks (and vice versa).
func TestRingAndStoreMaskingAgree(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "access-logs.db")
	s, err := newSQLiteSink(dbPath, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 64, true, sinkLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	e := &Entry{
		Site:      "t.local",
		Path:      "/download/0123456789abcdef0123456789abcdef01234567/file",
		Query:     "token=abc123&page=2",
		UserAgent: strings.Repeat("ua-", 400),
	}
	r := NewRing(4)
	r.Write(e)
	s.Write(e)
	if err := s.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}

	ring := r.Recent(1, "", "", "")
	if len(ring) != 1 {
		t.Fatalf("ring entries = %d, want 1", len(ring))
	}
	page, err := s.History(HistoryQuery{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("store rows = %d, want 1", len(page.Items))
	}
	stored := page.Items[0]
	if ring[0].Query != stored.Query {
		t.Fatalf("query mismatch: ring %q vs store %q", ring[0].Query, stored.Query)
	}
	if ring[0].Path != stored.Path {
		t.Fatalf("path mismatch: ring %q vs store %q", ring[0].Path, stored.Path)
	}
	if ring[0].UserAgent != stored.UserAgent {
		t.Fatalf("user agent mismatch: ring %d bytes vs store %d bytes", len(ring[0].UserAgent), len(stored.UserAgent))
	}
	// And both surfaces must actually be masked (not merely equal-raw).
	if ring[0].Query == "token=abc123&page=2" || strings.Contains(ring[0].Path, "0123456789abcdef") {
		t.Fatalf("both surfaces must be masked: ring query %q path %q", ring[0].Query, ring[0].Path)
	}
}

func TestShipperClickHouseJSONEachRow(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var paths []string
	got := make(chan struct{}, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		paths = append(paths, r.URL.Query().Get("query"))
		mu.Unlock()
		got <- struct{}{}
	}))
	defer ts.Close()

	sh, err := New(config.AccessLogSettings{
		Enabled: true, Type: "clickhouse", URL: ts.URL, Index: "kingmoat_access",
		BatchSize: 2, FlushSec: 1, TimeoutSec: 2,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	for i := 0; i < 3; i++ {
		sh.Write(&Entry{
			TS: time.Now().UTC().Format(time.RFC3339Nano), Site: "t.local",
			Method: "GET", Path: "/a", Status: 200, Outcome: "forwarded",
		})
	}

	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no push within 5s")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("no payload delivered")
	}
	if !strings.Contains(paths[0], "INSERT INTO kingmoat_access FORMAT JSONEachRow") {
		t.Fatalf("bad CH query: %q", paths[0])
	}
	lines := strings.Split(strings.TrimSpace(bodies[0]), "\n")
	if len(lines) < 1 {
		t.Fatal("empty JSONEachRow body")
	}
	var e Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("row is not JSON: %v", err)
	}
	if e.Outcome != "forwarded" {
		t.Fatalf("row content mismatch: %+v", e)
	}
}

func TestSampling(t *testing.T) {
	sh, err := New(config.AccessLogSettings{
		Enabled: true, Type: "loki", URL: "http://127.0.0.1:1", Index: "x",
		SamplePct: 0, // invalid → treated as 100%
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	if sh.samplePct != 100 {
		t.Fatalf("sample pct = %d, want 100", sh.samplePct)
	}
}

func TestRecorderCapturesStatusAndBytes(t *testing.T) {
	rec := NewRecorder(httptest.NewRecorder())
	rec.WriteHeader(http.StatusForbidden)
	rec.Write([]byte("blocked-by-kingmoat"))
	if rec.Status() != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Status())
	}
	if rec.BytesWritten() != len("blocked-by-kingmoat") {
		t.Fatalf("bytes = %d", rec.BytesWritten())
	}
}

func TestRecorderHijackUnsupported(t *testing.T) {
	rec := NewRecorder(httptest.NewRecorder())
	if _, _, err := rec.Hijack(); err == nil {
		t.Fatal("plain recorder must not support hijack")
	}
}

func TestShipperRejectsUnknownType(t *testing.T) {
	// kafka became a supported type (accesslog kafka sink); a genuinely
	// unknown type must still be rejected.
	if _, err := New(config.AccessLogSettings{Enabled: true, Type: "redis", URL: "http://x"}, nil); err == nil {
		t.Fatal("unknown type must be rejected")
	}
}

// startSyslogListener accepts one TCP syslog connection and signals both the
// accept and the peer close (EOF), so the test can watch the shipper's
// underlying connection from the collector side.
func startSyslogListener(t *testing.T) (addr string, accepts, closes chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepts = make(chan struct{}, 8)
	closes = make(chan struct{}, 8)
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
	})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case accepts <- struct{}{}:
		case <-done:
			return
		}
		buf := make([]byte, 1024)
		for {
			if _, err := conn.Read(buf); err != nil {
				break
			}
		}
		_ = conn.Close()
		select {
		case closes <- struct{}{}:
		case <-done:
		}
	}()
	return ln.Addr().String(), accepts, closes
}

// TestSyslogShipperCloseReleasesConnection covers the C-2 fix at shipper
// level: a type=syslog access-log shipper dials its target lazily, Close
// flushes, stops the batcher and THEN releases the syslog connection (the
// collector observes EOF), and a repeated Close is a safe no-op.
func TestSyslogShipperCloseReleasesConnection(t *testing.T) {
	addr, accepts, closes := startSyslogListener(t)

	sh, err := New(config.AccessLogSettings{
		Enabled: true, Type: "syslog", URL: "tcp://" + addr,
		BatchSize: 1, FlushSec: 1, TimeoutSec: 2,
		Syslog: &config.SyslogSettings{},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sh.Write(&Entry{TS: time.Now().UTC().Format(time.RFC3339Nano), Path: "/x", Outcome: "forwarded"})
	select {
	case <-accepts:
	case <-time.After(5 * time.Second):
		t.Fatal("collector saw no connection (batcher did not ship the entry)")
	}

	if err := sh.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := sh.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	select {
	case <-closes:
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not observe the connection release (EOF) after Shipper.Close")
	}
}
