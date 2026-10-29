package accesslog

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// testRecord stands in for a foreign record family (e.g. the AI-session
// Record): a different shape than Entry, encoded by its own toDoc.
type testRecord struct {
	TS      string `json:"ts"`
	TraceID string `json:"trace_id,omitempty"`
	Model   string `json:"model,omitempty"`
	Tokens  int    `json:"tokens,omitempty"`
}

func testRecordDoc(r *testRecord) doc {
	b, _ := json.Marshal(r)
	return doc{ts: r.TS, line: b, kind: r.Model, key: r.TraceID}
}

// TestGenericShipperESBulkKeepsRecordDocs: a generic shipper over a foreign
// record type pushes the encoder's exact JSON as the bulk document and
// routes the daily index by the record's own timestamp (two records spanning
// midnight land on their own days, not on today).
func TestGenericShipperESBulkKeepsRecordDocs(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	got := make(chan struct{}, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		got <- struct{}{}
	}))
	defer ts.Close()

	sh, err := NewGeneric[testRecord](config.AccessLogSettings{
		Enabled: true, Type: "elasticsearch", URL: ts.URL, Index: "kingmoat_ai_sessions",
		BatchSize: 2, FlushSec: 1, TimeoutSec: 2,
	}, streamAI, testRecordDoc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	r1 := &testRecord{TS: "2026-03-04T23:59:59Z", TraceID: "t-1", Model: "m1", Tokens: 11}
	r2 := &testRecord{TS: "2026-03-05T00:00:01Z", TraceID: "t-2", Model: "m1", Tokens: 22}
	sh.Write(r1)
	sh.Write(r2)

	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no push within 5s")
	}
	mu.Lock()
	defer mu.Unlock()
	lines := strings.Split(strings.TrimSpace(bodies[0]), "\n")
	if len(lines) != 4 {
		t.Fatalf("bulk line count = %d, want 4 (meta+doc per record)", len(lines))
	}
	// per-record daily routing keyed by the record ts (a now-based day would
	// collapse both records onto today's index)
	if !strings.Contains(lines[0], `"_index":"kingmoat_ai_sessions-2026.03.04"`) {
		t.Fatalf("meta line 0 = %q, want the 2026.03.04 index", lines[0])
	}
	if !strings.Contains(lines[2], `"_index":"kingmoat_ai_sessions-2026.03.05"`) {
		t.Fatalf("meta line 2 = %q, want the 2026.03.05 index", lines[2])
	}
	// documents keep the full record payload (ES doc shape = json.Marshal(record))
	for i, r := range []*testRecord{r1, r2} {
		want, _ := json.Marshal(r)
		if lines[2*i+1] != string(want) {
			t.Fatalf("doc line %d = %q, want %q", 2*i+1, lines[2*i+1], want)
		}
	}
}

// TestStreamIdentityLabels pins the per-stream sink labels: the s3 object
// kind segment, the loki job label and the default index / syslog APP-NAME
// constants stay distinct per stream.
func TestStreamIdentityLabels(t *testing.T) {
	for _, tc := range []struct {
		stream  string
		s3Kind  string
		lokiJob string
		index   string
		sysApp  string
	}{
		{streamAccess, "access", "kingmoat-access", "kingmoat_access", "kingmoat_access"},
		{streamAI, "ai", "kingmoat-ai", "kingmoat_ai_sessions", "kingmoat_ai_sessions"},
	} {
		s3Kind, lokiJob, index, sysApp, ok := streamIdentity(tc.stream)
		if !ok || s3Kind != tc.s3Kind || lokiJob != tc.lokiJob || index != tc.index || sysApp != tc.sysApp {
			t.Fatalf("streamIdentity(%q) = %q/%q/%q/%q/%v", tc.stream, s3Kind, lokiJob, index, sysApp, ok)
		}
	}
	if _, _, _, _, ok := streamIdentity("weird"); ok {
		t.Fatal("unknown stream must not resolve")
	}
}

// TestDefaultIndexByStream: an empty index keeps the historical access
// default; the AI stream defaults to its own index constant.
func TestDefaultIndexByStream(t *testing.T) {
	sh, err := NewGeneric[Entry](config.AccessLogSettings{
		Enabled: true, Type: "loki", URL: "http://127.0.0.1:1",
	}, streamAccess, entryDoc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sh.index != "kingmoat_access" {
		t.Fatalf("access default index = %q, want kingmoat_access", sh.index)
	}
	if err := sh.Close(); err != nil {
		t.Fatal(err)
	}

	ai, err := NewGeneric[testRecord](config.AccessLogSettings{
		Enabled: true, Type: "loki", URL: "http://127.0.0.1:1",
	}, streamAI, testRecordDoc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ai.index != "kingmoat_ai_sessions" {
		t.Fatalf("ai default index = %q, want kingmoat_ai_sessions", ai.index)
	}
	if err := ai.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestLokiJobLabelByStream: the loki job label comes from the stream kind,
// the app label from the section index.
func TestLokiJobLabelByStream(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	got := make(chan struct{}, 2)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		got <- struct{}{}
	}))
	defer ts.Close()

	sh, err := NewGeneric[testRecord](config.AccessLogSettings{
		Enabled: true, Type: "loki", URL: ts.URL, Index: "myindex",
		BatchSize: 1, FlushSec: 1, TimeoutSec: 2,
	}, streamAI, testRecordDoc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	sh.Write(&testRecord{TS: time.Now().UTC().Format(time.RFC3339Nano), Model: "m"})
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no push within 5s")
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(bodies[0], `"job":"kingmoat-ai"`) {
		t.Fatalf("loki payload missing ai job label: %s", bodies[0])
	}
	if !strings.Contains(bodies[0], `"app":"myindex"`) {
		t.Fatalf("loki payload missing section index as app: %s", bodies[0])
	}
}

// TestSyslogDefaultAppByStream: with no syslog.app_name and no index, the
// APP-NAME falls back to the per-stream constant (AI stream here).
func TestSyslogDefaultAppByStream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	frames := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		frames <- string(buf[:n])
	}()

	sh, err := NewGeneric[Entry](config.AccessLogSettings{
		Enabled: true, Type: "syslog", URL: "tcp://" + ln.Addr().String(),
		BatchSize: 1, FlushSec: 1, TimeoutSec: 2,
		Syslog: &config.SyslogSettings{},
	}, streamAI, entryDoc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	sh.Write(&Entry{TS: time.Now().UTC().Format(time.RFC3339Nano), Path: "/x", Outcome: "forwarded"})
	select {
	case raw := <-frames:
		s := raw
		// strip the RFC6587 octet-count prefix, then read the RFC5424
		// APP-NAME (5th whitespace field: PRI+VER TS HOST APP ...)
		if i := strings.IndexByte(s, ' '); i > 0 && allDigits(s[:i]) {
			s = s[i+1:]
		}
		f := strings.SplitN(s, " ", 5)
		if len(f) < 4 {
			t.Fatalf("short syslog frame: %q", raw)
		}
		if f[3] != "kingmoat_ai_sessions" {
			t.Fatalf("syslog APP-NAME = %q, want kingmoat_ai_sessions (frame %q)", f[3], raw)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no syslog frame within 5s")
	}
}

// TestShipperAliasSatisfiesSink compiles the compatibility contract: the
// historical *Shipper alias (*GenericShipper[Entry]) still implements Sink,
// so existing call sites (Tee wiring, SetAccessSink) keep working unchanged.
func TestShipperAliasSatisfiesSink(t *testing.T) {
	var _ Sink = (*Shipper)(nil)
}

// TestTeeDroppedWithGenericShipper: the ring Tee's *Shipper type assertions
// (Dropped/Depth proxies) keep working against the alias.
func TestTeeDroppedWithGenericShipper(t *testing.T) {
	sh, err := New(config.AccessLogSettings{
		Enabled: true, Type: "loki", URL: "http://127.0.0.1:1",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	tee := NewTee(NewRing(4), sh)
	if tee.Dropped() != 0 {
		t.Fatalf("Dropped = %d, want 0", tee.Dropped())
	}
	if tee.Depth() != 0 {
		t.Fatalf("Depth = %d, want 0", tee.Depth())
	}
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
