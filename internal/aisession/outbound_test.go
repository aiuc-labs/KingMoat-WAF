package aisession

// Offline tests for the generic multi-backend outbound (Shipper over
// accesslog.GenericShipper[Record]): ES / ClickHouse / Loki against httptest
// endpoints (asserting the daily index and the FULL record JSON — the AI
// semantics must never flatten), syslog against a local UDP/TCP receiver,
// and the kafka paths that can be verified without a broker (validation,
// lazy construction, dial-failure resilience). The kafka partition-key
// plumbing (doc.key → Message.Key) is pinned in accesslog's kafka tests.

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// aiTestRecord is a fully-populated AI record: every field the ES document
// shape promise covers (provider/model/usage/stream/trace_id/duration...).
func aiTestRecord() Record {
	return Record{
		ID: "r-1", TS: "2026-03-04T23:59:59Z", TraceID: "t-abc", Site: "s.local",
		ClientIP: "10.0.0.8", NodeID: "n-1", Method: "POST", Path: "/v1/chat",
		URL: "https://api.local/v1/chat", Status: 200, UserAgent: "ua",
		DurationMS: 421, Provider: "openai", Operation: "chat", Model: "gpt-test",
		Stream: true,
		Request: RequestPayload{
			System: "sys", Messages: json.RawMessage(`[{"role":"user","content":"hi"}]`),
		},
		Response:   ResponsePayload{Text: "hello"},
		Usage:      &Usage{PromptTokens: 11, CompletionTokens: 7, TotalTokens: 18},
		ReqBytes:   128, RespBytes: 64,
		Interrupted: false, Err: "",
	}
}

func aiTestLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newTestShipper builds an ES-configured shipper against the test endpoint.
func newTestShipper(t *testing.T, cfg config.AccessLogSettings) *Shipper {
	t.Helper()
	cfg.Enabled = true
	cfg.BatchSize, cfg.FlushSec, cfg.TimeoutSec = 2, 1, 2
	sh, err := NewShipper(cfg, aiTestLogger())
	if err != nil {
		t.Fatalf("NewShipper: %v", err)
	}
	t.Cleanup(func() { _ = sh.Close() })
	return sh
}

// waitPayload waits for the next pushed body (5s deadline).
func waitPayload(t *testing.T, mu *sync.Mutex, bodies *[]string, got chan struct{}) string {
	t.Helper()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no push within 5s")
	}
	mu.Lock()
	defer mu.Unlock()
	return (*bodies)[len(*bodies)-1]
}

// TestShipperESBulkKeepsFullRecord: the ES backend ships the FULL record JSON
// as the bulk document (byte-identical to json.Marshal(Record) — the AI
// semantics are intact, never flattened) and routes the daily index by the
// record's own timestamp (two records spanning midnight land on their own
// days).
func TestShipperESBulkKeepsFullRecord(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	got := make(chan struct{}, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_bulk" {
			t.Errorf("path = %q, want /_bulk", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		got <- struct{}{}
	}))
	defer ts.Close()

	sh := newTestShipper(t, config.AccessLogSettings{Type: "elasticsearch", URL: ts.URL, Index: "kingmoat_ai_sessions"})

	r1 := aiTestRecord()
	sh.WriteAIRecord(r1)
	body := waitPayload(t, &mu, &bodies, got)

	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 2 {
		t.Fatalf("bulk line count = %d, want 2 (meta+doc)", len(lines))
	}
	if !strings.Contains(lines[0], `"_index":"kingmoat_ai_sessions-2026.03.04"`) {
		t.Fatalf("meta line = %q, want the record-ts daily index", lines[0])
	}
	want, _ := json.Marshal(r1)
	if lines[1] != string(want) {
		t.Fatalf("doc lost the full AI record:\n got %s\nwant %s", lines[1], want)
	}

	// A record on the next day routes to its own index.
	r2 := aiTestRecord()
	r2.ID, r2.TS = "r-2", "2026-03-05T00:00:01Z"
	sh.WriteAIRecord(r2)
	body = waitPayload(t, &mu, &bodies, got)
	lines = strings.Split(strings.TrimSpace(body), "\n")
	if !strings.Contains(lines[0], `"_index":"kingmoat_ai_sessions-2026.03.05"`) {
		t.Fatalf("meta line = %q, want the 2026.03.05 index", lines[0])
	}
	want2, _ := json.Marshal(r2)
	if lines[1] != string(want2) {
		t.Fatalf("doc lost the full AI record:\n got %s\nwant %s", lines[1], want2)
	}
}

// TestShipperClickHouseJSONEachRow: the ClickHouse backend inserts the full
// record JSON as JSONEachRow rows into the section's table.
func TestShipperClickHouseJSONEachRow(t *testing.T) {
	var mu sync.Mutex
	var bodies, queries []string
	got := make(chan struct{}, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		queries = append(queries, r.URL.Query().Get("query"))
		mu.Unlock()
		got <- struct{}{}
	}))
	defer ts.Close()

	sh := newTestShipper(t, config.AccessLogSettings{Type: "clickhouse", URL: ts.URL, Index: "kingmoat_ai_sessions"})

	r1 := aiTestRecord()
	sh.WriteAIRecord(r1)
	body := waitPayload(t, &mu, &bodies, got)

	mu.Lock()
	q := queries[0]
	mu.Unlock()
	if !strings.Contains(q, "INSERT INTO kingmoat_ai_sessions FORMAT JSONEachRow") {
		t.Fatalf("query = %q, want the section table insert", q)
	}
	line := strings.Split(strings.TrimSpace(body), "\n")[0]
	want, _ := json.Marshal(r1)
	if line != string(want) {
		t.Fatalf("row lost the full AI record:\n got %s\nwant %s", line, want)
	}
}

// TestShipperLokiPush: the Loki backend pushes under the ai job label with
// the section index as app, and the value carries the full record JSON.
func TestShipperLokiPush(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	got := make(chan struct{}, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/loki/api/v1/push" {
			t.Errorf("path = %q, want /loki/api/v1/push", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		got <- struct{}{}
	}))
	defer ts.Close()

	sh := newTestShipper(t, config.AccessLogSettings{Type: "loki", URL: ts.URL, Index: "kingmoat_ai"})

	r1 := aiTestRecord()
	sh.WriteAIRecord(r1)
	body := waitPayload(t, &mu, &bodies, got)

	var payload struct {
		Streams []struct {
			Stream map[string]string `json:"stream"`
			Values [][]string        `json:"values"`
		} `json:"streams"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("loki payload is not JSON: %v", err)
	}
	if len(payload.Streams) != 1 {
		t.Fatalf("streams = %d, want 1", len(payload.Streams))
	}
	if payload.Streams[0].Stream["job"] != "kingmoat-ai" {
		t.Fatalf("job label = %q, want kingmoat-ai", payload.Streams[0].Stream["job"])
	}
	if payload.Streams[0].Stream["app"] != "kingmoat_ai" {
		t.Fatalf("app label = %q, want the section index", payload.Streams[0].Stream["app"])
	}
	if len(payload.Streams[0].Values) != 1 {
		t.Fatalf("values = %d, want 1", len(payload.Streams[0].Values))
	}
	want, _ := json.Marshal(r1)
	if payload.Streams[0].Values[0][1] != string(want) {
		t.Fatalf("loki value lost the full AI record:\n got %s\nwant %s", payload.Streams[0].Values[0][1], want)
	}
}

// stripOctetFraming removes the RFC6587 octet-count prefix from a TCP frame.
func stripOctetFraming(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 && allDigitsASCII(s[:i]) {
		return s[i+1:]
	}
	return s
}

func allDigitsASCII(s string) bool {
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

// parseRFC5424 splits a frame into app, msgid and msg. The frame shape is
// `<PRI>1 TS HOST APP - MSGID - MSG` (PROCID literal "-", SD "-").
func parseRFC5424(t *testing.T, frame string) (app, msgid, msg string) {
	t.Helper()
	if !strings.HasPrefix(frame, "<") {
		t.Fatalf("not an RFC5424 frame: %q", frame)
	}
	parts := strings.SplitN(frame, " ", 7)
	if len(parts) < 7 {
		t.Fatalf("short RFC5424 frame: %q", frame)
	}
	if parts[4] != "-" || parts[6] == "" || !strings.HasPrefix(parts[6], "- ") {
		t.Fatalf("unexpected RFC5424 field layout: %q", frame)
	}
	return parts[3], parts[5], parts[6][2:]
}

// TestShipperSyslogUDP: the UDP transport delivers one datagram per record;
// the APP-NAME is the section index (empty index → the per-stream constant),
// the MSGID is the AI event kind and the message body the full record JSON.
func TestShipperSyslogUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	sh := newTestShipper(t, config.AccessLogSettings{Type: "syslog", URL: "udp://" + pc.LocalAddr().String(), Index: "", Syslog: &config.SyslogSettings{}})

	r1 := aiTestRecord()
	sh.WriteAIRecord(r1)
	buf := make([]byte, 65536)
	if err := pc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no syslog datagram: %v", err)
	}
	app, msgid, msg := parseRFC5424(t, string(buf[:n]))
	if app != "kingmoat_ai_sessions" {
		t.Fatalf("APP-NAME = %q, want the ai stream constant", app)
	}
	if msgid != "completed" {
		t.Fatalf("MSGID = %q, want completed", msgid)
	}
	want, _ := json.Marshal(r1)
	if msg != string(want) {
		t.Fatalf("syslog body lost the full AI record:\n got %s\nwant %s", msg, want)
	}

	// Error and interrupted records carry their own MSGID.
	for _, tc := range []struct {
		rec  Record
		want string
	}{
		{func() Record { r := aiTestRecord(); r.ID, r.Err = "r-e", "boom"; return r }(), "error"},
		{func() Record { r := aiTestRecord(); r.ID, r.Interrupted = "r-i", true; return r }(), "interrupted"},
	} {
		sh.WriteAIRecord(tc.rec)
		n, _, err = pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("no syslog datagram: %v", err)
		}
		_, msgid, _ = parseRFC5424(t, string(buf[:n]))
		if msgid != tc.want {
			t.Fatalf("MSGID = %q, want %q", msgid, tc.want)
		}
	}
}

// TestShipperSyslogTCP: the TCP transport (octet-counted RFC6587 framing)
// delivers the same APP-NAME / MSGID / full-JSON body over a stream
// connection.
func TestShipperSyslogTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()
	frames := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 65536)
		n, _ := conn.Read(buf)
		frames <- string(buf[:n])
	}()

	sh := newTestShipper(t, config.AccessLogSettings{Type: "syslog", URL: "tcp://" + ln.Addr().String(), Index: "my_ai_index", Syslog: &config.SyslogSettings{}})

	r1 := aiTestRecord()
	sh.WriteAIRecord(r1)
	select {
	case raw := <-frames:
		app, msgid, msg := parseRFC5424(t, stripOctetFraming(raw))
		if app != "my_ai_index" {
			t.Fatalf("APP-NAME = %q, want the section index", app)
		}
		if msgid != "completed" {
			t.Fatalf("MSGID = %q, want completed", msgid)
		}
		want, _ := json.Marshal(r1)
		if msg != string(want) {
			t.Fatalf("syslog body lost the full AI record:\n got %s\nwant %s", msg, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no syslog frame within 5s")
	}
}

// TestShipperKafkaValidation: misconfigured kafka sections fail at
// construction (never silently stall on the first push).
func TestShipperKafkaValidation(t *testing.T) {
	if _, err := NewShipper(config.AccessLogSettings{Type: "kafka", Topic: "t"}, aiTestLogger()); err == nil {
		t.Fatal("no brokers must be rejected")
	}
	if _, err := NewShipper(config.AccessLogSettings{Type: "kafka", Brokers: []string{"b:9092"}}, aiTestLogger()); err == nil {
		t.Fatal("no topic must be rejected")
	}
	if _, err := NewShipper(config.AccessLogSettings{Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t", SASL: "md5"}, aiTestLogger()); err == nil {
		t.Fatal("unsupported sasl must be rejected")
	}
}

// TestShipperKafkaDialFailurePath: the kafka transport connects lazily, a
// push against an unreachable broker fails inside the batcher (warn + keep
// counting, the hot path never blocks) and Close stays idempotent.
func TestShipperKafkaDialFailurePath(t *testing.T) {
	sh, err := NewShipper(config.AccessLogSettings{
		Type: "kafka", Brokers: []string{"127.0.0.1:1"}, Topic: "kingmoat-test",
	}, aiTestLogger())
	if err != nil {
		t.Fatalf("lazy construction must succeed: %v", err)
	}
	sh.WriteAIRecord(aiTestRecord())
	// give the 50ms batch timeout a moment, then close (the failed push must
	// not wedged the shutdown)
	time.Sleep(200 * time.Millisecond)
	if err := sh.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := sh.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// Write after Close is a safe no-op.
	sh.WriteAIRecord(aiTestRecord())
}

// TestShipSettingsConversion: the AI-ship section maps field-for-field onto
// the access-log settings; the deprecated flat s3 prefix / use_ssl seed the
// nested block only when it is absent.
func TestShipSettingsConversion(t *testing.T) {
	useSSL := true
	in := config.AIAuditShipSettings{
		Enabled: true, UseAuditChannel: true, Type: "elasticsearch",
		URL: "http://es:9200", Index: "kingmoat_ai_sessions", SamplePct: 30,
		BatchSize: 11, FlushSec: 4, TimeoutSec: 6,
		Username: "u", Password: "p",
		Brokers: []string{"b1:9092", "b2:9092"}, Topic: "topic", UseTLS: true, SASL: "plain",
		TLSSkipVerify: &useSSL,
	}
	out := ShipSettings(in)
	if out.Enabled != true || out.UseAuditChannel != true || out.Type != "elasticsearch" ||
		out.URL != "http://es:9200" || out.Index != "kingmoat_ai_sessions" ||
		out.SamplePct != 30 || out.BatchSize != 11 || out.FlushSec != 4 || out.TimeoutSec != 6 ||
		out.Username != "u" || out.Password != "p" || out.Topic != "topic" ||
		out.UseTLS != true || out.SASL != "plain" || out.TLSSkipVerify != &useSSL {
		t.Fatalf("conversion lost fields: %+v", out)
	}
	if len(out.Brokers) != 2 || out.Brokers[0] != "b1:9092" {
		t.Fatalf("brokers = %v", out.Brokers)
	}
	// The brokers slice is a copy, not an alias.
	in.Brokers[0] = "changed:9092"
	if out.Brokers[0] != "b1:9092" {
		t.Fatal("converted brokers must be a copy")
	}

	// The deprecated flat s3 fields seed the nested block when it is absent.
	flat := ShipSettings(config.AIAuditShipSettings{Type: "s3", Prefix: "kingmoat/ai", UseSSL: &useSSL})
	if flat.S3 == nil || flat.S3.Prefix != "kingmoat/ai" || !flat.S3.UseSSL {
		t.Fatalf("flat s3 seed = %+v, want nested prefix/use_ssl", flat.S3)
	}

	// A nested s3 block wins and the flat fields are ignored.
	nested := ShipSettings(config.AIAuditShipSettings{
		Type: "s3", Prefix: "flat", UseSSL: &useSSL,
		S3: &config.S3Settings{Endpoint: "e:9000", Bucket: "b", Prefix: "nested"},
	})
	if nested.S3.Prefix != "nested" || nested.S3.Endpoint != "e:9000" {
		t.Fatalf("nested s3 = %+v, want the nested block", nested.S3)
	}

	// Non-s3 types never grow an s3 block.
	if got := ShipSettings(config.AIAuditShipSettings{Type: "loki", Prefix: "flat"}).S3; got != nil {
		t.Fatalf("non-s3 s3 block = %v, want nil", got)
	}
}

// TestShipperImplementsAISink compiles the contract: the generic shipper is
// an AISink (CentralStore fan-out) and an AIOutbound (rebuildAIShip slot).
func TestShipperImplementsAISink(t *testing.T) {
	var _ AISink = (*Shipper)(nil)
}
