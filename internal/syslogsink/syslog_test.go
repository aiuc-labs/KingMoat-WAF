package syslogsink

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

func testSettings(url string, sys *config.SyslogSettings) config.ShipperSettings {
	return config.ShipperSettings{Type: "syslog", URL: url, Index: "kingmoat", Syslog: sys}
}

func TestFormatMessageRFC5424(t *testing.T) {
	c, err := newClient(&config.SyslogSettings{
		Hostname: "waf-node-01",
		AppName:  "kingmoat",
	}, "tcp://syslog.example.com:514", "kingmoat", "kingmoat", time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	ts := time.Date(2026, 9, 16, 9, 30, 5, 123456000, time.FixedZone("CST", 8*3600))
	got := c.formatMessage(ts, "blocked", `{"action":"blocked"}`, 4)
	// PRI = 16*8+4 = 132
	want := "<132>1 2026-09-16T09:30:05.123456+08:00 waf-node-01 kingmoat - blocked - {\"action\":\"blocked\"}"
	if got != want {
		t.Fatalf("rfc5424 mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestFormatMessageRFC3164(t *testing.T) {
	c, err := newClient(&config.SyslogSettings{
		Format:   "rfc3164",
		Hostname: "waf-node-01",
		AppName:  "kingmoat",
	}, "udp://127.0.0.1:5140", "kingmoat", "kingmoat", time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	// rfc3164 renders the timestamp in the local zone (RFC 3164 has no zone
	// field), so pin time.Local: CI runners are UTC and would otherwise
	// render 01:30:05 instead of 09:30:05.
	savedLocal := time.Local
	time.Local = time.FixedZone("CST", 8*3600)
	t.Cleanup(func() { time.Local = savedLocal })
	ts := time.Date(2026, 9, 7, 9, 30, 5, 0, time.FixedZone("CST", 8*3600))
	got := c.formatMessage(ts, "blocked", "hello world", 0)
	// PRI = 16*8+6 = 134 (default severity 6); day is space-padded.
	if !strings.HasPrefix(got, "<134>Sep  7 09:30:05 waf-node-01 kingmoat: hello world") {
		t.Fatalf("rfc3164 mismatch: %s", got)
	}
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name   string
		url    string
		sys    *config.SyslogSettings
		wantOK bool
	}{
		{"missing url", "  ", nil, false},
		{"missing syslog settings", "udp://127.0.0.1:514", nil, false},
		{"bad protocol", "ws://127.0.0.1:514", &config.SyslogSettings{}, false},
		{"protocol override bad", "udp://127.0.0.1:514", &config.SyslogSettings{Protocol: "sctp"}, false},
		{"bad format", "udp://127.0.0.1:514", &config.SyslogSettings{Format: "json"}, false},
		{"bad framing", "tcp://127.0.0.1:514", &config.SyslogSettings{Framing: "raw"}, false},
		{"facility range", "udp://127.0.0.1:514", &config.SyslogSettings{Facility: 24}, false},
		{"severity range", "udp://127.0.0.1:514", &config.SyslogSettings{Severity: 8}, false},
		{"bare host ok", "10.0.0.8", &config.SyslogSettings{}, true},
		{"tls ok", "tls://collector:6514", &config.SyslogSettings{}, true},
	}
	for _, tc := range cases {
		_, err := newClient(tc.sys, tc.url, "kingmoat", "kingmoat", time.Second)
		if tc.wantOK && err != nil {
			t.Errorf("%s: expected ok, got error %v", tc.name, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}

func TestSendUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	c, err := New(testSettings("udp://"+pc.LocalAddr().String(), &config.SyslogSettings{
		Hostname: "waf-node-01",
	}), "kingmoat")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	msg := `{"action":"blocked","rule":"coraza/rule-949110"}`
	if err := c.Send(time.Now(), "blocked", msg, 4); err != nil {
		t.Fatalf("Send: %v", err)
	}

	buf := make([]byte, 4096)
	if err := pc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "<132>1 ") {
		t.Fatalf("PRI/version prefix missing: %s", got)
	}
	if !strings.HasSuffix(got, msg) {
		t.Fatalf("message body missing: %s", got)
	}
	if !strings.Contains(got, " kingmoat ") {
		t.Fatalf("APP-NAME missing: %s", got)
	}
}

func TestSendTCPNewline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()

	type received struct {
		line string
	}
	ch := make(chan received, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		sc := bufio.NewScanner(conn)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			ch <- received{line: sc.Text()}
		}
	}()

	c, err := New(testSettings("tcp://"+ln.Addr().String(), &config.SyslogSettings{
		Framing:  "newline",
		Hostname: "waf-node-01",
	}), "kingmoat")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	first := `{"action":"monitor"}`
	second := `{"action":"blocked"}`
	if err := c.Send(time.Now(), "monitor", first, 0); err != nil {
		t.Fatalf("Send 1: %v", err)
	}
	if err := c.Send(time.Now(), "blocked", second, 4); err != nil {
		t.Fatalf("Send 2: %v", err)
	}

	for i, want := range []string{first, second} {
		select {
		case r := <-ch:
			if !strings.HasSuffix(r.line, want) {
				t.Fatalf("frame %d mismatch: %s", i, r.line)
			}
			if !strings.HasPrefix(r.line, "<") {
				t.Fatalf("frame %d missing PRI: %s", i, r.line)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("frame %d not received", i)
		}
	}
}

func TestSendTCPOctetFraming(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()

	ch := make(chan string, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read the octet-counted frame: "<digits> " prefix then N bytes.
		buf := make([]byte, 1)
		var digits []byte
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
			if buf[0] == ' ' {
				break
			}
			digits = append(digits, buf[0])
		}
		n := 0
		for _, d := range digits {
			n = n*10 + int(d-'0')
		}
		body := make([]byte, n)
		if _, err := readFull(conn, body); err != nil {
			return
		}
		ch <- string(body)
	}()

	c, err := New(testSettings("tcp://"+ln.Addr().String(), &config.SyslogSettings{
		Hostname: "waf-node-01",
	}), "kingmoat")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Send(time.Now(), "blocked", "payload-with spaces", 4); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case got := <-ch:
		if !strings.HasSuffix(got, "payload-with spaces") {
			t.Fatalf("frame mismatch: %s", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("frame not received")
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// --- C-2: connection lifecycle (exported Close) ---

// tcpCollector is a minimal syslog stand-in: it accepts TCP connections,
// signals every accept, and signals every peer close (EOF observed while
// reading), so tests can watch the client connection lifetime from the
// collector side.
type tcpCollector struct {
	addr    string
	accepts chan struct{}
	closes  chan struct{}

	mu    sync.Mutex
	nConn int
}

func startCollector(t *testing.T) *tcpCollector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c := &tcpCollector{addr: ln.Addr().String(), accepts: make(chan struct{}, 8), closes: make(chan struct{}, 8)}
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.nConn++
			c.mu.Unlock()
			select {
			case c.accepts <- struct{}{}:
			default:
			}
			go func() {
				buf := make([]byte, 1024)
				for {
					if _, err := conn.Read(buf); err != nil {
						break
					}
				}
				_ = conn.Close()
				select {
				case c.closes <- struct{}{}:
				case <-done:
				}
			}()
		}
	}()
	return c
}

func (c *tcpCollector) connections() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nConn
}

// TestCloseIdempotentReleasesConnection covers the connection-leak fix: a TCP
// client dials lazily on the first Send, Close releases the connection (the
// collector observes EOF), a repeated Close is a no-op, and a Send after
// Close fails fast without dialing a new connection.
func TestCloseIdempotentReleasesConnection(t *testing.T) {
	coll := startCollector(t)
	client, err := New(testSettings("tcp://"+coll.addr, &config.SyslogSettings{}), "kingmoat_test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := client.Send(time.Now(), "test", "hello", 0); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case <-coll.accepts:
	case <-time.After(5 * time.Second):
		t.Fatal("collector saw no connection")
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-coll.closes:
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not observe the connection release (EOF)")
	}

	client.Close() // idempotent: must not panic or double-close

	if err := client.Send(time.Now(), "test", "after close", 0); err == nil {
		t.Fatal("Send after Close succeeded, want fast-fail error")
	}
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if n := coll.connections(); n != 1 {
			t.Fatalf("collector connections = %d, want 1 (closed client must not re-dial)", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestCloseConcurrentWithSend covers the send-on-closed hazard: Close racing
// in-flight Sends must never panic — the closed flag and the connection live
// under the same mutex, so each Send either observes the close or completes
// against the live connection.
func TestCloseConcurrentWithSend(t *testing.T) {
	coll := startCollector(t)
	client, err := New(testSettings("tcp://"+coll.addr, &config.SyslogSettings{}), "kingmoat_test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = client.Send(time.Now(), "test", "msg", 0) // nil or error, never a panic
		}
	}()
	go func() {
		defer wg.Done()
		time.Sleep(time.Millisecond)
		_ = client.Close()
		_ = client.Close()
	}()
	wg.Wait()
}
