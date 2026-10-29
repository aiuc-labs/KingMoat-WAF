package accesslog

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestKafkaSinkValidation mirrors the config-layer kafka rules at the sink:
// brokers and topic are required (blank-only broker entries count as absent)
// and an unsupported SASL mechanism is rejected.
func TestKafkaSinkValidation(t *testing.T) {
	if _, err := newKafkaSink(config.AccessLogSettings{Type: "kafka", Topic: "t"}, nil); err == nil {
		t.Fatal("no brokers must be rejected")
	}
	if _, err := newKafkaSink(config.AccessLogSettings{Type: "kafka", Brokers: []string{"b:9092"}}, nil); err == nil {
		t.Fatal("no topic must be rejected")
	}
	if _, err := newKafkaSink(config.AccessLogSettings{Type: "kafka", Brokers: []string{"  "}, Topic: "t"}, nil); err == nil {
		t.Fatal("blank-only brokers must be rejected")
	}
	if _, err := newKafkaSink(config.AccessLogSettings{Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t", SASL: "md5"}, nil); err == nil {
		t.Fatal("unsupported sasl must be rejected")
	}
}

// warnCounter is a minimal slog handler counting warn-or-higher records so
// the tests can assert on the implicit TLS skip-verify warning without
// matching log text.
type warnCounter struct {
	n int
}

func (h *warnCounter) Enabled(context.Context, slog.Level) bool { return true }

func (h *warnCounter) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		h.n++
	}
	return nil
}

func (h *warnCounter) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *warnCounter) WithGroup(string) slog.Handler { return h }

// TestKafkaTimeoutsFromConfig pins the timeout_sec derivation: zero/negative
// keeps the historical defaults (dial 5s, write/push 30s), a positive value
// drives the dial budget, the per-attempt WriteTimeout and the pushBatch
// context budget alike.
func TestKafkaTimeoutsFromConfig(t *testing.T) {
	base := config.AccessLogSettings{Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t"}
	sink, err := newKafkaSink(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := sink.writer.Transport.(*kafka.Transport)
	if sink.timeout != 30*time.Second || sink.writer.WriteTimeout != 30*time.Second || tr.DialTimeout != 5*time.Second {
		t.Fatalf("defaults: dial/write/push = %v/%v/%v, want 5s/30s/30s", tr.DialTimeout, sink.writer.WriteTimeout, sink.timeout)
	}
	cfg := base
	cfg.TimeoutSec = 10
	sink, err = newKafkaSink(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr = sink.writer.Transport.(*kafka.Transport)
	if sink.timeout != 10*time.Second || sink.writer.WriteTimeout != 10*time.Second || tr.DialTimeout != 10*time.Second {
		t.Fatalf("timeout_sec=10: dial/write/push = %v/%v/%v, want 10s/10s/10s", tr.DialTimeout, sink.writer.WriteTimeout, sink.timeout)
	}
}

// TestKafkaTLSWarnOnImplicitSkipVerify pins the operator-facing warning: it
// fires only when use_tls is on AND tls_skip_verify is absent (the implicit
// legacy skip), never for an explicit true/false and never for plaintext.
func TestKafkaTLSWarnOnImplicitSkipVerify(t *testing.T) {
	skipTrue, skipFalse := true, false
	tcs := []struct {
		name     string
		cfg      config.AccessLogSettings
		wantWarn int
	}{
		{"implicit skip warns", config.AccessLogSettings{Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t", UseTLS: true}, 1},
		{"explicit true stays silent", config.AccessLogSettings{Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t", UseTLS: true, TLSSkipVerify: &skipTrue}, 0},
		{"explicit false stays silent", config.AccessLogSettings{Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t", UseTLS: true, TLSSkipVerify: &skipFalse}, 0},
		{"plaintext stays silent", config.AccessLogSettings{Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t"}, 0},
	}
	for _, tc := range tcs {
		h := &warnCounter{}
		if _, err := newKafkaSink(tc.cfg, slog.New(h)); err != nil {
			t.Fatalf("%s: newKafkaSink: %v", tc.name, err)
		}
		if h.n != tc.wantWarn {
			t.Fatalf("%s: warn count = %d, want %d", tc.name, h.n, tc.wantWarn)
		}
	}
}

// TestKafkaTransportKnobs pins the TLS / SASL transport wiring: use_tls with
// an absent tls_skip_verify keeps the legacy zero-config skip, an explicit
// false turns broker-certificate verification on, plaintext carries no TLS
// config, and sasl=plain attaches the shared Username / Password.
func TestKafkaTransportKnobs(t *testing.T) {
	skipFalse := false
	tcs := []struct {
		name     string
		cfg      config.AccessLogSettings
		wantTLS  bool
		wantSkip bool
	}{
		{"tls default skip", config.AccessLogSettings{Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t", UseTLS: true}, true, true},
		{"tls explicit verify", config.AccessLogSettings{Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t", UseTLS: true, TLSSkipVerify: &skipFalse}, true, false},
		{"plaintext", config.AccessLogSettings{Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t"}, false, false},
	}
	for _, tc := range tcs {
		sink, err := newKafkaSink(tc.cfg, nil)
		if err != nil {
			t.Fatalf("%s: newKafkaSink: %v", tc.name, err)
		}
		tr, ok := sink.writer.Transport.(*kafka.Transport)
		if !ok {
			t.Fatalf("%s: transport is not *kafka.Transport", tc.name)
		}
		if (tr.TLS != nil) != tc.wantTLS {
			t.Fatalf("%s: TLS config presence = %v, want %v", tc.name, tr.TLS != nil, tc.wantTLS)
		}
		if tc.wantTLS && tr.TLS.InsecureSkipVerify != tc.wantSkip {
			t.Fatalf("%s: InsecureSkipVerify = %v, want %v", tc.name, tr.TLS.InsecureSkipVerify, tc.wantSkip)
		}
	}

	sink, err := newKafkaSink(config.AccessLogSettings{
		Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t",
		SASL: "plain", Username: "u", Password: "p",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := sink.writer.Transport.(*kafka.Transport)
	if pm, ok := tr.SASL.(plain.Mechanism); !ok || pm.Username != "u" || pm.Password != "p" {
		t.Fatalf("sasl plain mechanism not wired: %#v", tr.SASL)
	}
}

// TestKafkaMessagesAssembly: the payload is the pre-encoded JSON line and
// the partition key is the record key (trace id) when present.
func TestKafkaMessagesAssembly(t *testing.T) {
	msgs := kafkaMessages([]doc{
		{ts: "t1", line: []byte(`{"a":1}`)},
		{ts: "t2", line: []byte(`{"b":2}`), key: "trace-2"},
	})
	if len(msgs) != 2 {
		t.Fatalf("msgs = %d, want 2", len(msgs))
	}
	if string(msgs[0].Value) != `{"a":1}` || msgs[0].Key != nil {
		t.Fatalf("msg 0 = key %v value %q", msgs[0].Key, msgs[0].Value)
	}
	if string(msgs[1].Key) != "trace-2" || string(msgs[1].Value) != `{"b":2}` {
		t.Fatalf("msg 1 = key %v value %q", msgs[1].Key, msgs[1].Value)
	}
}

// TestKafkaPushBatchEmptyIsNoOp: an empty batch must not touch the writer.
func TestKafkaPushBatchEmptyIsNoOp(t *testing.T) {
	s := &kafkaSink{writer: &kafka.Writer{}}
	if err := s.pushBatch(nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
}

// TestKafkaPushBatchDialFailure covers the connection-failure path offline:
// a broker list pointing at a closed port fails the push (the shipper layer
// warns and keeps counting instead of stalling the hot path).
func TestKafkaPushBatchDialFailure(t *testing.T) {
	w := &kafka.Writer{
		Addr:         kafka.TCP("127.0.0.1:1"),
		Topic:        "kingmoat-test",
		BatchTimeout: 10 * time.Millisecond,
		WriteTimeout: 2 * time.Second,
		Transport:    &kafka.Transport{DialTimeout: 500 * time.Millisecond},
	}
	defer w.Close()
	s := &kafkaSink{writer: w}
	err := s.pushBatch([]doc{{ts: time.Now().UTC().Format(time.RFC3339Nano), line: []byte(`{"a":1}`)}})
	if err == nil {
		t.Fatal("push to a closed broker port must fail")
	}
}

// TestKafkaShipperLifecycle: a kafka-configured generic shipper constructs
// without dialing (lazy connection) and Close is idempotent.
func TestKafkaShipperLifecycle(t *testing.T) {
	sh, err := NewGeneric[Entry](config.AccessLogSettings{
		Enabled: true, Type: "kafka",
		Brokers: []string{"127.0.0.1:1"}, Topic: "kingmoat-test",
		BatchSize: 2, FlushSec: 1, TimeoutSec: 2,
	}, streamAccess, entryDoc, nil)
	if err != nil {
		t.Fatalf("NewGeneric kafka: %v", err)
	}
	if sh.kafka == nil || sh.kafka.writer == nil {
		t.Fatal("kafka sink not built")
	}
	if sh.kafka.writer.Topic != "kingmoat-test" {
		t.Fatalf("writer topic = %q", sh.kafka.writer.Topic)
	}
	if err := sh.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := sh.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
