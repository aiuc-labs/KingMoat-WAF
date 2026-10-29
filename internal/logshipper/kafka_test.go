package logshipper

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"

	"github.com/kingmoat/kingmoat/internal/config"
)

func boolPtr(b bool) *bool { return &b }

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
	base := config.ShipperSettings{Type: "kafka", Brokers: []string{"broker-1.internal:9092"}, Topic: "kingmoat-audit"}
	tgt, err := newKafkaTarget(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := tgt.writer.Transport.(*kafka.Transport)
	if tgt.timeout != 30*time.Second || tgt.writer.WriteTimeout != 30*time.Second || tr.DialTimeout != 5*time.Second {
		t.Fatalf("defaults: dial/write/push = %v/%v/%v, want 5s/30s/30s", tr.DialTimeout, tgt.writer.WriteTimeout, tgt.timeout)
	}
	cfg := base
	cfg.TimeoutSec = 10
	tgt, err = newKafkaTarget(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr = tgt.writer.Transport.(*kafka.Transport)
	if tgt.timeout != 10*time.Second || tgt.writer.WriteTimeout != 10*time.Second || tr.DialTimeout != 10*time.Second {
		t.Fatalf("timeout_sec=10: dial/write/push = %v/%v/%v, want 10s/10s/10s", tr.DialTimeout, tgt.writer.WriteTimeout, tgt.timeout)
	}
}

// TestKafkaTLSWarnOnImplicitSkipVerify pins the operator-facing warning: it
// fires only when use_tls is on AND tls_skip_verify is absent (the implicit
// legacy skip), never for an explicit true/false and never for plaintext.
func TestKafkaTLSWarnOnImplicitSkipVerify(t *testing.T) {
	base := config.ShipperSettings{
		Type:    "kafka",
		Brokers: []string{"broker-1.internal:9092"},
		Topic:   "kingmoat-audit",
	}
	tcs := []struct {
		name     string
		skip     *bool
		useTLS   bool
		wantWarn int
	}{
		{"implicit skip warns", nil, true, 1},
		{"explicit true stays silent", boolPtr(true), true, 0},
		{"explicit false stays silent", boolPtr(false), true, 0},
		{"plaintext stays silent", nil, false, 0},
	}
	for _, tc := range tcs {
		cfg := base
		cfg.UseTLS = tc.useTLS
		cfg.TLSSkipVerify = tc.skip
		h := &warnCounter{}
		if _, err := newKafkaTarget(cfg, slog.New(h)); err != nil {
			t.Fatalf("%s: newKafkaTarget: %v", tc.name, err)
		}
		if h.n != tc.wantWarn {
			t.Fatalf("%s: warn count = %d, want %d", tc.name, h.n, tc.wantWarn)
		}
	}
}

// TestKafkaTLSSkipVerifyKnob pins the broker-certificate verification knob:
// absent tls_skip_verify keeps the legacy zero-config behavior (internal
// self-signed brokers, certificates NOT verified); an explicit false turns
// chain verification on.
func TestKafkaTLSSkipVerifyKnob(t *testing.T) {
	base := config.ShipperSettings{
		Type:    "kafka",
		Brokers: []string{"broker-1.internal:9092"},
		Topic:   "kingmoat-audit",
		UseTLS:  true,
	}
	cases := []struct {
		name string
		skip *bool
		want bool
	}{
		{"absent keeps legacy skip-verify", nil, true},
		{"explicit true skips verification", boolPtr(true), true},
		{"explicit false verifies broker chain", boolPtr(false), false},
	}
	for _, tc := range cases {
		cfg := base
		cfg.TLSSkipVerify = tc.skip
		tgt, err := newKafkaTarget(cfg, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		tr, ok := tgt.writer.Transport.(*kafka.Transport)
		if !ok || tr.TLS == nil {
			t.Fatalf("%s: kafka transport/TLS config missing", tc.name)
		}
		if tr.TLS.InsecureSkipVerify != tc.want {
			t.Fatalf("%s: InsecureSkipVerify = %v, want %v", tc.name, tr.TLS.InsecureSkipVerify, tc.want)
		}
	}
}

// TestKafkaPlaintextIgnoresVerifyKnob: without use_tls no TLS config is
// built at all, regardless of the knob.
func TestKafkaPlaintextIgnoresVerifyKnob(t *testing.T) {
	cfg := config.ShipperSettings{
		Type:          "kafka",
		Brokers:       []string{"broker-1.internal:9092"},
		Topic:         "kingmoat-audit",
		TLSSkipVerify: boolPtr(false),
	}
	tgt, err := newKafkaTarget(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tr, ok := tgt.writer.Transport.(*kafka.Transport); ok && tr.TLS != nil {
		t.Fatal("plaintext kafka transport must not carry a TLS config")
	}
}
