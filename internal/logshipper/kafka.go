package logshipper

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// kafkaTarget wraps a kafka.Writer: one JSON message per audit event, keyed
// by trace_id when present so retries and partitioning keep event ordering
// per request.
type kafkaTarget struct {
	writer *kafka.Writer
	// timeout bounds one pushBatch call (the outer context budget, also the
	// per-attempt WriteTimeout); derived from timeout_sec like the sibling
	// sinks, zero/negative keeps the historical 30s default.
	timeout time.Duration
}

// newKafkaTarget builds the writer from the shipper settings. TLS and SASL
// (plain / scram-sha256) are optional; the transport mirrors the in-product
// decision for upstream TLS: certificates are not verified by default so
// self-signed internal brokers work zero-config.
func newKafkaTarget(cfg config.ShipperSettings, logger *slog.Logger) (*kafkaTarget, error) {
	brokers := make([]string, 0, len(cfg.Brokers))
	for _, b := range cfg.Brokers {
		if t := strings.TrimSpace(b); t != "" {
			brokers = append(brokers, t)
		}
	}
	if len(brokers) == 0 {
		return nil, fmt.Errorf("logshipper: kafka brokers is required")
	}
	topic := strings.TrimSpace(cfg.Topic)
	if topic == "" {
		return nil, fmt.Errorf("logshipper: kafka topic is required")
	}
	// timeout_sec drives every kafka timeout the same way it drives the HTTP
	// sinks (durationSec): zero/negative keeps the historical defaults (dial
	// 5s, produce/write 30s). The dial budget mirrors syslogsink, the write
	// budget the previous hardcoded value; the same duration also bounds the
	// whole pushBatch call in pushBatch so the two can no longer stack up to
	// ~60s on the single batcher goroutine.
	timeout := durationSec(cfg.TimeoutSec, 30)
	tr := &kafka.Transport{DialTimeout: durationSec(cfg.TimeoutSec, 5)}
	if cfg.UseTLS {
		// tls_skip_verify absent keeps the legacy zero-config behavior for
		// internal self-signed brokers (certificates not verified); an
		// explicit false turns broker-certificate verification on.
		skip := true
		if cfg.TLSSkipVerify != nil {
			skip = *cfg.TLSSkipVerify
		}
		if skip && cfg.TLSSkipVerify == nil && logger != nil {
			logger.Warn("logshipper kafka: TLS certificate verification is disabled (use_tls is on and tls_skip_verify is not explicitly set); set tls_skip_verify=false to verify broker certificates")
		}
		tr.TLS = &tls.Config{InsecureSkipVerify: skip}
	}
	mech, err := kafkaSASLMechanism(cfg)
	if err != nil {
		return nil, err
	}
	tr.SASL = mech
	w := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireOne,
		BatchSize:    256,
		BatchTimeout: 50 * time.Millisecond,
		WriteTimeout: timeout,
		Transport:    tr,
	}
	return &kafkaTarget{writer: w, timeout: timeout}, nil
}

func kafkaSASLMechanism(cfg config.ShipperSettings) (sasl.Mechanism, error) {
	switch cfg.SASL {
	case "", "none":
		return nil, nil
	case "plain":
		return plain.Mechanism{Username: cfg.Username, Password: cfg.Password}, nil
	case "scram-sha256":
		return scram.Mechanism(scram.SHA256, cfg.Username, cfg.Password)
	default:
		return nil, fmt.Errorf("logshipper: kafka sasl %q not supported", cfg.SASL)
	}
}

// pushBatch ships one batch of audit events as JSON messages under the push
// timeout derived from timeout_sec. A transport error is returned to the
// push layer, which logs a WARN and moves on; it deliberately does NOT bump
// dropped, whose semantics everywhere in this package (and in accesslog) are
// strictly queue-backpressure drops — push failures are counted the same way
// for every sink (warn only, the s3 sink included), so a kafka-only counter
// would break that symmetry.
func (t *kafkaTarget) pushBatch(batch []logstore.Event) error {
	msgs := make([]kafka.Message, 0, len(batch))
	for i := range batch {
		b, err := json.Marshal(batch[i])
		if err != nil {
			continue
		}
		m := kafka.Message{Value: b}
		if batch[i].TraceID != "" {
			m.Key = []byte(batch[i].TraceID)
		}
		msgs = append(msgs, m)
	}
	if len(msgs) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
	defer cancel()
	return t.writer.WriteMessages(ctx, msgs...)
}

func (t *kafkaTarget) close() error { return t.writer.Close() }
