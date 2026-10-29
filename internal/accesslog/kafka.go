package accesslog

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"

	"github.com/kingmoat/kingmoat/internal/config"
)

// kafkaSink wraps a kafka.Writer: one JSON message per pre-encoded document,
// keyed by the record key (e.g. the trace id) when present so retries and
// partitioning keep event ordering per request. The transport mirrors the
// audit outbound (internal/logshipper): TLS and SASL (plain / scram-sha256)
// are optional, and when use_tls is on broker certificates are not verified
// unless tls_skip_verify is explicitly false, so self-signed internal
// brokers work zero-config.
type kafkaSink struct {
	writer *kafka.Writer
	// timeout bounds one pushBatch call (the outer context budget, also the
	// per-attempt WriteTimeout); derived from timeout_sec like the sibling
	// sinks, zero/negative keeps the historical 30s default.
	timeout time.Duration
}

// newKafkaSink builds the writer from the access-log settings. SASL
// credentials are shared with the HTTP sinks (Username / Password); brokers
// and topic are validated here so a misconfigured pipeline fails at
// construction instead of silently stalling on the first push.
func newKafkaSink(cfg config.AccessLogSettings, logger *slog.Logger) (*kafkaSink, error) {
	brokers := make([]string, 0, len(cfg.Brokers))
	for _, b := range cfg.Brokers {
		if t := strings.TrimSpace(b); t != "" {
			brokers = append(brokers, t)
		}
	}
	if len(brokers) == 0 {
		return nil, fmt.Errorf("accesslog: kafka brokers is required")
	}
	topic := strings.TrimSpace(cfg.Topic)
	if topic == "" {
		return nil, fmt.Errorf("accesslog: kafka topic is required")
	}
	mech, err := kafkaSASLMechanism(cfg.SASL, cfg.Username, cfg.Password)
	if err != nil {
		return nil, err
	}
	// timeout_sec drives every kafka timeout the same way it drives the HTTP
	// sinks (durationSec): zero/negative keeps the historical defaults (dial
	// 5s, produce/write 30s). The dial budget mirrors syslogsink, the write
	// budget the previous hardcoded value; the same duration also bounds the
	// whole pushBatch call in pushBatch so the two can no longer stack up to
	// ~60s on the single batcher goroutine.
	timeout := durationSec(cfg.TimeoutSec, 30)
	tr := &kafka.Transport{DialTimeout: durationSec(cfg.TimeoutSec, 5), SASL: mech}
	if cfg.UseTLS {
		// tls_skip_verify absent keeps the legacy zero-config behavior for
		// internal self-signed brokers (certificates not verified); an
		// explicit false turns broker-certificate verification on.
		skip := true
		if cfg.TLSSkipVerify != nil {
			skip = *cfg.TLSSkipVerify
		}
		if skip && cfg.TLSSkipVerify == nil && logger != nil {
			logger.Warn("accesslog kafka: TLS certificate verification is disabled (use_tls is on and tls_skip_verify is not explicitly set); set tls_skip_verify=false to verify broker certificates")
		}
		tr.TLS = &tls.Config{InsecureSkipVerify: skip} //nolint:gosec // opt-in via tls_skip_verify
	}
	return &kafkaSink{writer: &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireOne,
		BatchSize:    256,
		BatchTimeout: 50 * time.Millisecond,
		WriteTimeout: timeout,
		Transport:    tr,
	}, timeout: timeout}, nil
}

func kafkaSASLMechanism(mech, username, password string) (sasl.Mechanism, error) {
	switch mech {
	case "", "none":
		return nil, nil
	case "plain":
		return plain.Mechanism{Username: username, Password: password}, nil
	case "scram-sha256":
		return scram.Mechanism(scram.SHA256, username, password)
	default:
		return nil, fmt.Errorf("accesslog: kafka sasl %q not supported", mech)
	}
}

// kafkaMessages assembles one produce message per pre-encoded document: the
// payload is the encoded JSON line, the partition key the record key
// (trace id) when present.
func kafkaMessages(batch []doc) []kafka.Message {
	msgs := make([]kafka.Message, 0, len(batch))
	for i := range batch {
		m := kafka.Message{Value: batch[i].line}
		if batch[i].key != "" {
			m.Key = []byte(batch[i].key)
		}
		msgs = append(msgs, m)
	}
	return msgs
}

// pushBatch ships one batch as JSON messages under the push timeout derived
// from timeout_sec. A transport error is returned to the push layer, which
// logs a WARN and moves on; it deliberately does NOT bump dropped, whose
// semantics everywhere in this package (and in logshipper) are strictly
// queue-backpressure drops — push failures are counted the same way for
// every sink (warn only), so a kafka-only counter would break that symmetry.
func (t *kafkaSink) pushBatch(batch []doc) error {
	msgs := kafkaMessages(batch)
	if len(msgs) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
	defer cancel()
	return t.writer.WriteMessages(ctx, msgs...)
}

func (t *kafkaSink) close() error { return t.writer.Close() }
