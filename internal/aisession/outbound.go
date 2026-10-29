package aisession

// Multi-backend outbound shipper for AI session records: a thin adapter over
// accesslog.GenericShipper[Record] built with the AI stream identity. The
// batcher, the backpressure drop counting, the sampling and the idempotent
// Close are shared with the access-log pipeline; the record encoder keeps the
// full AI semantics (the ES document shape is byte-identical to the retired
// ESShipper's json.Marshal(Record) payload, and the daily index rule follows
// the record's own timestamp).

import (
	"encoding/json"
	"log/slog"
	"slices"
	"time"

	"github.com/kingmoat/kingmoat/internal/accesslog"
	"github.com/kingmoat/kingmoat/internal/config"
)

// AIOutbound is the outbound-shipper contract the central store fans accepted
// records out to: an AISink plus Close (final flush + stop). rebuildAIShip
// swaps implementations behind an atomic interface pointer; Shipper is the
// generic multi-backend implementation (all six sink types).
type AIOutbound interface {
	AISink
	Close() error
}

// Shipper satisfies the outbound contract.
var _ AIOutbound = (*Shipper)(nil)

// Shipper ships AI session records to the configured backend
// (clickhouse / elasticsearch / loki / s3 / syslog / kafka) through the
// generic access-log pipeline. Close is idempotent and flushes pending
// records; WriteAIRecord never blocks the capture pipeline (drops under
// backpressure are counted inside the generic batcher; the central SQLite
// store always keeps its own durable copy first).
type Shipper struct {
	inner *accesslog.GenericShipper[Record]
}

// NewShipper validates the settings and starts the batcher. The settings are
// the AI-ship section resolved by cmd/kingmoatwaf (channel reuse applied)
// converted with ShipSettings.
func NewShipper(cfg config.AccessLogSettings, logger *slog.Logger) (*Shipper, error) {
	inner, err := accesslog.NewGeneric[Record](cfg, accesslog.StreamAI, recordDoc, logger)
	if err != nil {
		return nil, err
	}
	return &Shipper{inner: inner}, nil
}

// WriteAIRecord implements AISink: hand the record to the generic batcher.
func (s *Shipper) WriteAIRecord(r Record) { s.inner.Write(&r) }

// Dropped returns records shed under backpressure (observability).
func (s *Shipper) Dropped() int64 { return s.inner.Dropped() }

// Close flushes pending records and stops the batcher. It is idempotent.
func (s *Shipper) Close() error { return s.inner.Close() }

// recordDoc encodes one AI session record into the pre-encoded outbound
// document. The line is the FULL record JSON — provider/model/usage/stream/
// trace_id/duration and every other AI semantic stay intact (the outbound
// document never flattens into the generic event fields). kind is the AI
// event category (syslog MSGID; the severity mapping stays syslogsink's,
// keyed on the same blocked/challenged vocabulary the access stream uses)
// and key the trace id, which rides along as the kafka partition key for
// free. An empty record timestamp falls back to now so the daily index
// routing and the syslog/loki timestamps stay valid.
func recordDoc(r *Record) accesslog.Doc {
	ts := r.TS
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, _ := json.Marshal(r)
	return accesslog.NewDoc(ts, b, aiEventKind(r), r.TraceID)
}

// aiEventKind classifies one record for the syslog MSGID (and any future
// severity mapping): a failed call ships as "error", an interrupted one as
// "interrupted", everything else as "completed".
func aiEventKind(r *Record) string {
	switch {
	case r.Err != "":
		return "error"
	case r.Interrupted:
		return "interrupted"
	default:
		return "completed"
	}
}

// ShipSettings converts the AI-ship section into the access-log settings the
// generic shipper consumes. The two sections mirror each other field for
// field (same sink matrix, same transports); the deprecated flat s3 prefix /
// use_ssl seed the nested block when it is absent (T-1 fallback-seed
// convention: publish-time validation rejects a bare flat s3 section, so this
// only rescues hand-edited static files at runtime).
func ShipSettings(s config.AIAuditShipSettings) config.AccessLogSettings {
	out := config.AccessLogSettings{
		Enabled:         s.Enabled,
		UseAuditChannel: s.UseAuditChannel,
		Type:            s.Type,
		URL:             s.URL,
		Index:           s.Index,
		SamplePct:       s.SamplePct,
		BatchSize:       s.BatchSize,
		FlushSec:        s.FlushSec,
		TimeoutSec:      s.TimeoutSec,
		Username:        s.Username,
		Password:        s.Password,
		S3:              s.S3,
		Syslog:          s.Syslog,
		Brokers:         slices.Clone(s.Brokers),
		Topic:           s.Topic,
		UseTLS:          s.UseTLS,
		SASL:            s.SASL,
		TLSSkipVerify:   s.TLSSkipVerify,
	}
	if out.Type == "s3" && out.S3 == nil && (s.Prefix != "" || s.UseSSL != nil) {
		s3 := &config.S3Settings{Prefix: s.Prefix}
		if s.UseSSL != nil {
			s3.UseSSL = *s.UseSSL
		}
		out.S3 = s3
	}
	return out
}
