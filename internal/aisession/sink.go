package aisession

// Node-side pipeline: bounded async queue + in-memory ring. Identify/capture
// never blocks the request hot path; finalized records are enqueued (drop
// counted under backpressure) and fanned out to the ring (console live tail)
// and the uplink store hook (T-07).

import (
	cryptoRand "crypto/rand"
	"encoding/hex"
	"sync"
	"sync/atomic"

	"github.com/kingmoat/kingmoat/internal/config"
)

// Sink receives finalized records. The uplink store implements it in T-07.
type Sink interface {
	WriteAI(r Record)
}

// Pipeline is the per-node AI session-audit engine. nil-safety: the proxy
// path checks Load() before touching anything.
type Pipeline struct {
	nodeID    string
	cfg       atomic.Pointer[config.AIAuditSettings]
	sampleCtr atomic.Int64
	ring      *Ring
	ch        chan Record
	dropped   atomic.Int64
	out       atomic.Pointer[Sink]

	closed atomic.Bool

	wg sync.WaitGroup
}

// NewPipeline builds the engine with a 1024-slot queue and a ring bounded to
// ringSize entries (console live tail).
func NewPipeline(nodeID string, cfg *config.AIAuditSettings, ringSize int) *Pipeline {
	if ringSize <= 0 {
		ringSize = 500
	}
	p := &Pipeline{nodeID: nodeID,
		ring: NewRing(ringSize),
		ch:   make(chan Record, 1024),
	}
	if cfg != nil {
		p.cfg.Store(cfg)
	}
	p.wg.Add(1)
	go p.loop()
	return p
}

// Configure hot-applies new settings (captured per request via Load).
func (p *Pipeline) Configure(cfg *config.AIAuditSettings) {
	if cfg == nil {
		p.cfg.Store(nil)
		return
	}
	p.cfg.Store(cfg)
}

// SetSink wires the outbound/uplink consumer (nil disables it).
func (p *Pipeline) SetSink(s Sink) {
	if s == nil {
		p.out.Store(nil)
		return
	}
	p.out.Store(&s)
}

// Enabled reports whether capture is on for new requests.
func (p *Pipeline) Enabled() bool {
	c := p.cfg.Load()
	return c != nil && c.Enabled
}

// Settings returns the current snapshot (nil = off).
func (p *Pipeline) Settings() *config.AIAuditSettings { return p.cfg.Load() }

// Enqueue hands a finalized record to the async fan-out; never blocks and
// is safe after Close (no-op instead of panicking on a closed channel).
func (p *Pipeline) Enqueue(r Record) {
	if p.closed.Load() {
		p.dropped.Add(1)
		return
	}
	select {
	case p.ch <- r:
	default:
		p.dropped.Add(1)
	}
}

// Dropped returns the number of records dropped under backpressure.
func (p *Pipeline) Dropped() int64 { return p.dropped.Load() }

// Depth returns the current queue length (observability gauge).
func (p *Pipeline) Depth() int { return len(p.ch) }

// Ring exposes the live tail (console page).
func (p *Pipeline) Ring() *Ring { return p.ring }

func (p *Pipeline) loop() {
	defer p.wg.Done()
	for r := range p.ch {
		p.ring.Write(r)
		if s := p.out.Load(); s != nil {
			(*s).WriteAI(r)
		}
	}
}

// Close drains the queue best-effort and stops the consumer.
func (p *Pipeline) Close() error {
	if p.closed.Swap(true) {
		return nil
	}
	close(p.ch)
	p.wg.Wait()
	return nil
}

// newID returns a random 20-hex-char record id.
func newID() string {
	b := make([]byte, 10)
	_, _ = cryptoRand.Read(b)
	return hex.EncodeToString(b)
}
