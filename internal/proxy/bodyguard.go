package proxy

import (
	"sync"

	"github.com/kingmoat/kingmoat/internal/config"
)

// bodyMemGuard bounds the aggregate bytes buffered for request-body
// inspection across ALL in-flight requests. Site body limits cap a single
// request; without an aggregate bound, concurrency x limit is unbounded
// (the memory-amplification hardening: a site with a 1 GiB inspection
// limit and a burst of uploads would otherwise pin unbounded memory).
//
// Acquisition is incremental — the body read loop reserves each chunk
// before appending, so small bodies reserve small credits and known-length
// over-limit rejects (the ContentLength fast path) reserve nothing at all.
// Semantics are deliberately fail-closed: when the budget is exhausted the
// read aborts and the request is answered 503, so memory pressure can never
// silently downgrade body inspection to bypass.
type bodyMemGuard struct {
	mu     sync.Mutex
	inUse  int64
	budget int64 // bytes; < 0 = unlimited
}

// bodyMem is the process-wide guard. The budget is refreshed from the
// current configuration on every buildState (boot + publish), so
// body_buffer_budget_mb hot-applies.
var bodyMem = &bodyMemGuard{budget: config.DefaultBodyBufferBudgetMB << 20}

// setBudget swaps the aggregate budget in MB (negative disables the guard).
func (g *bodyMemGuard) setBudget(mb int64) {
	g.mu.Lock()
	g.budget = mb << 20
	g.mu.Unlock()
}

// reserve tries to add n bytes to the in-use accounting; false means the
// budget is exhausted (fail-fast: no waiting).
func (g *bodyMemGuard) reserve(n int64) bool {
	if n <= 0 {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.budget < 0 || g.inUse+n <= g.budget {
		g.inUse += n
		return true
	}
	return false
}

// budgetBytes reports the current aggregate budget in bytes (tests).
func (g *bodyMemGuard) budgetBytes() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.budget
}

// setBudgetMB shrinks/raises the budget in MB (tests use it directly; the
// production path is buildState -> setBudget).
func (g *bodyMemGuard) setBudgetMB(mb int64) { g.setBudget(mb) }

// setBudgetBytes swaps the aggregate budget in bytes directly (tests).
func (g *bodyMemGuard) setBudgetBytes(n int64) {
	g.mu.Lock()
	g.budget = n
	g.mu.Unlock()
}

// release returns previously reserved bytes to the budget.
func (g *bodyMemGuard) release(n int64) {
	if n <= 0 {
		return
	}
	g.mu.Lock()
	g.inUse -= n
	if g.inUse < 0 {
		g.inUse = 0
	}
	g.mu.Unlock()
}

// inUseBytes reports the current reservation (tests/observability).
func (g *bodyMemGuard) inUseBytes() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inUse
}
