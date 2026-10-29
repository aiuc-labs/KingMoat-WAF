package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

var (
	errRequestBodyRead = errors.New("proxy: read request body failed")
	// errBodyBudget: the aggregate body-buffer budget is exhausted — the
	// request is answered 503 (deliberately fail-closed: memory pressure
	// must never silently downgrade body inspection to bypass).
	errBodyBudget = errors.New("proxy: request body buffer budget exhausted")
	// errBodyIdle: no body-read progress within the idle window — the
	// request is answered 408 (nginx client_body_timeout parity).
	errBodyIdle = errors.New("proxy: request body read stalled")
)

// bodyIdleTimeout bounds how long a request-body read may make no progress.
// Package var so tests can shrink it; the watchdog aborts by rewinding the
// connection read deadline.
var bodyIdleTimeout = 60 * time.Second

// countBody counts the bytes read from the wrapped request body (up
// direction of the site transferred-data panel) without changing Read/Close
// semantics for the WAF engine and the reverse-proxy copy.
type countBody struct {
	rc io.ReadCloser
	n  *atomic.Int64
}

func (c *countBody) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *countBody) Close() error { return c.rc.Close() }

// bodyWatchdog aborts request-body reads that stall: no read progress for
// bodyIdleTimeout. One timer per request, reset (cheap) on every read; the
// abort unblocks a pending Read by rewinding the connection read deadline
// via http.ResponseController, and the wrapped reader fail-fasts subsequent
// reads with errBodyIdle. stop() disarms it at handler end.
type bodyWatchdog struct {
	aborted  atomic.Bool
	disarmed atomic.Bool
	timer    *time.Timer
	w        http.ResponseWriter
}

func newBodyWatchdog(w http.ResponseWriter) *bodyWatchdog {
	wd := &bodyWatchdog{w: w}
	wd.timer = time.AfterFunc(bodyIdleTimeout, wd.abort)
	return wd
}

// touch records read progress and re-arms the idle timer.
func (wd *bodyWatchdog) touch() { wd.timer.Reset(bodyIdleTimeout) }

// disarm stops the idle abort: once the body has been fully buffered (or the
// request is about to end with a reject) there are no more client reads to
// protect — a long-running detection pipeline or upstream round trip must
// NOT be mistaken for a stalled body (the abort rewinds the connection read
// deadline, which Go's server interprets as client disconnect and cancels
// the request context, killing the in-flight round trip).
func (wd *bodyWatchdog) disarm() {
	wd.disarmed.Store(true)
	wd.timer.Stop()
}

// abort marks the watchdog fired and unblocks the pending body Read.
func (wd *bodyWatchdog) abort() {
	if wd.disarmed.Load() {
		return
	}
	wd.aborted.Store(true)
	// Best effort: on a real connection rewinding the read deadline fails
	// the in-flight Read immediately; where the controller is unavailable
	// (tests, hijacked connections) the wrapped reader's next Read still
	// fails fast.
	_ = http.NewResponseController(wd.w).SetReadDeadline(time.Now().Add(-time.Second))
}

func (wd *bodyWatchdog) stop() {
	if wd.timer != nil {
		wd.timer.Stop()
	}
}

// wrap returns a ReadCloser that records progress through the watchdog and
// fail-fasts once the idle abort fired.
func (wd *bodyWatchdog) wrap(rc io.ReadCloser) io.ReadCloser {
	return &stallBody{rc: rc, wd: wd}
}

type stallBody struct {
	rc io.ReadCloser
	wd *bodyWatchdog
}

func (s *stallBody) Read(p []byte) (int, error) {
	if s.wd.aborted.Load() {
		return 0, errBodyIdle
	}
	n, err := s.rc.Read(p)
	if n > 0 {
		s.wd.touch()
	}
	if err != nil && s.wd.aborted.Load() {
		// The abort unblocked this Read (connection read deadline rewound);
		// report the stall, not the low-level timeout it caused.
		return n, errBodyIdle
	}
	return n, err
}

func (s *stallBody) Close() error { return s.rc.Close() }

// wantsBody reports whether the request carries a body worth buffering:
// not an upgrade (WebSocket) and either a known positive Content-Length or
// a chunked body.
func wantsBody(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		strings.EqualFold(r.Header.Get("Connection"), "upgrade") {
		return false
	}
	if r.ContentLength > 0 {
		return true
	}
	if r.ContentLength < 0 { // chunked / unknown length
		return true
	}
	return false
}

// poolBufMax bounds the buffer size eligible for pooling. Requests whose
// body fits within it (the overwhelming majority) reuse pooled memory; larger
// limits fall back to plain allocations so the pool stays small.
const poolBufMax = 64 << 10

// bodyPool recycles small request-body buffers across requests. Buffers are
// reused, not zeroed — contents are always overwritten before use and never
// leave the process.
var bodyPool = sync.Pool{
	New: func() any { b := make([]byte, 0, poolBufMax); return &b },
}

// bodyBufPool wraps the pooled scratch buffer with its final cap so Put can
// decide whether the grown buffer is still worth recycling.
type bodyBufPool struct {
	buf []byte
}

// readBody reads up to limit+1 bytes of the request body, reserving every
// chunk against the aggregate body-buffer budget BEFORE appending (fail-
// closed: budget pressure aborts the read, it never silently skips
// inspection). It returns the bytes read plus a pool handle: when pooled !=
// nil the caller must return the handle via bodyPool.Put once the bytes are
// no longer needed (after inspection and forwarding decisions). over
// reports that the limit was exceeded (the extra byte was read to detect
// it); reserved reports the budget bytes the caller must release (via
// bodyMem.release) once the buffer is no longer referenced — on error the
// reservation is already returned and reserved is 0.
func readBody(r *http.Request, limit int64) (head []byte, over bool, pooled *bodyBufPool, reserved int64, err error) {
	bp := bodyPool.Get().(*[]byte)
	buf := (*bp)[:0]
	tmp := make([]byte, 16<<10)
	for {
		// Never read past limit+1: bytes beyond it must stay in the stream
		// so over-limit policies can forward them untouched.
		want := limit + 1 - int64(len(buf))
		if want <= 0 {
			break
		}
		if want > int64(len(tmp)) {
			want = int64(len(tmp))
		}
		n, rerr := r.Body.Read(tmp[:want])
		if n > 0 {
			if !bodyMem.reserve(int64(n)) {
				// Glue back whatever we got so the error response is clean;
				// this chunk was never appended, earlier chunks are returned.
				r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
				*bp = buf
				bodyPool.Put(bp)
				bodyMem.release(reserved)
				return nil, false, nil, 0, errBodyBudget
			}
			reserved += int64(n)
			buf = append(buf, tmp[:n]...)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			// Glue back whatever we got so the error response is clean.
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
			*bp = buf
			bodyPool.Put(bp)
			bodyMem.release(reserved)
			// Preserve the idle-abort semantics so the caller can answer 408
			// instead of the generic 400.
			if errors.Is(rerr, errBodyIdle) {
				return nil, false, nil, 0, errBodyIdle
			}
			return nil, false, nil, 0, errRequestBodyRead
		}
	}
	if int64(len(buf)) > limit {
		*bp = buf
		if cap(buf) <= poolBufMax {
			// Caller glues the bytes back before forwarding; the handle
			// must be recycled afterwards.
			return buf[:limit+1], true, &bodyBufPool{buf: buf}, reserved, nil
		}
		return buf[:limit+1], true, nil, reserved, nil
	}
	*bp = buf
	if cap(buf) <= poolBufMax {
		return buf, false, &bodyBufPool{buf: buf}, reserved, nil
	}
	return buf, false, nil, reserved, nil
}

// recycle returns a pooled handle; grown buffers beyond the pool cap are
// left to the GC.
func recycle(p *bodyBufPool) {
	if p == nil || cap(p.buf) > poolBufMax {
		return
	}
	bp := p.buf[:0]
	bodyPool.Put(&bp)
}

// bodyOutcome carries the request-body buffering decision for one request.
type bodyOutcome struct {
	data    []byte       // buffered bytes for inspection (nil = nothing buffered)
	over    bool         // the site body limit was exceeded
	pool    *bodyBufPool // pooled scratch handle to recycle at handler end (nil = none)
	release func()       // aggregate-budget release for the buffered bytes (nil = none)
	skip    string       // "bypass" | "prefix": the body passed WITHOUT full inspection
	err     error        // read/abort/budget error; the caller answers the request
}

// bufferBody reads the request body for inspection, enforcing the site
// limit and the aggregate buffer budget. Outcomes (pool/release non-nil
// mean the caller must recycle/release once the bytes are no longer
// referenced — a deferred recycle/release in ServeHTTP covers all paths):
//   - !over          — body buffered, r.Body rewound, data returned
//   - over, reject   — the caller answers 413; over=true, no pass marker
//   - over, bypass   — prefix dropped, full stream forwards untouched
//   - over, stream   — prefix returned for inspection, remainder streams
//   - err            — budget exhausted (503), idle abort (408) or client
//     abort / I/O failure (400); the caller maps err to the response
//
// data is the bytes fed to the detection ENGINE — bounded by the inspect
// window (site.WAF.InspectLimit(), default 256 KB): full-CRS scanning of
// urlencoded bodies costs ~170 KB/s, so the window bounds per-request CPU
// independently of the body size; the remainder forwards untouched and the
// partial inspection is marked via skip="prefix". The body_limit_bytes
// accept/reject decision is unaffected by the window.
//
// The site's WAF body limit is authoritative for the accept/reject decision
// (proxy buffer == limit, and the engine's SecRequestBodyLimit is aligned
// at build time; the engine only ever sees up to the window, never more).
func bufferBody(r *http.Request, site *config.Site, wd *bodyWatchdog) bodyOutcome {
	limit := site.WAF.BodyLimit()
	inspect := site.WAF.InspectLimit()
	// Effective over-limit behavior for THIS request path: a declared
	// body_stream_paths prefix forces "stream" (upload endpoints), so the
	// fast path and the branch order below must key off the resolved mode —
	// checking the site-level body_over_limit instead would send declared
	// upload paths down the reject/bypass fast path and silently skip the
	// prefix inspection the declaration promises.
	mode := site.WAF.OverLimitForPath(r.URL.Path)

	// Trusted Content-Length above the limit: reject and bypass answer
	// without reading a single byte (no memory, no budget). The stream
	// policy still deep-inspects the first `limit` bytes, so it must NOT
	// take the fast path — a known-length over-limit body used to skip
	// prefix inspection entirely, silently diverging from the chunked
	// shape (the exact class of inconsistency this guard closes).
	if r.ContentLength > limit && mode != "stream" {
		if mode == "reject" {
			if wd != nil {
				wd.disarm()
			}
			return bodyOutcome{over: true}
		}
		// Bypass: the wrapper stays in the forwarded chain — keep armed.
		return bodyOutcome{over: true, skip: "bypass"}
	}

	head, over, pool, reserved, err := readBody(r, limit)
	if err != nil {
		return bodyOutcome{err: err}
	}
	var release func()
	if reserved > 0 {
		release = func() { bodyMem.release(reserved) }
	}
	if over {
		// Rewind consumed bytes: full stream forwards untouched (bypass and
		// stream policies); reject short-circuits before forwarding anyway.
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(head), r.Body))
		if mode == "stream" {
			// Deep-inspect the buffered prefix; the remainder streams — the
			// wrapper stays in the forwarded chain, watchdog stays armed.
			return bodyOutcome{data: head[:inspect], over: true, pool: pool, release: release, skip: "prefix"}
		}
		if wd != nil {
			wd.disarm()
		}
		if mode == "reject" {
			return bodyOutcome{over: true, pool: pool, release: release}
		}
		return bodyOutcome{over: true, pool: pool, release: release, skip: "bypass"}
	}
	// Fully buffered: no further client reads (the rewound body is memory);
	// disarm so a long detection pipeline is never mistaken for a stall.
	if wd != nil {
		wd.disarm()
	}
	if int64(len(head)) > inspect {
		// Engine window: only the first `inspect` bytes are scanned; the
		// remainder forwards untouched and the partial inspection is marked.
		r.Body = io.NopCloser(bytes.NewReader(head))
		return bodyOutcome{data: head[:inspect], pool: pool, release: release, skip: "prefix"}
	}
	r.Body = io.NopCloser(bytes.NewReader(head))
	return bodyOutcome{data: head, pool: pool, release: release}
}
