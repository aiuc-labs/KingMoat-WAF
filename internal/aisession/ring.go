package aisession

import "sync"

// Ring is a fixed-capacity in-memory tail for the console live view
// (thread-safe; newest at the head of Recent).
type Ring struct {
	mu    sync.Mutex
	buf   []Record
	head  int
	count int
}

// NewRing builds a ring bounded to cap entries.
func NewRing(capacity int) *Ring {
	if capacity <= 0 {
		capacity = 500
	}
	return &Ring{buf: make([]Record, capacity)}
}

// Write appends one record (overwrites the oldest when full).
func (r *Ring) Write(rec Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.head] = rec
	r.head = (r.head + 1) % len(r.buf)
	if r.count < len(r.buf) {
		r.count++
	}
}

// Count returns the number of records currently held.
func (r *Ring) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// Recent returns up to limit newest records, newest first, optionally
// filtered by site / free-text (path|ip|ua|model) / outcome-less provider.
func (r *Ring) Recent(limit int, site, q, provider string) []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, 0, min(limit, r.count))
	for i := 0; i < r.count && len(out) < limit; i++ {
		idx := (r.head - 1 - i + len(r.buf)) % len(r.buf)
		rec := r.buf[idx]
		if site != "" && rec.Site != site {
			continue
		}
		if provider != "" && rec.Provider != provider {
			continue
		}
		if q != "" && !matchesQuery(rec, q) {
			continue
		}
		out = append(out, rec)
	}
	return out
}

func matchesQuery(rec Record, q string) bool {
	lq := lower(q)
	for _, v := range []string{rec.Path, rec.ClientIP, rec.UserAgent, rec.Model, rec.Provider, rec.TraceID, rec.Response.Text} {
		if contains(lower(v), lq) {
			return true
		}
	}
	return false
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

func contains(s, sub string) bool {
	if sub == "" {
		return true
	}
	return indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	n, m := len(s), len(sub)
	if m == 0 || m > n {
		if m == 0 {
			return 0
		}
		return -1
	}
	for i := 0; i+m <= n; i++ {
		if s[i:i+m] == sub {
			return i
		}
	}
	return -1
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
