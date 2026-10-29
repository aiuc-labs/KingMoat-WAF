// Package configcenter implements the M2 versioned configuration center:
// publish → validate → append revision → in-process fan-out. Data planes
// observe changes either in-process (all-in-one) or via the API poll
// endpoint (remote mode). Validation failure never takes effect
// (docs/ARCHITECTURE.md §4.3).
package configcenter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/store"
)

// Center holds the current configuration and its revision history.
type Center struct {
	store  *store.Store
	dbPath string
	logger *slog.Logger

	mu   sync.RWMutex
	rev  int64
	cfg  *config.Config
	subs map[chan RevEvent]struct{}

	// loadNotes carries the load-time normalization/degradation facts of the
	// CURRENT config (which outbound sections were migrated/degraded at boot
	// or by the latest rollback, and why — see config.NormalizeLegacyOutbound
	// for the entry texts). In-memory only: stored revisions are never
	// rewritten (append-only). Every successful publish sets the notes to the
	// new revision's own facts — none for Publish (the revision passed strict
	// validation), the rollback's normalization entries for Rollback — in the
	// same critical section that activates the revision, so a concurrent
	// publish can never leave a stale note on the newer config. Guarded by mu.
	loadNotes []string

	// lastApply carries the data-plane outcome of the most recent revision
	// (written by the hot-reload consumer via SetApplyStatus).
	lastApply atomic.Value

	// applyResults carries the per-revision apply outcomes so a waiter for
	// revision N can never read the result of revision N+1 (the old single
	// ">= rev" check let a newer result stand in for an older failure).
	// Bounded: entries far below the newest result are pruned on insert.
	applyMu      sync.Mutex
	applyResults map[int64]ApplyStatus
}

// DBPath returns the SQLite database file path (for sibling data dirs).
func (c *Center) DBPath() string { return c.dbPath }

// Open initializes the center from SQLite. When the store is empty and a
// seed config is provided, the seed is imported as revision 1.
//
// Both load paths tolerate legacy outbound shapes produced by v0.7.13 and
// earlier: stored revisions and the seed are normalized AND unshippable
// outbound sections degraded BEFORE validate (config.NormalizeLegacyOutbound /
// NormalizeLegacyOutboundJSON), so an upgraded binary can never be denied boot
// by an outbound section — the class of shapes v0.7.13 accepted. Stored
// revisions are never rewritten — normalization is deterministic and
// re-derived on every boot.
func Open(dbPath string, seed *config.Config, logger *slog.Logger) (*Center, error) {
	if logger == nil {
		logger = slog.Default()
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	c := &Center{store: st, dbPath: dbPath, logger: logger, subs: make(map[chan RevEvent]struct{})}

	rev, raw, err := st.CurrentRevision()
	if err == nil {
		nb, applied, nerr := config.NormalizeLegacyOutboundJSON([]byte(raw))
		if nerr != nil {
			logger.Warn("configcenter: stored revision is not decodable JSON; passing through to decode for the schema error",
				"revision", rev, "err", nerr)
		}
		var cfg config.Config
		if err := json.Unmarshal(nb, &cfg); err != nil {
			st.Close()
			return nil, fmt.Errorf("configcenter: decode revision %d: %w", rev, err)
		}
		if degraded := config.NormalizeLegacyOutbound(&cfg); len(degraded) > 0 {
			applied = append(applied, degraded...)
		}
		if len(applied) > 0 {
			logger.Warn("configcenter: legacy outbound form normalized/degraded (stored revision kept as-is; re-derived on every boot)",
				"revision", rev, "applied", applied)
			c.mu.Lock()
			c.loadNotes = applied
			c.mu.Unlock()
		}
		if err := cfg.Validate(); err != nil {
			st.Close()
			return nil, fmt.Errorf("configcenter: stored revision %d invalid: %w", rev, err)
		}
		c.rev, c.cfg = rev, &cfg
		return c, nil
	}
	if seed == nil {
		st.Close()
		return nil, fmt.Errorf("configcenter: %w", err)
	}
	if applied := config.NormalizeLegacyOutbound(seed); len(applied) > 0 {
		logger.Warn("configcenter: seed config legacy outbound form normalized/degraded", "applied", applied)
		c.mu.Lock()
		c.loadNotes = applied
		c.mu.Unlock()
	}
	if err := seed.Validate(); err != nil {
		st.Close()
		return nil, fmt.Errorf("configcenter: seed config invalid: %w", err)
	}
	b, _ := json.Marshal(seed)
	rev, err = st.AppendRevision(string(b), "bootstrap", "initial import")
	if err != nil {
		st.Close()
		return nil, err
	}
	c.rev, c.cfg = rev, seed
	logger.Info("configcenter: seed config imported", "revision", rev, "sites", len(seed.Sites))
	return c, nil
}

// ErrNoChanges is returned by Publish when the submitted configuration is
// identical (after normalization) to the active revision; no new revision is
// created and the active revision is returned untouched. Rollback bypasses
// this check on purpose: re-publishing a historical revision always creates
// an explicit point-in-time marker.
var ErrNoChanges = errors.New("configcenter: configuration unchanged")

// Current returns the active revision id and configuration.
func (c *Center) Current() (int64, *config.Config) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rev, c.cfg
}

// LoadNotes returns the load-time normalization/degradation entries of the
// current configuration (nil = clean load, nothing was migrated/degraded).
// The entries reuse config.NormalizeLegacyOutbound's own texts verbatim.
func (c *Center) LoadNotes() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.loadNotes) == 0 {
		return nil
	}
	out := make([]string, len(c.loadNotes))
	copy(out, c.loadNotes)
	return out
}

// AppendLoadNote records one additional load-time fact about the CURRENT
// configuration: a data-plane degradation discovered while hot-applying
// revision rev (e.g. the local access-log store rebuild failed and the
// previous posture stays active). The append shares publishInternal's
// critical section (mu over loadNotes), and only lands while the active
// revision is still rev: a concurrent publish either clears the notes as
// part of activating its own revision or voids the append, so a note about
// an older revision's failure can never linger on a newer one. Reports
// whether the note was recorded (false = revision advanced, caller logs).
func (c *Center) AppendLoadNote(rev int64, note string) bool {
	if strings.TrimSpace(note) == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rev != rev {
		return false
	}
	c.loadNotes = append(c.loadNotes, note)
	return true
}

// Publish validates and persists a new configuration revision, then notifies
// all in-process subscribers. When the submitted config is identical to the
// active one, ErrNoChanges is returned and no revision is appended. On any
// error the current config is untouched.
func (c *Center) Publish(next *config.Config, author, note string) (int64, error) {
	return c.publishInternal(next, author, note, false, nil)
}

func (c *Center) publishInternal(next *config.Config, author, note string, allowNoChanges bool, loadNotes []string) (int64, error) {
	if next == nil {
		return 0, fmt.Errorf("configcenter: nil config")
	}
	if err := next.Validate(); err != nil {
		return 0, err
	}
	b, err := json.Marshal(next)
	if err != nil {
		return 0, fmt.Errorf("configcenter: encode config: %w", err)
	}
	if !allowNoChanges {
		// Compare against the ACTIVE REVISION'S STORED payload (the source of
		// truth) after normalizing both sides: empty objects/arrays are
		// stripped recursively, because console forms round-trip absent
		// sections as empty containers (e.g. an edited site carries
		// "security":{}) — a difference that changes no behavior must not
		// create a new revision. Comparing the live in-memory object instead
		// would misreport "no changes" when callers mutate the shared config
		// in place before publishing (e.g. policy exception handlers).
		curRev, _ := c.Current()
		if curRev > 0 {
			if raw, gerr := c.store.GetRevision(curRev); gerr == nil {
				var curAny, nextAny any
				if uerr := json.Unmarshal([]byte(raw), &curAny); uerr == nil {
					if nerr := json.Unmarshal(b, &nextAny); nerr == nil {
						cb, merr := json.Marshal(normalizeEmptyContainers(curAny))
						nb, nerr := json.Marshal(normalizeEmptyContainers(nextAny))
						if merr == nil && nerr == nil && bytes.Equal(cb, nb) {
							return curRev, ErrNoChanges
						}
					}
				}
			}
		}
	}
	rev, err := c.store.AppendRevision(string(b), author, note)
	if err != nil {
		return 0, err
	}

	c.mu.Lock()
	c.rev = rev
	c.cfg = next
	// loadNotes carries THIS revision's own load-time facts: Publish passes
	// none (strict validation passed), Rollback passes its normalization
	// entries. Setting it inside the same critical section that activates the
	// revision keeps "activate config" and "record notes" one atomic step —
	// a concurrent publish can never interleave and leave a stale rollback
	// note on a newer revision.
	c.loadNotes = loadNotes
	for ch := range c.subs {
		select {
		case ch <- RevEvent{Rev: rev, Config: next}:
		default: // subscriber slow: event dropped (buffer full); Consume's catch-up check re-applies Current() after the next handled event
		}
	}
	c.mu.Unlock()

	c.logger.Info("configcenter: revision published",
		"revision", rev, "sites", len(next.Sites), "author", author, "note", note)
	return rev, nil
}

// PublishSite validates and publishes a single-site change: the site is
// merged into the current configuration (replaced when one of its domains
// already exists, appended otherwise) and the whole document is validated
// before a new revision is stored.
//
// Because the live configuration is always valid, a validation failure can
// only come from the submitted site — other sites' changes are never blocked
// by it, which is the per-site isolation the API surface promises.
func (c *Center) PublishSite(domain string, site config.Site, author, note string) (int64, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return 0, fmt.Errorf("configcenter: domain is required")
	}
	_, cur := c.Current()
	if cur == nil {
		return 0, fmt.Errorf("configcenter: no active configuration")
	}
	next := *cur // shallow copy; Sites slice is rebuilt below
	next.Sites = make([]config.Site, len(cur.Sites))
	copy(next.Sites, cur.Sites)

	match := -1
	for i := range next.Sites {
		for _, d := range next.Sites[i].Domains {
			if strings.ToLower(strings.TrimSpace(d)) == domain {
				match = i
				break
			}
		}
		if match >= 0 {
			break
		}
	}
	if match >= 0 {
		next.Sites[match] = site
	} else {
		next.Sites = append(next.Sites, site)
	}
	if note == "" {
		note = "site publish: " + domain
	}
	return c.Publish(&next, author, note)
}

// RevEvent is one published revision with the configuration snapshot that
// belongs to it. Consumers must apply event.Config (not the center's current
// config): by the time a slow consumer handles revision N, a newer revision
// may already be active, and applying Current() would mispair the reload
// result reported for N.
type RevEvent struct {
	Rev    int64
	Config *config.Config
}

// Subscribe returns a channel receiving published revision events (revision
// id + its config snapshot), plus a cancel func.
func (c *Center) Subscribe() (<-chan RevEvent, func()) {
	ch := make(chan RevEvent, 8)
	c.mu.Lock()
	c.subs[ch] = struct{}{}
	c.mu.Unlock()
	cancel := func() {
		c.mu.Lock()
		delete(c.subs, ch)
		c.mu.Unlock()
	}
	return ch, cancel
}

// Rollback re-publishes the payload of an existing revision as a new revision
// (history is append-only; rollback never rewrites it). Legacy outbound
// shapes in historical revisions are normalized and unshippable sections
// degraded before validate so rolling back to a pre-strictness revision stays
// possible; the new revision stores the normalized form. The normalization
// entries are recorded as the load notes of the now-active config inside
// publishInternal's success critical section (atomic against a concurrent
// publish); a failed rollback leaves the previously active revision's notes
// in place.
func (c *Center) Rollback(id int64, author string) (int64, error) {
	raw, err := c.store.GetRevision(id)
	if err != nil {
		return 0, err
	}
	nb, applied, nerr := config.NormalizeLegacyOutboundJSON([]byte(raw))
	if nerr != nil {
		applied = nil // not decodable JSON: unmarshal below reports the schema error
	}
	var cfg config.Config
	if err := json.Unmarshal(nb, &cfg); err != nil {
		return 0, fmt.Errorf("configcenter: decode revision %d: %w", id, err)
	}
	if degraded := config.NormalizeLegacyOutbound(&cfg); len(degraded) > 0 {
		applied = append(applied, degraded...)
	}
	if len(applied) > 0 {
		c.logger.Warn("configcenter: rollback revision carries legacy outbound form; normalized into the new revision",
			"revision", id, "applied", applied)
	}
	// Record the rollback's normalization entries inside the publish's success
	// critical section: with the strictly-validated new revision now active,
	// these entries are its load-time fact (the historical revision itself is
	// untouched), and recording them there makes the write atomic against a
	// concurrent publish clearing the notes.
	rev, err := c.publishInternal(&cfg, author, fmt.Sprintf("rollback to revision %d", id), true, applied)
	if err != nil {
		return 0, err
	}
	return rev, nil
}

// ApplyStatus reports the data-plane outcome of one published revision.
type ApplyStatus struct {
	Revision int64  `json:"revision"`
	Status   string `json:"status"` // "applied" | "failed" | "pending"
	Error    string `json:"error,omitempty"`
}

// SetApplyStatus records the data-plane apply outcome for a revision; called
// by the hot-reload consumer right after the plane rebuild returns.
func (c *Center) SetApplyStatus(rev int64, applyErr error) {
	st := ApplyStatus{Revision: rev, Status: "applied"}
	if applyErr != nil {
		st.Status = "failed"
		st.Error = applyErr.Error()
	}
	c.lastApply.Store(st)
	c.applyMu.Lock()
	if c.applyResults == nil {
		c.applyResults = make(map[int64]ApplyStatus)
	}
	c.applyResults[rev] = st
	for len(c.applyResults) > applyHistoryLimit {
		minRev := int64(0)
		for r := range c.applyResults {
			if minRev == 0 || r < minRev {
				minRev = r
			}
		}
		delete(c.applyResults, minRev)
	}
	c.applyMu.Unlock()
}

// ApplyStatus returns the most recent data-plane apply outcome (zero value =
// no consumer reported yet).
func (c *Center) ApplyStatus() ApplyStatus {
	if v, ok := c.lastApply.Load().(ApplyStatus); ok {
		return v
	}
	return ApplyStatus{}
}

// ApplyStatusFor returns the recorded apply outcome for exactly rev; ok is
// false when no consumer has reported that revision yet.
func (c *Center) ApplyStatusFor(rev int64) (ApplyStatus, bool) {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	st, ok := c.applyResults[rev]
	return st, ok
}

// applyHistoryLimit bounds the per-revision apply-result registry (status
// queries only ever need recent revisions).
const applyHistoryLimit = 64

// WaitForApply blocks until a consumer reports the apply outcome for rev, or
// the timeout elapses ("pending"). Returns immediately when there are no
// in-process subscribers (remote mode, API-level tests). Matching is exact:
// only rev's own outcome settles the wait, never a newer revision's (a newer
// "applied" must not mask this revision's failure and vice versa).
func (c *Center) WaitForApply(rev int64, timeout time.Duration) ApplyStatus {
	c.mu.RLock()
	n := len(c.subs)
	c.mu.RUnlock()
	if n == 0 {
		return ApplyStatus{Revision: rev, Status: "pending"}
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if st, ok := c.ApplyStatusFor(rev); ok {
			return st
		}
		time.Sleep(50 * time.Millisecond)
	}
	return ApplyStatus{Revision: rev, Status: "pending"}
}

// RevConfig returns the configuration snapshot stored for rev (read from the
// revision store; the active revision falls back to the in-memory copy).
func (c *Center) RevConfig(rev int64) (*config.Config, error) {
	raw, err := c.store.GetRevision(rev)
	if err == nil {
		var cfg config.Config
		if uerr := json.Unmarshal([]byte(raw), &cfg); uerr != nil {
			return nil, fmt.Errorf("configcenter: decode revision %d: %w", rev, uerr)
		}
		return &cfg, nil
	}
	if curRev, curCfg := c.Current(); curRev == rev && curCfg != nil {
		return curCfg, nil
	}
	return nil, fmt.Errorf("configcenter: revision %d not found", rev)
}

// Store exposes the underlying store (read-only usage by the API layer).
func (c *Center) Store() *store.Store { return c.store }

// Close closes the backing store.
func (c *Center) Close() error { return c.store.Close() }

// normalizeEmptyContainers returns a copy of v with empty maps and empty
// slices removed recursively, so "absent section" and "present but empty
// section" compare equal (they are behaviorally identical for the WAF).
func normalizeEmptyContainers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			nv := normalizeEmptyContainers(val)
			if isEmptyContainer(nv) {
				continue
			}
			out[k] = nv
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, val := range t {
			out = append(out, normalizeEmptyContainers(val))
		}
		return out
	default:
		return v
	}
}

// isEmptyContainer reports whether v is an empty map or an empty slice.
func isEmptyContainer(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	}
	return false
}
