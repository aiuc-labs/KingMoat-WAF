// Outbound-section change detection for the hot-reload rebuilders: publish
// handlers resend the whole configuration on every save, and most saves touch
// a site or a policy rule — the outbound sections (audit webhook, log
// shipper, access-log pipeline, AI session ship) ride along byte-identical.
// Rebuilding them anyway would tear down and re-dial healthy outbound
// connections on every unrelated publish; the trackers below make each
// rebuilder compare the section it is about to apply against the snapshot
// its CURRENT instance was built from and skip the rebuild when they are
// deep-equal.
//
// The stored snapshot is the section the current instance was built from.
// For the webhook and the audit log shipper that is the section pointer from
// the applied config revision; the access-log pipeline and the AI session
// ship store the RESOLVED effective section (config.ResolveAccessOut /
// config.ResolveAIShipOut) so that
// use_audit_channel channel reuse rides the same change detection: a
// log_shipper channel change flows into the resolved section (rebuild), a
// change to the section's own channel fields while the switch is on does not
// (skip). A preflight audit verified that no code path mutates these
// sections in place after apply (the established in-place mutation patterns
// touch only Policy / AI / Sites, which no outbound tracker observes), and
// the comparison is by deep value equality anyway.
package main

import (
	"reflect"
	"sync/atomic"
)

// sectionTracker remembers the outbound-section snapshot the CURRENT
// pipeline instance was built from. Atomic so the boot build and the
// config-center consumer cannot race (publishes are serialized by the
// consume loop in practice).
type sectionTracker[T any] struct {
	applied atomic.Pointer[T]
}

// unchanged reports whether next is deep-equal to the section snapshot the
// current instance was built from. Two nils are unchanged (the outbound is
// absent from both revisions); exactly one nil is a change (enable or
// remove).
func (t *sectionTracker[T]) unchanged(next *T) bool {
	prev := t.applied.Load()
	if prev == nil || next == nil {
		return prev == next
	}
	return reflect.DeepEqual(*prev, *next)
}

// seed records the section the boot-time instance was built from. The boot
// builds for webhook/shipper/AI go through their rebuilders and seed on the
// first call; the access-log boot build is inline (rebuildAccess is not
// called at boot), so main seeds that tracker in the boot success branch.
func (t *sectionTracker[T]) seed(next *T) {
	t.applied.Store(next)
}
