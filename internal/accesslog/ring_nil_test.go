package accesslog

import "testing"

// TestNilRingAndTeeWritesAreNoOps: nil receivers and nil Tee members must
// degrade to silent no-ops instead of panicking — defense in depth behind the
// compose-time fix for the typed-nil access sink (A-1): a mis-wired chain
// must never take down the data plane on the first request.
func TestNilRingAndTeeWritesAreNoOps(t *testing.T) {
	var ring *Ring
	ring.Write(&Entry{Path: "/x"})
	ring.Write(nil)
	if err := ring.Close(); err != nil {
		t.Fatalf("nil ring Close: %v", err)
	}

	var tee *Tee
	tee.Write(&Entry{Path: "/x"})
	tee.Write(nil)
	if err := tee.Close(); err != nil {
		t.Fatalf("nil tee Close: %v", err)
	}
	if tee.Dropped() != 0 || tee.Depth() != 0 {
		t.Fatalf("nil tee counters: dropped=%d depth=%d", tee.Dropped(), tee.Depth())
	}

	empty := NewTee(nil, nil)
	empty.Write(&Entry{Path: "/y"})
	empty.Write(nil)
	if err := empty.Close(); err != nil {
		t.Fatalf("tee(nil,nil) Close: %v", err)
	}
}
