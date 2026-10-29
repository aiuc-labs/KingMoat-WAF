package configcenter

import (
	"strings"
	"sync"
	"testing"
)

// TestAppendLoadNoteRevGuard: the data-plane degradation note lands only
// while the active revision is still the one the note belongs to — a
// concurrent newer publish voids it (no stale facts on a newer revision),
// and a successful publish clears previously appended notes (same critical
// section / same semantics as publishInternal's own notes write).
func TestAppendLoadNoteRevGuard(t *testing.T) {
	c, err := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rev, _ := c.Current()

	if !c.AppendLoadNote(rev, "访问日志本地记录应用失败，已保持上一配置（测试条目）") {
		t.Fatal("append against the active revision must land")
	}
	joined := strings.Join(c.LoadNotes(), "; ")
	if !strings.Contains(joined, "访问日志本地记录应用失败") {
		t.Fatalf("note must surface via LoadNotes, got %q", joined)
	}

	// A note scoped to a FUTURE revision is void while rev is not active.
	if c.AppendLoadNote(rev+1, "stale future note") {
		t.Fatal("append against a non-active revision must be rejected")
	}
	if strings.Contains(strings.Join(c.LoadNotes(), "; "), "stale future note") {
		t.Fatal("rejected note must not surface")
	}

	// A note scoped to an ALREADY-SUPERSEDED revision is void too.
	next := twoSiteCfg()
	if _, err := c.Publish(next, "t", "bump revision"); err != nil {
		t.Fatal(err)
	}
	if c.AppendLoadNote(rev, "stale old note") {
		t.Fatal("append against the superseded revision must be rejected")
	}
	// The successful publish cleared the earlier appended note.
	if notes := c.LoadNotes(); notes != nil {
		t.Fatalf("a successful publish must clear appended notes, got %v", notes)
	}

	// Interleaved appends and publishes: notes never survive on a newer
	// revision they do not belong to.
	newRev, _ := c.Current()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 32; i++ {
			c.AppendLoadNote(newRev, "访问日志本地记录应用失败（并发写者）")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 32; i++ {
			cfg := twoSiteCfg()
			cfg.Sites[0].Domains = []string{"apn.local"}
			if _, err := c.Publish(cfg, "t", "concurrent"); err != nil {
				return // last publish may race our reads; not the invariant here
			}
		}
	}()
	wg.Wait()
	finalRev, _ := c.Current()
	for _, n := range c.LoadNotes() {
		if strings.Contains(n, "并发写者") && finalRev != newRev {
			t.Fatalf("stale failure note %q survived on newer revision %d", n, finalRev)
		}
	}
}
