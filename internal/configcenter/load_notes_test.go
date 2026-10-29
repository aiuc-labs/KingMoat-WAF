package configcenter

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestLoadNotesRecordedForLegacyRevision: a stored revision in the legacy
// v0.7.13 outbound shape records its load-time normalization facts on the
// center (same entries the WARN log carries), while the stored revision
// itself stays untouched (append-only).
func TestLoadNotesRecordedForLegacyRevision(t *testing.T) {
	c, err := Open(seedLegacyDB(t, v0713RevisionRaw), seedCfg(), quiet())
	if err != nil {
		t.Fatalf("legacy revision must boot: %v", err)
	}
	defer c.Close()

	notes := c.LoadNotes()
	if len(notes) == 0 {
		t.Fatal("a legacy revision must record load notes")
	}
	joined := strings.Join(notes, "; ")
	for _, want := range []string{
		"access_log: migrated flat s3 fields into the s3 block",
		"log_shipper: synthesized a default syslog block (transport from url scheme, rfc5424)",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("load notes missing %q: %v", want, notes)
		}
	}

	stRaw, err := c.Store().GetRevision(1)
	if err != nil {
		t.Fatal(err)
	}
	if stRaw != v0713RevisionRaw {
		t.Fatal("recording load notes must not rewrite the stored revision")
	}
}

// TestLoadNotesRecordedForDegradedSeed: a seed whose outbound section is
// unshippable as configured is degraded at load and the degradation entry —
// carrying the original validation error — surfaces in the notes.
func TestLoadNotesRecordedForDegradedSeed(t *testing.T) {
	seed := seedCfg()
	seed.AccessLog = &config.AccessLogSettings{Enabled: true, Type: "s3"} // no s3 block
	c, err := Open(t.TempDir()+"/cc.db", seed, quiet())
	if err != nil {
		t.Fatalf("degraded seed must boot: %v", err)
	}
	defer c.Close()

	joined := strings.Join(c.LoadNotes(), "; ")
	if !strings.Contains(joined, "access_log: disabled (unshippable as configured: ") {
		t.Fatalf("load notes must carry the degradation entry, got %q", joined)
	}
	if !strings.Contains(joined, "type s3 requires the s3 block") {
		t.Fatalf("degradation entry must carry the original error, got %q", joined)
	}
}

// TestCleanLoadLeavesNoNotes: a compliant seed produces no notes (the status
// field is omitted for clean loads).
func TestCleanLoadLeavesNoNotes(t *testing.T) {
	c, err := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if notes := c.LoadNotes(); notes != nil {
		t.Fatalf("clean load must leave no notes, got %v", notes)
	}
}

// TestPublishClearsLoadNotesFailureKeeps: a successful publish replaces the
// notes with none (the new revision passed strict validation); a FAILED
// publish keeps the previously active revision's notes.
func TestPublishClearsLoadNotesFailureKeeps(t *testing.T) {
	c, err := Open(seedLegacyDB(t, v0713RevisionRaw), seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if len(c.LoadNotes()) == 0 {
		t.Fatal("precondition: the legacy boot must have recorded notes")
	}

	bad := seedCfg()
	bad.LogShipper = &config.ShipperSettings{Type: "kafka", Topic: "t"} // publish-time rejection
	if _, err := c.Publish(bad, "t", "bad"); err == nil {
		t.Fatal("publish must fail for the unshippable log_shipper")
	}
	if len(c.LoadNotes()) == 0 {
		t.Fatal("a failed publish must keep the active revision's load notes")
	}

	if _, err := c.Publish(twoSiteCfg(), "t", "clean"); err != nil {
		t.Fatal(err)
	}
	if notes := c.LoadNotes(); notes != nil {
		t.Fatalf("a successful publish must clear the load notes, got %v", notes)
	}
}

// TestOpenBootsFlatAIShipS3: ai_audit.ship in the deprecated flat s3 form
// (type "s3" + flat prefix/use_ssl, no nested block) boots ENABLED with the
// values migrated into the nested s3 block (the runtime fallback would have
// seeded them, but Validate would have degraded the section), and the
// migration is reported in the load notes. Stored revision untouched.
func TestOpenBootsFlatAIShipS3(t *testing.T) {
	raw := `{"listen_http":":8080","sites":[{"domains":["a.local"],"upstream":{"nodes":[{"address":"127.0.0.1:9001"}]}}],
		"ai_audit":{"ship":{"enabled":true,"type":"s3","index":"kingmoat_ai_sessions",
			"endpoint":"minio.internal:9000","bucket":"ai-logs","prefix":"kingmoat/ai","use_ssl":true}}}`
	c, err := Open(seedLegacyDB(t, raw), seedCfg(), quiet())
	if err != nil {
		t.Fatalf("flat ai_audit.ship must boot: %v", err)
	}
	defer c.Close()

	_, cfg := c.Current()
	ship := cfg.AiAudit.Ship
	if ship == nil || !ship.Enabled {
		t.Fatalf("ship must stay enabled, got %+v", ship)
	}
	if ship.S3 == nil || ship.S3.Endpoint != "minio.internal:9000" || ship.S3.Bucket != "ai-logs" ||
		ship.S3.Prefix != "kingmoat/ai" || !ship.S3.UseSSL {
		t.Fatalf("migrated s3 block wrong: %+v", ship.S3)
	}
	if !strings.Contains(strings.Join(c.LoadNotes(), "; "), "ai_audit.ship: migrated flat s3 fields into the s3 block") {
		t.Fatalf("migration must be recorded in the load notes: %v", c.LoadNotes())
	}
	stRaw, err := c.Store().GetRevision(1)
	if err != nil {
		t.Fatal(err)
	}
	if stRaw != raw {
		t.Fatal("stored revision must not be rewritten in place")
	}
}

// TestRollbackRecordsLoadNotes: rolling back to a pre-strictness revision
// normalizes its legacy shapes into the new revision; that normalization is
// the load-time fact of the now-active config and is recorded — while a
// failed rollback leaves the previously active revision's notes untouched.
func TestRollbackRecordsLoadNotes(t *testing.T) {
	c, err := Open(seedLegacyDB(t, v0713RevisionRaw), seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.Publish(twoSiteCfg(), "t", "v2 strict"); err != nil {
		t.Fatal(err)
	}
	if notes := c.LoadNotes(); notes != nil {
		t.Fatalf("the strict publish must clear the notes, got %v", notes)
	}

	newRev, err := c.Rollback(1, "admin")
	if err != nil {
		t.Fatalf("rollback to the legacy revision must succeed: %v", err)
	}
	joined := strings.Join(c.LoadNotes(), "; ")
	if !strings.Contains(joined, "access_log: migrated flat s3 fields into the s3 block") {
		t.Fatalf("rollback normalization must be recorded, got %q", joined)
	}

	// The rolled-back revision stores the normalized form (as before), so a
	// fresh boot over it must come up clean — the notes pipeline stays
	// boot-scoped and must not grow stale entries across restarts.
	stRaw, err := c.Store().GetRevision(newRev)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stRaw, `"s3":{`) {
		t.Fatalf("rollback revision must store the normalized form: %s", stRaw)
	}
}

// TestRollbackLoadNotesAtomicWithConcurrentPublish: the notes a rollback
// records and the notes a concurrent successful publish clears are written
// in ONE critical section (publishInternal's success path), so the active
// (rev, config, loadNotes) triple is always set atomically: the notes can
// never linger as a stale rollback fact on top of a newer, strictly-validated
// published revision (the console reads load_notes via /api/status).
//
// The interleave window itself cannot be deterministically hit in a test
// (no injectable hook between the old publish return and the old post-hoc
// lock section, and -race is unavailable on this platform): this test
// interleaves both writers and asserts the pairing invariant — notes must
// always match the revision that actually landed last — which the old
// two-phase write violated whenever the scheduler hit the window.
func TestRollbackLoadNotesAtomicWithConcurrentPublish(t *testing.T) {
	c, err := Open(seedLegacyDB(t, v0713RevisionRaw), seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Baseline: a clean, strictly-validated publish leaves no notes, so any
	// note observed after the interleaved run must come from that run.
	if _, err := c.Publish(twoSiteCfg(), "t", "clean baseline"); err != nil {
		t.Fatal(err)
	}
	if notes := c.LoadNotes(); notes != nil {
		t.Fatalf("precondition: baseline publish must clear the notes, got %v", notes)
	}

	const rounds = 64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // publisher: always a clean, strictly-validated config
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			cfg := twoSiteCfg()
			cfg.Sites[0].Domains = []string{"pub.local"}
			cfg.Sites[1].Domains = []string{fmt.Sprintf("pub%d.local", i)} // distinct per round: every publish lands a new revision
			if _, err := c.Publish(cfg, "t", "concurrent clean publish"); err != nil {
				t.Errorf("concurrent publish failed: %v", err)
				return
			}
		}
	}()
	go func() { // rollbacker: always lands the legacy revision (normalization entries non-empty)
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if _, err := c.Rollback(1, "t"); err != nil {
				t.Errorf("concurrent rollback failed: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	rev, cfg := c.Current()
	notes := c.LoadNotes()
	isPublished := false
	for _, s := range cfg.Sites {
		for _, d := range s.Domains {
			if d == "pub.local" {
				isPublished = true
			}
		}
	}
	if isPublished {
		// The last landed revision is a strict publish: its load facts are none.
		if notes != nil {
			t.Fatalf("rev %d: stale rollback notes survive a concurrent publish: %v", rev, notes)
		}
		return
	}
	// Otherwise the last landed revision is a rollback of the legacy revision:
	// its own normalization entries must be the notes.
	joined := strings.Join(notes, "; ")
	if !strings.Contains(joined, "access_log: migrated flat s3 fields into the s3 block") {
		t.Fatalf("rev %d: rollback notes missing after the concurrent run: %q", rev, joined)
	}
}
