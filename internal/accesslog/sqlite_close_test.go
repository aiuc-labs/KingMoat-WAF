package accesslog

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestSQLiteSinkWriteAfterCloseDropsSilently: a Write holding a sink
// reference that outlived Close (the in-flight request shape) must be a
// silent counted drop — never a send on a closed channel (H1).
func TestSQLiteSinkWriteAfterCloseDropsSilently(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 8, true)
	s.Write(entryAt("a.local", 0, "/before"))
	if err := s.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s.Write(entryAt("a.local", 0, "/after"))
	if s.Dropped() != 1 {
		t.Fatalf("dropped after close = %d, want 1 (post-close writes are counted drops)", s.Dropped())
	}
	// Close is idempotent: repeat calls return nil without touching the
	// already-closed channel again.
	if err := s.Close(); err != nil {
		t.Fatalf("repeat close must be a no-op, got %v", err)
	}
}

// TestSQLiteSinkCloseWriteRace hammers Write from several goroutines across
// a Close (the config-switch race the data plane hits on every recording
// toggle) and keeps writing after the close. Run with -count=20 to shake
// interleavings (no cgo on this host: no -race).
func TestSQLiteSinkCloseWriteRace(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 64}, 128, true)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s.Write(entryAt("a.local", 0, "/race"))
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	_ = s.Close()
	close(stop)
	wg.Wait()
	// One final write with the reference in hand: must not panic.
	s.Write(entryAt("a.local", 0, "/post"))
}

// TestSQLiteSinkNonWorkerWriteAfterClose: the worker-less test constructor
// path gets the same guard (closed flag checked even without close(ch)).
func TestSQLiteSinkNonWorkerWriteAfterClose(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all"}, 4, false)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s.Write(entryAt("a.local", 0, "/after"))
	if s.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", s.Dropped())
	}
}

// TestSQLiteSinkStartupMaintenancePurgesExpired: the reopen's asynchronous
// startup maintenance pass (L7) purges over-retention rows shortly after
// construction — without waiting for the 24h retention ticker.
func TestSQLiteSinkStartupMaintenancePurgesExpired(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "access-logs.db")
	old, err := newSQLiteSink(dbPath, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1, RetentionDays: 1}, 64, true, sinkLogger())
	if err != nil {
		t.Fatal(err)
	}
	old.Write(entryAt("a.local", 72, "/stale"))
	old.Write(entryAt("a.local", 0, "/fresh"))
	if err := old.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	fresh, err := NewSQLiteSink(dbPath, config.AccessLogRecordSettings{Mode: "all", RetentionDays: 1}, sinkLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows, rerr := fresh.Rows()
		if rerr == nil && rows == 1 {
			break // /fresh survived, /stale purged by the startup pass
		}
		if time.Now().After(deadline) {
			t.Fatalf("startup maintenance did not purge expired rows (rows=%d, err=%v)", rows, rerr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
