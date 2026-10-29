package metrics

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestsBaseMergeAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics-state.json")

	// Seed a base as if a previous run had persisted 100 forwarded requests.
	if err := os.WriteFile(path, []byte(`{"forwarded":100,"blocked":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadRequestsBase(path)

	m := SnapshotRequests()
	if m["forwarded"] < 100 || m["blocked"] < 7 {
		t.Fatalf("base not merged: %+v", m)
	}

	// Persist loop writes base+live to the state file. cancel() alone does
	// NOT wait for the goroutine to exit: without <-done the loop (including
	// its shutdown flush) could still be writing this file when the next
	// -count iteration re-seeds it, and on Windows the still-open .tmp file
	// makes t.TempDir's RemoveAll cleanup fail the test. Waiting on done
	// makes the writer deterministically gone (its final flush completed)
	// before the reload below and before the TempDir cleanup runs.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() {
		cancel()
		<-done // also on the t.Fatal path: no writer may survive the test
	}()
	go func() {
		defer close(done)
		StartRequestsPersist(ctx, path, 50*time.Millisecond)
	}()
	time.Sleep(200 * time.Millisecond)

	// Read while the loop is running: within one iteration reqBase+live
	// only ever grows, so the file content is monotonic and the >=
	// assertions are race-free.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]int64
	if err := json.Unmarshal(b, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted["forwarded"] < 100 || persisted["blocked"] < 7 {
		t.Fatalf("persisted state lost counters: %+v", persisted)
	}
	cancel()
	<-done

	// Reload in a "new process": the base carries forward. After <-done no
	// writer exists and the file only grew since `persisted` was read, so a
	// regression that loses counters (e.g. persisting live counters without
	// the base) still fails this assertion; a regression that lets the
	// writer outlive the test would resurface as the TempDir cleanup race
	// on Windows.
	LoadRequestsBase(path)
	m2 := SnapshotRequests()
	if m2["forwarded"] < persisted["forwarded"] {
		t.Fatalf("reload dropped counters: %+v", m2)
	}
}

func TestLoadRequestsBaseMissingFile(t *testing.T) {
	before := SnapshotRequests()
	LoadRequestsBase(filepath.Join(t.TempDir(), "absent.json")) // must not panic
	after := SnapshotRequests()
	// Contract (LoadRequestsBase): a missing file is a fresh start — no base
	// is merged, so the snapshot must be exactly what it was before the call
	// (for a fresh process that is the zero-value counters; when a previous
	// test left a base behind, that base must survive untouched).
	if len(after) != len(before) {
		t.Fatalf("missing-file load changed the snapshot shape: before=%v after=%v", before, after)
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("missing-file load mutated counter %q: before=%d after=%d", k, v, after[k])
		}
	}
}
