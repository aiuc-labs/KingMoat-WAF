package aisession

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// seedLegacyCentralDB creates the pre-dedup ai_sessions shape used by early
// v0.8.0-dev deployments (no node_id/boot_id/seq columns) plus one row.
func seedLegacyCentralDB(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE ai_sessions (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		ts_ms     INTEGER NOT NULL,
		site      TEXT NOT NULL DEFAULT '',
		provider  TEXT NOT NULL DEFAULT '',
		model     TEXT NOT NULL DEFAULT '',
		client_ip TEXT NOT NULL DEFAULT '',
		path      TEXT NOT NULL DEFAULT '',
		status    INTEGER NOT NULL DEFAULT 0,
		raw       TEXT NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO ai_sessions (ts_ms, site, raw) VALUES (1, 's.local', '{"legacy":true}')`); err != nil {
		t.Fatal(err)
	}
}

func TestCentralStoreMigratesLegacySchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ai.db")
	seedLegacyCentralDB(t, dbPath)

	cs, err := NewCentralStore(dbPath, nil)
	if err != nil {
		t.Fatalf("open legacy central db: %v", err)
	}
	defer cs.Close()

	// Legacy row survived the migration (Record fields rebuild from raw).
	_, total, err := cs.List(AIQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("legacy rows = %d, want 1", total)
	}

	// Dedup ingest works against the migrated table.
	r := AIWireSession{Seq: 1, Record: json.RawMessage(`{"n":1}`)}
	if n, err := cs.IngestBulk("node-a", "boot-1", []AIWireSession{r}); err != nil || n != 1 {
		t.Fatalf("ingest = %d, %v", n, err)
	}
	if n, err := cs.IngestBulk("node-a", "boot-1", []AIWireSession{r}); err != nil || n != 0 {
		t.Fatalf("replay = %d, %v, want 0 (dedup)", n, err)
	}
	if got := cs.Count(); got != 2 {
		t.Fatalf("count = %d, want 2 (legacy + new)", got)
	}
}

func TestCentralStoreFreshDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fresh.db")
	cs, err := NewCentralStore(dbPath, nil)
	if err != nil {
		t.Fatalf("open fresh db: %v", err)
	}
	defer cs.Close()
	if got := cs.Count(); got != 0 {
		t.Fatalf("fresh count = %d, want 0", got)
	}
}

func TestCentralStoreRejectsForeignSchema(t *testing.T) {
	// The AI assistant store shape (no raw column): must fail with a clear
	// error instead of ALTERing dedup columns onto a foreign table.
	dbPath := filepath.Join(t.TempDir(), "assistant.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE ai_sessions (
		id TEXT PRIMARY KEY,
		title TEXT NOT NULL DEFAULT '',
		owner TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, err = NewCentralStore(dbPath, nil)
	if err == nil {
		t.Fatal("foreign ai_sessions accepted, want error")
	}
}
