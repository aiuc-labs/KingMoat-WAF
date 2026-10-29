package api

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/metrics"
)

type statsBytesPair struct {
	Down int64 `json:"down"`
	Up   int64 `json:"up"`
}

// TestStatsBytesRangeAndRetention verifies the bytes node of /api/stats:
// per-site down/up totals follow the same ?days= calendar window as the
// request cards — days=1 keeps only today (live daily series, superseding
// the stale folded entry), wider ranges add the folded history days and
// days beyond the window stay out.
func TestStatsBytesRangeAndRetention(t *testing.T) {
	metrics.ResetDailyForTest()
	t.Cleanup(metrics.ResetDailyForTest)

	writeHist := func(hist map[string]map[string]int64) string {
		t.Helper()
		b, err := json.Marshal(hist)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "bytes_history.json")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	metrics.LoadBytesHistory(writeHist(map[string]map[string]int64{
		time.Now().Format("2006-01-02"):                   {"a.local\x00down": 111, "a.local\x00up": 22}, // today: superseded by the live snapshot
		time.Now().AddDate(0, 0, -1).Format("2006-01-02"): {"a.local\x00down": 1000, "a.local\x00up": 200, "b.local\x00down": 3000},
		time.Now().AddDate(0, 0, -40).Format("2006-01-02"): {"a.local\x00down": 500000}, // beyond the widest window
	}))
	// Live daily bytes for today.
	metrics.SiteBytesInc("a.local", 7, 3)
	metrics.SiteBytesInc("quiet.local", 0, 5)

	s, _ := newPerSiteServer(t)

	read := func(days int) (sites map[string]statsBytesPair, total statsBytesPair) {
		rec := httptest.NewRecorder()
		s.handleStats(rec, httptest.NewRequest("GET", "/api/stats?days="+strconv.Itoa(days), nil))
		if rec.Code != 200 {
			t.Fatalf("status = %d", rec.Code)
		}
		var out struct {
			Bytes struct {
				Sites map[string]statsBytesPair `json:"sites"`
				Total statsBytesPair            `json:"total"`
			} `json:"bytes"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Bytes.Sites, out.Bytes.Total
	}

	today, total1 := read(1)
	if got := today["a.local"]; got.Down != 7 || got.Up != 3 {
		t.Fatalf("days=1 a.local bytes wrong: %+v (want live snapshot, not the stale fold 111/22)", got)
	}
	if total1.Down != 7 || total1.Up != 8 {
		t.Fatalf("days=1 total bytes wrong: %+v (a.local 7/3 + quiet.local 0/5)", total1)
	}

	week, total7 := read(7)
	if got := week["a.local"]; got.Down != 1007 || got.Up != 203 {
		t.Fatalf("days=7 a.local bytes wrong: %+v", got)
	}
	if got := week["b.local"]; got.Down != 3000 || got.Up != 0 {
		t.Fatalf("days=7 b.local bytes wrong: %+v", got)
	}
	if got := week["quiet.local"]; got.Down != 0 || got.Up != 5 {
		t.Fatalf("days=7 quiet.local bytes wrong: %+v", got)
	}
	if total7.Down != 1007+3000 || total7.Up != 203+5 {
		t.Fatalf("days=7 total bytes wrong: %+v", total7)
	}

	// days=30 must not pull the 40-day-old entry (window filter).
	month, total30 := read(30)
	if got := month["a.local"]; got.Down != 1007 || got.Up != 203 {
		t.Fatalf("days=30 must exclude the 40-day-old entry: %+v", got)
	}
	if total30.Down != 1007+3000 || total30.Up != 203+5 {
		t.Fatalf("days=30 total bytes wrong: %+v", total30)
	}
}
