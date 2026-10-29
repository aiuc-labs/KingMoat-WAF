package accesslog

import (
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestMaskPathTokenShapes pins the RC-2 judgment list: credential-shaped
// segments collapse onto "<masked>" while the path structure (and every
// benign segment) stays verbatim for forensics navigation.
func TestMaskPathTokenShapes(t *testing.T) {
	cases := []struct{ in, want string }{
		// --- masked shapes ---
		// Canonical UUID.
		{"/api/v1/users/6ba7b810-9dad-11d1-80b4-00c04fd430c8/profile", "/api/v1/users/<masked>/profile"},
		// 32+ hex (reset links, digests, session ids).
		{"/reset/deadbeefdeadbeefdeadbeefdeadbeef", "/reset/<masked>"},
		{"/verify/0123456789ABCDEF0123456789abcdef", "/verify/<masked>"},
		// 64 hex (sha256) still a single hex run.
		{"/h/" + strings.Repeat("a", 64), "/h/<masked>"},
		// Token wrapped as a download filename.
		{"/dl/0123456789abcdef0123456789abcdef.json", "/dl/<masked>"},
		// Three-segment JWT.
		{"/v1/chat/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			"/v1/chat/<masked>"},
		// sk- / bearer- / bearer%20 prefixed credentials.
		{"/keys/sk-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6", "/keys/<masked>"},
		{"/auth/bearer-eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig12345678", "/auth/<masked>"},
		{"/auth/bearer%20eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij", "/auth/<masked>"},
		// ≥24 base64url mixing upper+lower+digit.
		{"/files/a1B2c3D4e5F6g7H8i9J0k1L2", "/files/<masked>"},
		// ≥32 base64url containing a digit (lowercase random token).
		{"/t/abcdefghijklmnopabcdefghijklmnopqrstuvwxyz012345", "/t/<masked>"},
		// --- kept verbatim ---
		{"/api/v1/users/12345/profile", "/api/v1/users/12345/profile"}, // numeric ids
		{"/files/report.pdf", "/files/report.pdf"},                     // ordinary file names
		{"/search/2026-10-13", "/search/2026-10-13"},                   // dates
		{"/products/red-large-shirt", "/products/red-large-shirt"},     // words
		{"/health", "/health"},
		{"/releases/v2.0.1", "/releases/v2.0.1"},                           // versions
		{"/img/cdnCache123456.jpg", "/img/cdnCache123456.jpg"},             // 22 mixed chars: below the 24 floor
		{"/w/abcdefghijklmnop", "/w/abcdefghijklmnop"},                     // 16 lowercase-only: no digit/case mixing
		{"/w/ABCDEFGHIJKLMNOP", "/w/ABCDEFGHIJKLMNOP"},                     // 16 uppercase-only
		{"/x/deadbeef", "/x/deadbeef"},                                     // short hex
		{"/q/1'%20OR%20'1'='1", "/q/1'%20OR%20'1'='1"},                     // attack payload keeps verbatim (query/ua carry it too)
		{"/w/" + strings.Repeat("z", 40), "/w/" + strings.Repeat("z", 40)}, // long lowercase word without digits
		// Edge shapes.
		{"", ""},
		{"/", "/"},
		{"//", "//"},
		{"/a//b", "/a//b"},
	}
	for _, tc := range cases {
		if got := MaskPath(tc.in); got != tc.want {
			t.Errorf("MaskPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMaskPathLengthCapInteraction: masking runs before the stored-path cap
// in Write, and the masked output never exceeds the cap while staying valid
// UTF-8 (the mask only shortens).
func TestMaskPathLengthCapInteraction(t *testing.T) {
	long := "/u/" + strings.Repeat("a", 64) + "/" + strings.Repeat("b", 2000)
	got := MaskPath(long)
	got = truncateUTF8(got, maxStoredPathLen)
	if len(got) > maxStoredPathLen {
		t.Fatalf("masked+truncated length = %d, want <= %d", len(got), maxStoredPathLen)
	}
	if !strings.HasPrefix(got, "/u/<masked>/") {
		t.Fatalf("masked prefix lost: %q", got[:20])
	}
}

// TestMaskPathSurvivesHistory pins the store round-trip: a masked path lands
// as "<masked>" and reads back unchanged through History.
func TestMaskPathSurvivesHistory(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 64, true)
	e := entryAt("a.local", 0, "/reset/deadbeefdeadbeefdeadbeefdeadbeef")
	s.Write(e)
	if err := s.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	page, err := s.History(HistoryQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.Items[0].Path != "/reset/<masked>" {
		t.Fatalf("stored path = %+v, want /reset/<masked>", page.Items[0].Path)
	}
}
