package accesslog

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestMaskQuerySensitiveKeys pins the sensitive-key hit matrix: case and
// -/_ separator variants, URL-encoded key variants, repeated keys — every
// sensitive value must come back as "***" with the raw key spelling kept.
func TestMaskQuerySensitiveKeys(t *testing.T) {
	cases := []struct{ in, want string }{
		// token family (incl. short aliases).
		{"token=abc", "token=***"},
		{"Token=abc", "Token=***"},
		{"ACCESS_TOKEN=abc&x=1", "ACCESS_TOKEN=***&x=1"},
		{"refresh_token=abc", "refresh_token=***"},
		{"at=abc&tt=xyz", "at=***&tt=***"},
		// password family.
		{"password=hunter2", "password=***"},
		{"PASSWD=x", "PASSWD=***"},
		{"pwd=x", "pwd=***"},
		{"user_password=x", "user_password=***"},
		// secret / api key / access key family.
		{"secret=x", "secret=***"},
		{"secret_key=x", "secret_key=***"},
		// bare "key" is the most common short API-key parameter name (R3-02).
		{"key=a1b2c3d4", "key=***"},
		{"KEY=x&k=abc", "KEY=***&k=***"}, // exact set incl. the k single-letter shorthand
		{"api_key=x", "api_key=***"},
		{"api-key=x", "api-key=***"},
		{"apikey=x", "apikey=***"},
		{"access_key=x", "access_key=***"},
		{"accesskey=x", "accesskey=***"},
		{"client_secret=x", "client_secret=***"},
		// session family.
		{"session=x", "session=***"},
		{"session_id=x", "session_id=***"},
		{"sessionId=x", "sessionId=***"},
		{"sid=x", "sid=***"},
		{"phpsessid=x", "phpsessid=***"},
		// sign family.
		{"sign=x", "sign=***"},
		{"signature=x", "signature=***"},
		{"sig=x", "sig=***"},
		// auth family.
		{"auth=x", "auth=***"},
		{"authorization=Basic abc", "authorization=***"},
		// otp / code / verify.
		{"otp=123456", "otp=***"},
		{"code=xyz", "code=***"},
		{"verify=1", "verify=***"},
		{"verify_code=9", "verify_code=***"},
		// personal identifiers.
		{"ssn=x", "ssn=***"},
		{"idcard=x", "idcard=***"},
		{"id_card=x", "id_card=***"},
		{"phone=13800000000", "phone=***"},
		{"mobile=13800000000", "mobile=***"},
		{"tel=123", "tel=***"},
		{"email=a@b.c", "email=***"},
		{"mail=a@b.c", "mail=***"},
		// URL-encoded key variants (decoded key matches, raw spelling kept).
		{"%61pi_key=x", "%61pi_key=***"},
		{"API%2DKEY=x", "API%2DKEY=***"},
		// repeated keys: every occurrence masked.
		{"token=a&token=b", "token=***&token=***"},
		// mixed shapes.
		{"a=1&token=x&b=2", "a=1&token=***&b=2"},
	}
	for _, tc := range cases {
		if got := MaskQuery(tc.in); got != tc.want {
			t.Errorf("MaskQuery(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMaskQueryPreservesBenignValues: non-sensitive business parameters keep
// their verbatim values (forensics value), empty-value and bare keys carry
// nothing to leak and stay as-is.
func TestMaskQueryPreservesBenignValues(t *testing.T) {
	cases := []struct{ in, want string }{
		{"page=2&size=10", "page=2&size=10"},
		{"q=SELECT * FROM t&order=id", "q=SELECT * FROM t&order=id"},
		{"q=alert(1)&src=反射", "q=alert(1)&src=反射"},
		{"token=", "token="},                                   // empty value: nothing to leak
		{"flag&x=1", "flag&x=1"},                               // bare key inside a parseable query
		{"statuscode=200&state=ok", "statuscode=200&state=ok"}, // substring safety
		{"countrycode=86&design=1", "countrycode=86&design=1"}, // exact-match keys only
		{"postcode=100123&size=1", "postcode=100123&size=1"},   // substring safety
		{"", ""},
	}
	for _, tc := range cases {
		if got := MaskQuery(tc.in); got != tc.want {
			t.Errorf("MaskQuery(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMaskQueryMalformed: a query that cannot be parsed as key=value pairs
// takes the conservative path — truncated and masked as a whole.
func TestMaskQueryMalformed(t *testing.T) {
	for _, in := range []string{"no-equals-shape", "%%", "%zz%zz", "&&&"} {
		if got := MaskQuery(in); got != maskedQueryValue {
			t.Errorf("MaskQuery(%q) = %q, want the whole-input mask %q", in, got, maskedQueryValue)
		}
	}
}

// TestMaskQueryLengthCap: the masked output never exceeds the stored cap.
// The input is pre-truncated (poison-long queries cannot burn the parse
// budget; content beyond the cap is discarded whole — nothing leaks), the
// cap is re-applied AFTER masking (S-11: masking can lengthen the text),
// truncation never splits a UTF-8 rune, and a sensitive parameter inside
// the cap still gets masked.
func TestMaskQueryLengthCap(t *testing.T) {
	long := "token=secretvalue&" + strings.Repeat("a=x&", 600) // token inside the cap
	got := MaskQuery(long)
	if len(got) > maxStoredQueryLen {
		t.Fatalf("masked length = %d, want <= %d", len(got), maxStoredQueryLen)
	}
	if !strings.HasPrefix(got, "token=***") {
		t.Fatalf("in-cap sensitive parameter must be masked, got %q", got[:20])
	}

	tailSensitive := strings.Repeat("a=x&", 600) + "token=secretvalue" // token beyond the cap
	got = MaskQuery(tailSensitive)
	if len(got) > maxStoredQueryLen {
		t.Fatalf("masked length = %d, want <= %d", len(got), maxStoredQueryLen)
	}
	if strings.Contains(got, "secretvalue") {
		t.Fatal("content beyond the cap must not survive the truncate-then-mask order")
	}

	multibyte := strings.Repeat("中", 700) // 2100 bytes, rune boundary at 2048 splits it
	got = MaskQuery(multibyte)
	if !utf8.ValidString(got) {
		t.Fatalf("truncation produced invalid UTF-8: %q", got)
	}
	if len(got) > maxStoredQueryLen {
		t.Fatalf("multibyte truncation length = %d, want <= %d", len(got), maxStoredQueryLen)
	}
}

// TestMaskQueryCapAfterMasking pins the S-11 order: masking LENGTHENS each
// masked chunk (t=1 → t=***), so enough short sensitive parameters push the
// MASKED text past the stored cap even though the raw window fits it — the
// old truncate-then-mask order stored ~1.25× the cap. 600 chunks (not
// fewer): a smaller set stays under the cap either way and could not pin
// the order.
func TestMaskQueryCapAfterMasking(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 600; i++ {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString("t=")
		b.WriteString(itoa(i))
	}
	got := MaskQuery(b.String())
	if len(got) > maxStoredQueryLen {
		t.Fatalf("masked length = %d, want <= %d (the cap must hold AFTER masking)", len(got), maxStoredQueryLen)
	}
	if !utf8.ValidString(got) {
		t.Fatal("masked output must stay valid UTF-8")
	}
	if !strings.Contains(got, "t=***") {
		t.Fatal("in-cap sensitive parameters must stay masked")
	}
}

// TestTruncateUTF8: byte-exact cap, no split runes, no-op below the cap.
func TestTruncateUTF8(t *testing.T) {
	s := strings.Repeat("中", 10) // 30 bytes
	if got := truncateUTF8(s, 100); got != s {
		t.Fatalf("below-cap input must stay intact")
	}
	got := truncateUTF8(s, 16) // splits the 6th rune (bytes 15..17)
	if len(got) != 15 {
		t.Fatalf("truncated length = %d, want 15 (walked back to the rune boundary)", len(got))
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncated string must stay valid UTF-8")
	}
	if got := truncateUTF8("abc", 0); got != "" {
		t.Fatalf("max=0 must yield empty, got %q", got)
	}
}

// TestMaskQueryBypassMatrix pins the RC-1 hardening: every confirmed bypass
// shape now hits — double percent-encoding (bounded to 2 decode rounds),
// semicolon-separated legacy backends, the bare pass family, over-long keys
// and Unicode homoglyph/fullwidth variants — while the raw key spelling is
// preserved in the stored text.
func TestMaskQueryBypassMatrix(t *testing.T) {
	cases := []struct{ in, want string }{
		// ① double percent-encoding: two decode rounds reach the real key.
		{"%2561pi_key=SECRET", "%2561pi_key=***"},
		{"%2574oken=SECRET", "%2574oken=***"},
		// Triple encoding is OUT of threat scope (needs a backend decoding a
		// request three times): the decode round cap keeps it verbatim — an
		// accepted boundary, documented here so it stays a decision.
		{"%252570ass=SECRET", "%252570ass=SECRET"},
		// ② semicolon-separated legacy backends.
		{"x=1;token=SECRET", "x=1;token=***"},
		{"token=SECRET;x=1", "token=***;x=1"},
		{"a=1;pwd=hunter2;b=2", "a=1;pwd=***;b=2"},
		{"x=1;;api_key=SECRET;;y=2", "x=1;;api_key=***;;y=2"},
		// ③ bare pass family (no longer carrier substring exists).
		{"userpass=abc", "userpass=***"},
		{"newpass=abc", "newpass=***"},
		{"passphrase=abc", "passphrase=***"},
		{"pass1=abc", "pass1=***"},
		{"passwd2=abc", "passwd2=***"},
		{"connectsid=abc123", "connectsid=***"},
		// ④ over-long keys (beyond the former 64-byte gate) still match.
		{strings.Repeat("x", 100) + "token=SECRET", strings.Repeat("x", 100) + "token=***"},
		{strings.Repeat("pad_", 40) + "api_key=SECRET", strings.Repeat("pad_", 40) + "api_key=***"},
		// ⑤ Unicode homoglyphs and fullwidth folding.
		{"tоken=SECRET", "tоken=***"},      // Cyrillic о
		{"passwоrd=x", "passwоrd=***"},     // Cyrillic о inside password
		{"secret_κey=x", "secret_κey=***"}, // Greek κ → k
		{"ＡＰＩ_ＫＥＹ=x", "ＡＰＩ_ＫＥＹ=***"},       // fullwidth ASCII block
		// Mixed shapes.
		{"page=2;%2561pi_key=SECRET&q=ok", "page=2;%2561pi_key=***&q=ok"},
	}
	for _, tc := range cases {
		if got := MaskQuery(tc.in); got != tc.want {
			t.Errorf("MaskQuery(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// Stored text stays valid UTF-8 after masking (排障可读; the raw key
	// spelling is preserved, only values are replaced).
	for _, tc := range cases {
		if !utf8.ValidString(tc.want) {
			t.Errorf("masked output for %q is not valid UTF-8", tc.in)
		}
	}
}

// TestMaskQueryPassSubstringTradeoff pins the DELIBERATE false-positive set
// the "pass" substring family introduces (RC-1 ③, 宁掩勿漏): benign
// pass-carrying words lose their value — accepted coverage trade-off, kept
// visible here so a future key-shape refinement re-decides it consciously.
func TestMaskQueryPassSubstringTradeoff(t *testing.T) {
	for _, k := range []string{"compass", "passport", "bypass", "surpass", "passthrough"} {
		in := k + "=value"
		if got := MaskQuery(in); got != k+"=***" {
			t.Errorf("MaskQuery(%q) = %q, want the accepted false-positive mask %q", in, got, k+"=***")
		}
	}
}

// TestMaskQuerySingleLetterKeys pins the R3-02 single-character closure.
// Layer 1: the k/p/t exact set masks unconditionally — 宁掩勿漏, ?p=hunter2 IS
// a plaintext password; the ?p=2 page-number false positive is ACCEPTED,
// same trade-off as the "pass" substring family (compass/passport), kept
// visible here so it stays a conscious decision. Layer 2: every other
// single-letter key is judged by VALUE SHAPE only (the pathmask judgment
// list) — random-token values mask, ordinary short values don't.
func TestMaskQuerySingleLetterKeys(t *testing.T) {
	cases := []struct{ in, want string }{
		// Layer 1: exact single-letter credential set (k/p/t).
		{"k=a1b2c3d4", "k=***"},
		{"p=hunter2", "p=***"},
		{"t=r4nd0m-t0k3n", "t=***"},
		{"K=x&P=hunter2&T=y", "K=***&P=***&T=***"}, // case variants
		{"%70=hunter2", "%70=***"},                 // encoded key (%70 = p)
		{"p=2", "p=***"},                           // accepted page-number false positive
		// Layer 2: other single-letter keys, value-shape judged.
		{"s=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8", "s=***"},              // 40-hex digest
		{"s=SK-abcdef0123456789", "s=***"},                               // sk- prefixed credential
		{"x=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "x=***"}, // three-segment JWT
		{"u=550e8400-e29b-41d4-a716-446655440000", "u=***"},              // canonical UUID
		{"s=%73%6B%2Dabcdef0123456789", "s=***"},                         // percent-encoded sk- value
		// Layer 2 negatives: ordinary short values stay verbatim.
		{"s=hello", "s=hello"},
		{"q=hello", "q=hello"},
		{"id=7", "id=7"},
		{"m=abc", "m=abc"},
		{"n=2&v=1.2.3", "n=2&v=1.2.3"},
		// Empty values carry nothing to leak (k/p/t included).
		{"p=", "p="},
		{"t=", "t="},
		{"k=", "k="},
	}
	for _, tc := range cases {
		if got := MaskQuery(tc.in); got != tc.want {
			t.Errorf("MaskQuery(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMaskedQuerySurvivesHistory: a masked query round-trips through the
// store (written → committed → History) unchanged and stays valid UTF-8, so
// the masked text the operator sees is exactly what was stored.
func TestMaskedQuerySurvivesHistory(t *testing.T) {
	s := newTestSink(t, config.AccessLogRecordSettings{Mode: "all", BatchSize: 1}, 64, true)
	e := entryAt("a.local", 0, "/login")
	e.Query = "%2561pi_key=SECRET;userpass=p%40ss&join=1&mobile=13800000000"
	want := MaskQuery(e.Query)
	if !utf8.ValidString(want) {
		t.Fatalf("masked query is not valid UTF-8: %q", want)
	}
	if !strings.Contains(want, maskedQueryValue) || strings.Contains(want, "SECRET") {
		t.Fatalf("masking did not replace the sensitive values: %q", want)
	}
	s.Write(e)
	if err := s.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	page, err := s.History(HistoryQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("history = %d/%d, want 1/1", page.Total, len(page.Items))
	}
	if got := page.Items[0].Query; got != want {
		t.Fatalf("stored query = %q, want the masked text %q", got, want)
	}
	if !utf8.ValidString(page.Items[0].Query) {
		t.Fatal("stored query must stay valid UTF-8")
	}
}

// TestMaskQueryShortAbbrevKeys pins the R-4 short-key closure: the
// abbreviation shorthands pw/pwd/tok/sess join the exact sensitive set, and
// the value-shape judgment widens from single-letter to ≤3-letter keys —
// random-token values behind short non-sensitive names must not land in
// clear text, while ordinary short values (id=42, lang=zh) stay verbatim
// (the ≥16-byte shape floor bounds the false-positive surface).
func TestMaskQueryShortAbbrevKeys(t *testing.T) {
	cases := []struct{ in, want string }{
		// Exact abbreviation set (case and encoded-key variants included).
		{"pw=hunter2", "pw=***"},
		{"pw=a1b2c3d4e5f6a7b8", "pw=***"},
		{"tok=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "tok=***"},
		{"sess=a1b2c3d4e5f6a7b8c9d0", "sess=***"},
		{"sid=a1b2c3d4e5f6a7b8c9d0e1f2a3b4", "sid=***"}, // long-held exact key, pinned alongside the new ones
		{"PW=x&TOK=y&SESS=z", "PW=***&TOK=***&SESS=***"},
		{"t%6Fk=SECRET", "t%6Fk=***"}, // encoded key (decodes to tok)
		// Shape judgment widened to ≤3-letter keys: credential-shaped values
		// behind short non-sensitive names mask (宁掩勿漏).
		{"id=550e8400-e29b-41d4-a716-446655440000", "id=***"},    // canonical UUID behind a 2-letter key
		{"xyz=SK-abcdef0123456789", "xyz=***"},                   // sk- prefixed value behind a 3-letter key
		{"wxyz=SK-abcdef0123456789", "wxyz=SK-abcdef0123456789"}, // 4 letters: beyond the short-key window
		// Ordinary short values stay verbatim (shape-floor negatives).
		{"id=42", "id=42"},
		{"q=hello", "q=hello"},
		{"lang=zh", "lang=zh"},
		{"xyz=a1b2c3d4", "xyz=a1b2c3d4"}, // 8-byte run is below the ≥16-byte shape floor
		// Empty values carry nothing to leak.
		{"pw=", "pw="},
	}
	for _, tc := range cases {
		if got := MaskQuery(tc.in); got != tc.want {
			t.Errorf("MaskQuery(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
