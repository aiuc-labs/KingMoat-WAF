package stages

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Round-trip contract for the captcha challenge token: hexI emits an
// even-width hex segment per field, fields are delimiter-separated and the
// verifier decodes each segment independently — so zero-padding one field
// must never shift the others. The sweep covers the full gap domain
// 0..512, including the 256..259 range that originally produced odd-length
// hex and undecodable tokens (~1.6% of challenges), so a future width
// change cannot silently break alignment again.
func TestCaptchaChallengeTokenRoundTrip(t *testing.T) {
	site := &captchaSite{secret: []byte("round-trip-secret"), cookie: "cap", ttl: 5 * time.Minute, tol: 3}
	exp := time.Now().Add(5 * time.Minute).Unix()
	for gap := 0; gap <= 512; gap++ {
		token := hexI(int64(gap)) + "." + hexI(exp) + "." +
			hex.EncodeToString(site.sign("chal|"+strconv.Itoa(gap)+"|"+strconv.FormatInt(exp, 10)))
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("gap %d: token split = %d parts", gap, len(parts))
		}
		gapTok, ok := hexVal(parts[0])
		if !ok {
			t.Fatalf("gap %d: gap segment undecodable (%q)", gap, parts[0])
		}
		if int(gapTok) != gap {
			t.Fatalf("gap %d: decoded back as %d", gap, gapTok)
		}
		expTok, ok := hexVal(parts[1])
		if !ok || expTok != exp {
			t.Fatalf("gap %d: exp segment wrong (%q)", gap, parts[1])
		}
		sig, err := hex.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("gap %d: signature undecodable: %v", gap, err)
		}
		want := site.sign(fmt.Sprintf("chal|%d|%d", gapTok, expTok))
		if !hmac.Equal(sig, want) {
			t.Fatalf("gap %d: signature mismatch", gap)
		}
	}
}

// The pass token shares the encoder: every exp value must survive
// issue -> verify, including the odd-width boundaries.
func TestCaptchaPassTokenRoundTrip(t *testing.T) {
	site := &captchaSite{secret: []byte("round-trip-secret"), cookie: "cap", ttl: 5 * time.Minute, tol: 3}
	for base := int64(0); base <= 512; base++ {
		exp := time.Now().Add(5 * time.Minute).Unix()/1000*1000 + base
		val := hexI(exp) + "." + hex.EncodeToString(site.sign("pass|"+strconv.FormatInt(exp, 10)))
		parts := strings.Split(val, ".")
		if len(parts) != 2 {
			t.Fatalf("exp %d: pass token split = %d parts", exp, len(parts))
		}
		got, err := hex.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("exp %d: pass signature undecodable: %v", exp, err)
		}
		want := site.sign("pass|" + strconv.FormatInt(exp, 10))
		if !hmac.Equal(got, want) {
			t.Fatalf("exp %d: pass signature mismatch", exp)
		}
	}
}

// hexI must refuse to produce undecodable output for out-of-domain input:
// negatives clamp to 0 (documented domain constraint) instead of emitting
// a "-1" segment that hexVal rejects.
func TestHexINegativeClampsToZero(t *testing.T) {
	if got := hexI(-1); got != "00" {
		t.Fatalf("hexI(-1) = %q, want \"00\"", got)
	}
	if v, ok := hexVal(hexI(-1)); !ok || v != 0 {
		t.Fatalf("hexVal(hexI(-1)) = %d, %v; want 0, true", v, ok)
	}
}
