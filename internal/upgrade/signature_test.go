package upgrade

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

// TestVerifyChecksumsSignature covers the signed-release path: a valid
// signature over checksums.txt passes, a tampered payload or a corrupt
// signature is rejected, and an embedded key without a signature is refused by
// the caller (ErrUnsignedRelease).
func TestVerifyChecksumsSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := releasePublicKey
	releasePublicKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { releasePublicKey = old })

	if !SignatureRequired() {
		t.Fatal("SignatureRequired must be true with an embedded key")
	}

	payload := []byte("abc123  kingmoatwaf_v1.0.0-stable_linux_amd64.tar.gz\n")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	if err := VerifyChecksumsSignature(payload, []byte(sig)); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	tampered := []byte("abc123  kingmoatwaf_v1.0.0-stable_linux_amd64.tar.gz\nx")
	if err := VerifyChecksumsSignature(tampered, []byte(sig)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered payload not rejected: %v", err)
	}

	if err := VerifyChecksumsSignature(payload, []byte("not-base64!!")); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("corrupt signature not rejected: %v", err)
	}
}

// TestSignatureDisabledByDefault pins that a build without an embedded key does
// not enforce signatures (the pre-v1.0.0 behaviour).
func TestSignatureDisabledByDefault(t *testing.T) {
	old := releasePublicKey
	releasePublicKey = ""
	t.Cleanup(func() { releasePublicKey = old })
	if SignatureRequired() {
		t.Fatal("signature enforcement must stay off without a key")
	}
}
