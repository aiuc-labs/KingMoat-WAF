package upgrade

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// releasePublicKey is the base64 Ed25519 public key used to verify
// checksums.txt. It is public information and is injected at build time:
//
//	-X github.com/kingmoat/kingmoat/internal/upgrade.releasePublicKey=<base64>
//
// An empty value disables signature enforcement: upgrades then rely on TLS to
// the release origin plus the repository ACL (the pre-v1.0.0 behaviour). When a
// key is embedded, a release without a valid checksums.txt.sig is refused.
var releasePublicKey = ""

// ErrUnsignedRelease reports a release that lacks checksums.txt.sig while a
// verification key is embedded.
var ErrUnsignedRelease = errors.New("upgrade: 发布缺少 checksums.txt 签名，已中止升级")

// ErrBadSignature reports a signature that does not verify.
var ErrBadSignature = errors.New("upgrade: checksums.txt 签名校验失败，已中止升级")

// SignatureRequired reports whether this build enforces release signatures.
func SignatureRequired() bool { return strings.TrimSpace(releasePublicKey) != "" }

// VerifyChecksumsSignature checks the base64 Ed25519 signature over payload.
func VerifyChecksumsSignature(payload, sigB64 []byte) error {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(releasePublicKey))
	if err != nil {
		return fmt.Errorf("upgrade: 内置发布公钥无效: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("upgrade: 内置发布公钥长度异常（%d）", len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil {
		return fmt.Errorf("%w: 签名不是合法 base64", ErrBadSignature)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return ErrBadSignature
	}
	return nil
}
