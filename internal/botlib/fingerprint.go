package botlib

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// Fingerprint derives a stable per-client identifier from the remote address,
// User-Agent and a short whitelist of content-negotiation header values. It is
// cheap, cacheable and requires no cookies; it is not a strong identity and
// must only drive behavioral signals (rate, challenge history).
//
// Only values from stable, browser-driven headers are hashed: hashing the full
// header-name set (the previous behaviour) let a client rotate its rate-limit
// bucket by inventing one header per request, and split a single client across
// buckets whenever the request method changed the header set.
var fingerprintHeaders = []string{
	"Accept",
	"Accept-Encoding",
	"Accept-Language",
	"Sec-Ch-Ua-Platform",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Site",
}

func Fingerprint(ip, ua string, r *http.Request) string {
	h := sha256.New()
	h.Write([]byte(ip))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(ua)))
	for _, name := range fingerprintHeaders {
		h.Write([]byte{0})
		if r != nil {
			h.Write([]byte(strings.ToLower(strings.Join(r.Header.Values(name), ","))))
		}
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16]) // 32 hex chars; 64-bit truncation collides at 2^32 clients
}
