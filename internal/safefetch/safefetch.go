// Package safefetch performs outbound HTTP GETs under a strict SSRF policy:
// only absolute http(s) URLs without credentials, every resolved address is
// checked against the Guard (loopback / private / link-local / multicast /
// unspecified / ULA are rejected unless AllowPrivate), every redirect hop is
// re-validated, and the response body plus media type are bounded.
//
// The same policy guards the actual TCP connection (net.Dialer.Control), so a
// DNS answer that changes between the pre-flight lookup and the dial (DNS
// rebinding) is rejected as well.
package safefetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Limits applied to every request; callers may lower them via Options.
const (
	MaxURLLen           = 2048
	defaultTimeout      = 10 * time.Second
	defaultMaxBytes     = 8 << 20 // 8 MiB
	defaultMaxRedirects = 5
	DefaultUserAgent    = "KingMoatWAF/1.0"
)

// Sentinel errors; the API layer maps them to user-facing Chinese text.
var (
	// ErrBadURL reports a malformed or disallowed URL (scheme, credentials,
	// missing host, over-long).
	ErrBadURL = errors.New("safefetch: url must be an absolute http(s) URL without credentials")
	// ErrBlockedTarget reports an address the policy refuses to connect to.
	ErrBlockedTarget = errors.New("safefetch: target address is not allowed")
	// ErrRedirectRejected reports a redirect hop that failed validation.
	ErrRedirectRejected = errors.New("safefetch: redirect target rejected")
	// ErrBodyTooLarge reports a response body over the byte budget.
	ErrBodyTooLarge = errors.New("safefetch: response body exceeds the size limit")
	// ErrContentType reports a media type outside the accepted list.
	ErrContentType = errors.New("safefetch: response content type is not accepted")
)

// Guard is the address policy. AllowPrivate widens it to intranet targets
// (the console's requires_external escape hatch).
type Guard struct {
	AllowPrivate bool
}

// blockedPrefixes are IPv4 ranges that net.IP.IsPrivate() does not cover but
// must never be reachable from a user-supplied URL: carrier-grade NAT
// (100.64.0.0/10 — Alibaba Cloud metadata lives at 100.100.100.200) and the
// benchmarking range (198.18.0.0/15).
var blockedPrefixes = []struct {
	net  net.IP
	bits int
}{
	{net: net.IPv4(100, 64, 0, 0), bits: 10},
	{net: net.IPv4(198, 18, 0, 0), bits: 15},
}

func inBlockedPrefix(v4 net.IP) bool {
	for _, p := range blockedPrefixes {
		if (&net.IPNet{IP: p.net.To4(), Mask: net.CIDRMask(p.bits, 32)}).Contains(v4) {
			return true
		}
	}
	return false
}

// AllowsIP reports whether the guard permits connecting to ip.
func (g Guard) AllowsIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4.IsUnspecified(), v4.IsLoopback(), v4.IsPrivate(),
			v4.IsLinkLocalUnicast(), v4.IsLinkLocalMulticast(), v4.IsMulticast():
			return g.AllowPrivate
		case v4[0] == 0: // 0.0.0.0/8 "this network"
			return g.AllowPrivate
		case inBlockedPrefix(v4):
			return g.AllowPrivate
		}
		return true
	}
	switch {
	case ip.IsUnspecified(), ip.IsLoopback(), ip.IsPrivate(),
		ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsMulticast():
		return g.AllowPrivate
	}
	return true
}

// DialContext dials address after re-checking the concrete IP, so a rebound
// DNS name cannot smuggle the connection into a blocked range.
func (g Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrBlockedTarget, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("%w: non-IP dial target %q", ErrBlockedTarget, host)
			}
			if !g.AllowsIP(ip) {
				return fmt.Errorf("%w: %s", ErrBlockedTarget, ip)
			}
			return nil
		},
	}
	return d.DialContext(ctx, network, address)
}

// Options bound one fetch.
type Options struct {
	// AllowPrivate admits intranet / loopback targets.
	AllowPrivate bool
	// Timeout caps the whole request, DNS pre-flight included (default 10s).
	Timeout time.Duration
	// MaxBytes caps the response body (default 8 MiB).
	MaxBytes int64
	// AcceptTypes is a media-type whitelist matched against the response
	// Content-Type (params ignored). Empty accepts anything. Entries may be
	// exact types ("text/xml") or wildcards ("text/*", "*/*").
	AcceptTypes []string
	// MaxRedirects caps redirect hops (default 5, 0 = default).
	MaxRedirects int
	// UserAgent overrides the default agent string.
	UserAgent string
}

func (o Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return defaultTimeout
}

func (o Options) maxBytes() int64 {
	if o.MaxBytes > 0 {
		return o.MaxBytes
	}
	return defaultMaxBytes
}

func (o Options) maxRedirects() int {
	if o.MaxRedirects > 0 {
		return o.MaxRedirects
	}
	return defaultMaxRedirects
}

// ValidateURL reports whether rawURL is an acceptable target.
func ValidateURL(rawURL string) (*url.URL, error) {
	if strings.TrimSpace(rawURL) == "" || len(rawURL) > MaxURLLen {
		return nil, ErrBadURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q", ErrBadURL, u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("%w: missing host", ErrBadURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: credentials in URL", ErrBadURL)
	}
	return u, nil
}

// checkHost resolves host and rejects the request when any resolved address
// falls outside the guard. Checking every answer (not just the first) keeps a
// mixed A record set from slipping a private address through.
func checkHost(ctx context.Context, host string, g Guard) error {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("safefetch: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("safefetch: resolve %s: no addresses", host)
	}
	for _, ip := range ips {
		if !g.AllowsIP(ip.IP) {
			return fmt.Errorf("%w: %s resolves to %s", ErrBlockedTarget, host, ip.IP)
		}
	}
	return nil
}

// CheckRedirectTarget validates one redirect hop: the URL shape first, then
// every resolved address against the guard. It is exported so callers (and
// tests) can reason about a hop without an initial public host.
func CheckRedirectTarget(ctx context.Context, rawURL string, g Guard) error {
	u, err := ValidateURL(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedirectRejected, err)
	}
	if err := checkHost(ctx, u.Hostname(), g); err != nil {
		return fmt.Errorf("%w: %w", ErrRedirectRejected, err)
	}
	return nil
}

func acceptedType(accept []string, mediaType string) bool {
	if len(accept) == 0 {
		return true
	}
	mt := strings.ToLower(strings.TrimSpace(mediaType))
	for _, a := range accept {
		a = strings.ToLower(strings.TrimSpace(a))
		switch {
		case a == "*/*" || a == mt:
			return true
		case strings.HasSuffix(a, "/*"):
			if strings.HasPrefix(mt, strings.TrimSuffix(a, "*")) {
				return true
			}
		}
	}
	return false
}

func mediaTypeOf(contentType string) string {
	if mt, _, err := mime.ParseMediaType(contentType); err == nil {
		return mt
	}
	if i := strings.Index(contentType, ";"); i >= 0 {
		contentType = contentType[:i]
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

// Get fetches rawURL and returns the body (bounded), the status code and the
// raw Content-Type header. A non-2xx/3xx status is returned to the caller
// together with the body: interpreting upstream status is a per-consumer
// decision (feeds treat 304 as "not modified", for example).
func Get(ctx context.Context, rawURL string, opts Options) ([]byte, int, string, error) {
	u, err := ValidateURL(rawURL)
	if err != nil {
		return nil, 0, "", err
	}
	// The budget must cover the DNS pre-flight too: with a caller-supplied
	// background context a hanging resolver would otherwise block forever.
	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()

	guard := Guard{AllowPrivate: opts.AllowPrivate}
	if err := checkHost(ctx, u.Hostname(), guard); err != nil {
		return nil, 0, "", err
	}

	transport := &http.Transport{
		// Deliberately no Proxy: environment proxy settings must not be able
		// to route (and thereby bypass) the address policy.
		Proxy:                 nil,
		DialContext:           guard.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{
		Timeout:   opts.timeout(),
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= opts.maxRedirects() {
				return fmt.Errorf("%w: too many redirects", ErrRedirectRejected)
			}
			return CheckRedirectTarget(req.Context(), req.URL.String(), guard)
		},
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, "", fmt.Errorf("%w: %v", ErrBadURL, err)
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if len(opts.AcceptTypes) > 0 && !acceptedType(opts.AcceptTypes, mediaTypeOf(ct)) {
		return nil, resp.StatusCode, ct, fmt.Errorf("%w: %q", ErrContentType, mediaTypeOf(ct))
	}

	limit := opts.maxBytes()
	// Guard the overflow: MaxInt64+1 wraps negative and LimitReader would then
	// return an empty body with no error.
	probe := limit
	if probe < math.MaxInt64 {
		probe++
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, probe))
	if err != nil {
		return nil, resp.StatusCode, ct, fmt.Errorf("safefetch: read body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, resp.StatusCode, ct, fmt.Errorf("%w: limit %d bytes", ErrBodyTooLarge, limit)
	}
	return body, resp.StatusCode, ct, nil
}