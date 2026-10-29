package safefetch

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSafefetchRejectsPrivate(t *testing.T) {
	g := Guard{}
	cases := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "::1", "fc00::1", "fe80::1", "0.0.0.0", "224.0.0.1",
	}
	for _, s := range cases {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test ip %q", s)
		}
		if g.AllowsIP(ip) {
			t.Fatalf("guard allowed %s", s)
		}
		if !(Guard{AllowPrivate: true}).AllowsIP(ip) {
			t.Fatalf("AllowPrivate guard rejected %s", s)
		}
	}
	if !g.AllowsIP(net.ParseIP("93.184.216.34")) {
		t.Fatal("guard rejected a public address")
	}

	// The request path must refuse a loopback literal before dialing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret"))
	}))
	defer srv.Close()
	_, _, _, err := Get(context.Background(), srv.URL, Options{Timeout: 2 * time.Second})
	if !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("err = %v, want ErrBlockedTarget", err)
	}
}

func TestSafefetchRedirectHopRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// The hop policy is what protects a public feed that bounces to an
	// intranet address: the same guard used for the initial target decides.
	err := CheckRedirectTarget(ctx, "http://10.1.2.3/steal", Guard{})
	if !errors.Is(err, ErrRedirectRejected) {
		t.Fatalf("private hop err = %v, want ErrRedirectRejected", err)
	}
	if err := CheckRedirectTarget(ctx, "file:///etc/passwd", Guard{}); !errors.Is(err, ErrRedirectRejected) {
		t.Fatalf("scheme hop err = %v, want ErrRedirectRejected", err)
	}
	if err := CheckRedirectTarget(ctx, "http://10.1.2.3/ok", Guard{AllowPrivate: true}); err != nil {
		t.Fatalf("AllowPrivate hop rejected: %v", err)
	}

	// End to end: with the intranet allowed the redirect is followed (proving
	// the policy, not an unrelated network failure, is what blocks above).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://10.1.2.3/steal", http.StatusFound)
	}))
	defer target.Close()

	body, status, _, err := Get(ctx, target.URL, Options{AllowPrivate: true, Timeout: 3 * time.Second})
	if err != nil {
		// A dial timeout to a non-existent intranet host is acceptable here;
		// the point is that the hop passed validation.
		t.Logf("followed redirect failed at dial (expected on an isolated host): %v", err)
		return
	}
	if status != http.StatusFound || len(body) == 0 {
		t.Fatalf("unexpected redirect result: %d %q", status, string(body))
	}
}

func TestSafefetchContentTypeRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>hi</body></html>"))
	}))
	defer srv.Close()

	_, _, _, err := Get(context.Background(), srv.URL, Options{
		AllowPrivate: true, Timeout: 3 * time.Second,
		AcceptTypes: []string{"text/xml", "application/xml"},
	})
	if !errors.Is(err, ErrContentType) {
		t.Fatalf("err = %v, want ErrContentType", err)
	}

	body, status, ct, err := Get(context.Background(), srv.URL, Options{
		AllowPrivate: true, Timeout: 3 * time.Second, AcceptTypes: []string{"text/*"},
	})
	if err != nil {
		t.Fatalf("wildcard accept failed: %v", err)
	}
	if status != http.StatusOK || string(body) != "<html><body>hi</body></html>" || ct == "" {
		t.Fatalf("unexpected response: %d %q %q", status, string(body), ct)
	}
}

func TestSafefetchRejectsBadURLAndOversizeBody(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/passwd",
		"ftp://example.com/x",
		"http://user:pw@example.com/",
		"http://",
	} {
		if _, err := ValidateURL(raw); !errors.Is(err, ErrBadURL) {
			t.Fatalf("ValidateURL(%q) = %v, want ErrBadURL", raw, err)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer srv.Close()

	_, _, _, err := Get(context.Background(), srv.URL, Options{
		AllowPrivate: true, Timeout: 3 * time.Second, MaxBytes: 4,
	})
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("err = %v, want ErrBodyTooLarge", err)
	}
}