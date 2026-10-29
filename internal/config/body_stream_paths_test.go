package config

import (
	"strings"
	"testing"
)

// TestOverLimitForPath pins the two-state upload policy resolution: a
// declared body_stream_paths prefix forces "stream" even when the site-level
// body_over_limit is reject, the longest matching prefix wins, and undeclared
// paths keep the site-level behavior.
func TestOverLimitForPath(t *testing.T) {
	if got := (*WAFSettings)(nil).OverLimitForPath("/x"); got != "reject" {
		t.Fatalf("nil WAF must resolve to reject, got %q", got)
	}
	w := &WAFSettings{
		BodyOverLimit:   "reject",
		BodyStreamPaths: []string{"/v1/upload", "/v1/upload/big"},
	}
	cases := []struct {
		path string
		want string
	}{
		{"/v1/upload/file", "stream"},     // prefix hit
		{"/v1/upload/big/part9", "stream"}, // longest prefix still stream
		{"/v1/uploader", "stream"},        // raw prefix semantics (documented)
		{"/other", "reject"},              // undeclared -> site default
		{"", "reject"},
	}
	for _, c := range cases {
		if got := w.OverLimitForPath(c.path); got != c.want {
			t.Fatalf("OverLimitForPath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
	// Site-level bypass/stream still apply to undeclared paths, and a declared
	// prefix is redundant but harmless under them.
	bypass := &WAFSettings{BodyOverLimit: "bypass"}
	if got := bypass.OverLimitForPath("/x"); got != "bypass" {
		t.Fatalf("site bypass must resolve for undeclared path, got %q", got)
	}
	streamSite := &WAFSettings{BodyOverLimit: "stream"}
	if got := streamSite.OverLimitForPath("/x"); got != "stream" {
		t.Fatalf("site stream must resolve for undeclared path, got %q", got)
	}
}

// TestValidateBodyStreamPaths pins the relaxed-table validation: entries must
// be path prefixes, unique, bounded, and free of whitespace/query markers.
func TestValidateBodyStreamPaths(t *testing.T) {
	mk := func(paths []string) *Config {
		return &Config{ListenHTTP: ":80", Sites: []Site{{
			Domains:  []string{"t.local"},
			Upstream: Upstream{Nodes: []UpstreamNode{{Address: "127.0.0.1:9000"}}},
			WAF:      &WAFSettings{BodyStreamPaths: paths},
		}}}
	}
	if err := mk([]string{"/v1/upload", "/api/attachment"}).Validate(); err != nil {
		t.Fatalf("valid prefixes rejected: %v", err)
	}
	bad := map[string][]string{
		"missing slash": {"v1/upload"},
		"bare root":     {"/"},
		"whitespace":    {"/v1/up load"},
		"query marker":  {"/v1/upload?x=1"},
		"duplicate":     {"/v1/upload", "/v1/upload"},
	}
	for name, paths := range bad {
		if err := mk(paths).Validate(); err == nil {
			t.Fatalf("%s: expected validation error for %v", name, paths)
		}
	}
	many := make([]string, MaxBodyStreamPaths+1)
	for i := range many {
		many[i] = "/p" + strings.Repeat("x", i+1)
	}
	if err := mk(many).Validate(); err == nil {
		t.Fatal("over-cap body_stream_paths accepted")
	}
}