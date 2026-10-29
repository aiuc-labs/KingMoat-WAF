package api

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/kingmoat/kingmoat/internal/config"
)

func commentPtr(s string) *string { return &s }

// TestResolveSiteCommentPrecedence pins the merge rules for the site note
// (备注): an explicit request comment wins, a non-empty site.comment is next,
// and an omitted comment keeps the note already stored for that domain so API
// automation cannot wipe an operator's note by re-publishing the site.
func TestResolveSiteCommentPrecedence(t *testing.T) {
	cur := &config.Config{Sites: []config.Site{{
		Domains: []string{"a.local"},
		Comment: "归属：平台组",
	}}}

	cases := []struct {
		name string
		req  sitePublishRequest
		want string
	}{
		{
			name: "request comment overrides stored note",
			req:  sitePublishRequest{Domain: "a.local", Site: config.Site{Domains: []string{"a.local"}}, Comment: commentPtr("归属：安全组")},
			want: "归属：安全组",
		},
		{
			name: "explicit empty request comment clears the note",
			req:  sitePublishRequest{Domain: "a.local", Site: config.Site{Domains: []string{"a.local"}}, Comment: commentPtr("")},
			want: "",
		},
		{
			name: "site body comment wins when request omits it",
			req:  sitePublishRequest{Domain: "a.local", Site: config.Site{Domains: []string{"a.local"}, Comment: "  工单 CHG-42  "}},
			want: "工单 CHG-42",
		},
		{
			name: "omitted comment keeps the stored note (case-insensitive domain)",
			req:  sitePublishRequest{Domain: "A.LOCAL", Site: config.Site{Domains: []string{"a.local"}}},
			want: "归属：平台组",
		},
		{
			name: "unknown domain starts without a note",
			req:  sitePublishRequest{Domain: "new.local", Site: config.Site{Domains: []string{"new.local"}}},
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			if err := resolveSiteComment(&req, cur); err != nil {
				t.Fatalf("resolveSiteComment: %v", err)
			}
			if req.Site.Comment != tc.want {
				t.Fatalf("comment = %q, want %q", req.Site.Comment, tc.want)
			}
		})
	}
}

func TestResolveSiteCommentLengthCap(t *testing.T) {
	ok := strings.Repeat("归", siteCommentMax)
	req := sitePublishRequest{Site: config.Site{}, Comment: commentPtr(ok)}
	if err := resolveSiteComment(&req, nil); err != nil {
		t.Fatalf("exactly %d runes must be accepted: %v", siteCommentMax, err)
	}
	if n := utf8.RuneCountInString(req.Site.Comment); n != siteCommentMax {
		t.Fatalf("stored %d runes, want %d", n, siteCommentMax)
	}

	req = sitePublishRequest{Site: config.Site{}, Comment: commentPtr(ok + "x")}
	err := resolveSiteComment(&req, nil)
	if err == nil {
		t.Fatal("over-long comment must be rejected")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error should name the cap: %v", err)
	}
}

// TestResolveSiteCommentSiteBodyCap covers clients that only send the full
// site object: the cap applies there too.
func TestResolveSiteCommentSiteBodyCap(t *testing.T) {
	req := sitePublishRequest{Site: config.Site{Comment: strings.Repeat("a", siteCommentMax+1)}}
	if err := resolveSiteComment(&req, nil); err == nil {
		t.Fatal("over-long site.comment must be rejected")
	}
}

// TestResolveSiteCommentKeepsLegacyLongNote pins that an inherited note longer
// than the cap is preserved instead of rejected: a stored over-long note must
// not make the site unpublishable (the console's enable/disable toggle sends
// the note back verbatim).
func TestResolveSiteCommentKeepsLegacyLongNote(t *testing.T) {
	legacy := strings.Repeat("旧", siteCommentMax+50)
	cur := &config.Config{Sites: []config.Site{{Domains: []string{"a.local"}, Comment: legacy}}}
	req := sitePublishRequest{Domain: "a.local", Site: config.Site{Domains: []string{"a.local"}}}
	if err := resolveSiteComment(&req, cur); err != nil {
		t.Fatalf("inherited long note must be accepted: %v", err)
	}
	if req.Site.Comment != legacy {
		t.Fatalf("inherited note changed: %d runes", len([]rune(req.Site.Comment)))
	}
}

// TestCheckSiteComments covers the whole-config publish path.
func TestCheckSiteComments(t *testing.T) {
	good := &config.Config{Sites: []config.Site{{Comment: strings.Repeat("a", siteCommentMax)}}}
	if err := checkSiteComments(good); err != nil {
		t.Fatalf("cap-sized note must pass: %v", err)
	}
	bad := &config.Config{Sites: []config.Site{{}, {Comment: strings.Repeat("a", siteCommentMax+1)}}}
	err := checkSiteComments(bad)
	if err == nil {
		t.Fatal("over-long note in a full publish must be rejected")
	}
	if !strings.Contains(err.Error(), "sites[1]") || !strings.Contains(err.Error(), "500") {
		t.Fatalf("error should name the site index and the cap: %v", err)
	}
}
