package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/webui"
)

const credFixtureJSON = `{
 "listen_http": ":80",
 "sites": [{"domains": ["a.local"], "upstream": {"nodes": [{"address": "127.0.0.1:9001"}]}}],
 "log_shipper": {"type": "elasticsearch", "url": "http://es:9200", "username": "ship-user", "password": "ship-pass", "access_key": "ship-ak", "secret_key": "ship-sk"},
 "access_log": {"type": "elasticsearch", "url": "http://es:9201", "username": "acc-user", "password": "acc-pass", "s3": {"bucket": "b", "access_key": "acc-ak", "secret_key": "acc-sk"}},
 "ai_audit": {"enabled": true, "ship": {"type": "elasticsearch", "url": "http://es:9202", "username": "ai-user", "password": "ai-pass", "s3": {"bucket": "b", "access_key": "ai-ak", "secret_key": "ai-sk"}}},
 "webhook": {"url": "https://hook.example/x", "secret": "whk-secret", "s3": {"bucket": "b", "access_key": "whk-ak", "secret_key": "whk-sk"}},
 "metrics": {"push": {"url": "http://pg:9091/metrics", "bearer_token": "push-tok"}},
 "email": {"host": "smtp.example:587", "password": "mail-pass"}
}`

func credFixture(t *testing.T) *config.Config {
	t.Helper()
	c := new(config.Config)
	if err := json.Unmarshal([]byte(credFixtureJSON), c); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	ps := credentialPointers(c)
	if len(ps) != 14 {
		t.Fatalf("fixture wires %d credential fields, want 14 (json tag drift?)", len(ps))
	}
	for i, p := range ps {
		if *p == "" {
			t.Fatalf("credential field %d empty — fixture tag mismatch", i)
		}
	}
	return c
}

func credMarkers() []string {
	return []string{"ship-pass", "ship-ak", "ship-sk", "acc-pass", "acc-ak", "acc-sk",
		"ai-pass", "ai-ak", "ai-sk", "whk-secret", "whk-ak", "whk-sk", "push-tok", "mail-pass"}
}

func setAllCreds(c *config.Config, v string) {
	for _, p := range credentialPointers(c) {
		*p = v
	}
}

func TestRedactedConfigCopyMasksEveryCredential(t *testing.T) {
	cfg := credFixture(t)
	out, err := redactedConfigCopy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range credentialPointers(out) {
		if *p != credPlaceholder {
			t.Fatalf("masked field %d = %q, want placeholder", i, *p)
		}
	}
	b, _ := json.Marshal(out)
	s := string(b)
	for _, m := range credMarkers() {
		if strings.Contains(s, m) {
			t.Fatalf("redacted copy leaks %q", m)
		}
	}
	if !strings.Contains(s, "ship-user") {
		t.Fatal("usernames must stay readable")
	}
	for i, p := range credentialPointers(cfg) {
		if *p == credPlaceholder {
			t.Fatalf("live config field %d mutated by redactedConfigCopy", i)
		}
	}
}

func TestRedactedConfigCopyKeepsEmptyUnconfigured(t *testing.T) {
	cfg := credFixture(t)
	setAllCreds(cfg, "")
	out, err := redactedConfigCopy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range credentialPointers(out) {
		if *p != "" {
			t.Fatalf("unconfigured field %d = %q, want empty", i, *p)
		}
	}
}

func TestRestorePlaceholderAndEmptyKeepStored(t *testing.T) {
	want := credFixture(t)
	for _, sentinel := range []string{credPlaceholder, ""} {
		in := credFixture(t)
		cur := credFixture(t)
		setAllCreds(in, sentinel)
		restoreOutboundCredentials(in, cur)
		got, exp := credentialPointers(in), credentialPointers(want)
		for i := range got {
			if *got[i] != *exp[i] {
				t.Fatalf("sentinel %q: field %d = %q, want stored %q", sentinel, i, *got[i], *exp[i])
			}
		}
	}
}

func TestRestoreExplicitValueOverwrites(t *testing.T) {
	in := credFixture(t)
	cur := credFixture(t)
	setAllCreds(in, "new-value")
	restoreOutboundCredentials(in, cur)
	for i, p := range credentialPointers(in) {
		if *p != "new-value" {
			t.Fatalf("field %d = %q, want explicit new-value", i, *p)
		}
	}
}

func TestRestoreSentinelWithoutStoredCounterpartNormalizes(t *testing.T) {
	in := credFixture(t)
	setAllCreds(in, credPlaceholder)
	restoreOutboundCredentials(in, new(config.Config))
	for i, p := range credentialPointers(in) {
		if *p != "" {
			t.Fatalf("orphan sentinel field %d = %q, want normalized empty (sentinel never persisted)", i, *p)
		}
	}
}

func TestRestoreSectionMissingOnOneSideNoPair(t *testing.T) {
	in := credFixture(t)
	cur := credFixture(t)
	cur.LogShipper = nil
	setAllCreds(in, credPlaceholder)
	restoreOutboundCredentials(in, cur)
	if in.LogShipper.Password != "" || in.LogShipper.AccessKey != "" || in.LogShipper.SecretKey != "" {
		t.Fatal("section missing in stored config must normalize sentinels, not keep across sections")
	}
	if in.AccessLog.Password != "acc-pass" {
		t.Fatalf("paired section lost its stored value: %q", in.AccessLog.Password)
	}
}

func TestRestoreIdempotent(t *testing.T) {
	in := credFixture(t)
	cur := credFixture(t)
	for i, p := range credentialPointers(in) {
		switch i % 3 {
		case 0:
			*p = credPlaceholder
		case 1:
			*p = ""
		default:
			*p = "fresh"
		}
	}
	restoreOutboundCredentials(in, cur)
	first, err := json.Marshal(credentialPointers(in))
	if err != nil {
		t.Fatal(err)
	}
	restoreOutboundCredentials(in, cur)
	second, err := json.Marshal(credentialPointers(in))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("restore not idempotent:\nfirst  %s\nsecond %s", first, second)
	}
}

func TestAPICredentialRoundTripHidesPlaintext(t *testing.T) {
	center, err := configcenter.Open(t.TempDir()+"/cred-test.db", credFixture(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer center.Close()
	audit, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	srv := New(Options{SkipBootstrap: true, Center: center, Logs: audit, WebUI: webui.Handler("test")})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/config")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := readAllAndClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/config = %d, body %s", resp.StatusCode, body)
	}
	for _, m := range credMarkers() {
		if strings.Contains(string(body), m) {
			t.Fatalf("GET /api/config leaks credential %q", m)
		}
	}
	var envelope struct {
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || len(envelope.Config) == 0 {
		t.Fatalf("unexpected GET envelope: %s (%v)", body, err)
	}
	var masked config.Config
	if err := json.Unmarshal(envelope.Config, &masked); err != nil {
		t.Fatal(err)
	}
	if masked.LogShipper == nil || masked.LogShipper.Password != credPlaceholder {
		t.Fatalf("GET config credential = %+v, want placeholder", masked.LogShipper)
	}

	reqBody, _ := json.Marshal(map[string]any{"note": "credential round trip", "config": &masked})
	resp2, err := http.Post(ts.URL+"/api/config/publish", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	pubBody, _ := readAllAndClose(resp2.Body)
	if resp2.StatusCode != http.StatusOK && resp2.StatusCode != http.StatusConflict {
		t.Fatalf("publish masked config = %d, body %s", resp2.StatusCode, pubBody)
	}
	if resp2.StatusCode == http.StatusConflict {
		t.Logf("publish of masked round-trip is a no-op diff (stored already matches): %s", pubBody)
	}
	_, cur := center.Current()
	if cur.LogShipper == nil || cur.LogShipper.Password != "ship-pass" {
		t.Fatalf("stored credential changed after publishing masked config: %+v", cur.LogShipper)
	}
	if cur.Metrics == nil || cur.Metrics.Push == nil || cur.Metrics.Push.BearerToken != "push-tok" {
		t.Fatalf("metrics push token changed after publishing masked config")
	}
}

func readAllAndClose(rc interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(rc)
	if c, ok := rc.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	return buf.Bytes(), err
}

// urlCredFixture wires every outbound URL field with a user:pass@ userinfo —
// the http(s) forms publish without any userinfo rejection rule, so they are
// the live echo window S-4 closes.
const urlCredFixtureJSON = `{
 "listen_http": ":80",
 "sites": [{"domains": ["a.local"], "upstream": {"nodes": [{"address": "127.0.0.1:9001"}]}}],
 "log_shipper": {"type": "elasticsearch", "url": "http://es-user:es-pass@es:9200"},
 "access_log": {"enabled": true, "type": "elasticsearch", "url": "https://acc-user:acc-url-pass@es:9201"},
 "ai_audit": {"enabled": true, "ship": {"type": "elasticsearch", "url": "http://ai-user:ai-url-pass@es:9202"}},
 "webhook": {"url": "https://wh-user:wh-url-pass@hook.example/x"},
 "metrics": {"push": {"url": "http://push-user:push-url-pass@pg:9091/metrics"}},
 "ip_groups": [{"name": "feeds", "url": "https://feed-user:feed-url-pass@feeds.example/list"}]
}`

func urlCredFixture(t *testing.T) *config.Config {
	t.Helper()
	c := new(config.Config)
	if err := json.Unmarshal([]byte(urlCredFixtureJSON), c); err != nil {
		t.Fatalf("url fixture: %v", err)
	}
	return c
}

var urlCredMarkers = []string{"es-pass", "acc-url-pass", "ai-url-pass", "wh-url-pass", "push-url-pass", "feed-url-pass"}

// S-4: the GET view masks the password component of every outbound URL's
// userinfo in place, without touching the live config.
func TestRedactedConfigCopyMasksURLUserInfo(t *testing.T) {
	cfg := urlCredFixture(t)
	out, err := redactedConfigCopy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, got, want string }{
		{"log_shipper", out.LogShipper.URL, "http://es-user:******@es:9200"},
		{"access_log", out.AccessLog.URL, "https://acc-user:******@es:9201"},
		{"ai_audit.ship", out.AiAudit.Ship.URL, "http://ai-user:******@es:9202"},
		{"webhook", out.Webhook.URL, "https://wh-user:******@hook.example/x"},
		{"metrics.push", out.Metrics.Push.URL, "http://push-user:******@pg:9091/metrics"},
		{"ip_groups", out.IPGroups[0].URL, "https://feed-user:******@feeds.example/list"},
	} {
		if tc.got != tc.want {
			t.Fatalf("%s = %q, want %q (username/host stay readable, only the password masks)", tc.name, tc.got, tc.want)
		}
	}
	b, _ := json.Marshal(out)
	s := string(b)
	for _, m := range urlCredMarkers {
		if strings.Contains(s, m) {
			t.Fatalf("redacted copy leaks url credential %q", m)
		}
	}
	if cfg.LogShipper.URL != "http://es-user:es-pass@es:9200" {
		t.Fatalf("live config mutated by redactedConfigCopy: %q", cfg.LogShipper.URL)
	}
}

// S-4 key assertion: GET-masksed URLs PUT back restore the stored value
// byte-for-byte (the masked form is the redacted echo, not a new value).
func TestRestoreMaskedURLRoundTripKeepsStored(t *testing.T) {
	cur := urlCredFixture(t)
	in := urlCredFixture(t)
	maskOutboundCredentials(in) // simulate the console round-tripping a GET response
	restoreOutboundCredentials(in, cur)
	for _, tc := range []struct {
		name      string
		got, want string
	}{
		{"log_shipper", in.LogShipper.URL, cur.LogShipper.URL},
		{"access_log", in.AccessLog.URL, cur.AccessLog.URL},
		{"ai_audit.ship", in.AiAudit.Ship.URL, cur.AiAudit.Ship.URL},
		{"webhook", in.Webhook.URL, cur.Webhook.URL},
		{"metrics.push", in.Metrics.Push.URL, cur.Metrics.Push.URL},
		{"ip_groups", in.IPGroups[0].URL, cur.IPGroups[0].URL},
	} {
		if tc.got != tc.want {
			t.Fatalf("%s masked round trip = %q, want stored %q verbatim", tc.name, tc.got, tc.want)
		}
	}
}

// A host-only edit while the password is masked keeps the stored password.
func TestRestoreMaskedURLHostEditKeepsStoredPassword(t *testing.T) {
	cur := urlCredFixture(t)
	in := urlCredFixture(t)
	in.LogShipper.URL = "http://es-user:******@es2:9200"
	restoreOutboundCredentials(in, cur)
	if in.LogShipper.URL != "http://es-user:es-pass@es2:9200" {
		t.Fatalf("host edit with masked password = %q, want stored password spliced in", in.LogShipper.URL)
	}
}

// Without a stored counterpart the mask token degrades to an empty password —
// it must never persist as a literal credential.
func TestRestoreMaskedURLTokenNeverPersistsWithoutCounterpart(t *testing.T) {
	in := urlCredFixture(t)
	maskOutboundCredentials(in)
	restoreOutboundCredentials(in, new(config.Config))
	for _, tc := range []struct{ name, got, want string }{
		{"log_shipper", in.LogShipper.URL, "http://es-user@es:9200"},
		{"webhook", in.Webhook.URL, "https://wh-user@hook.example/x"},
		{"ip_groups", in.IPGroups[0].URL, "https://feed-user@feeds.example/list"},
	} {
		if tc.got != tc.want {
			t.Fatalf("%s = %q, want %q (token dropped, username kept)", tc.name, tc.got, tc.want)
		}
	}
}

// S-8: credEraseSentinel clears the stored credential; the placeholder and
// the empty string keep it; an explicit value overwrites it. Old behavior
// unchanged.
func TestRestoreEraseSentinelClearsStored(t *testing.T) {
	cur := credFixture(t)
	in := credFixture(t)
	in.LogShipper.Password = credEraseSentinel // erase
	in.LogShipper.AccessKey = credPlaceholder  // keep
	in.LogShipper.SecretKey = "brand-new-key"  // overwrite
	in.AccessLog.Password = ""                 // keep
	restoreOutboundCredentials(in, cur)
	if in.LogShipper.Password != "" {
		t.Fatalf("erase sentinel = %q, want cleared", in.LogShipper.Password)
	}
	if in.LogShipper.AccessKey != "ship-ak" {
		t.Fatalf("placeholder = %q, want stored %q", in.LogShipper.AccessKey, "ship-ak")
	}
	if in.LogShipper.SecretKey != "brand-new-key" {
		t.Fatalf("explicit value = %q, want overwritten", in.LogShipper.SecretKey)
	}
	if in.AccessLog.Password != "acc-pass" {
		t.Fatalf("empty = %q, want stored %q", in.AccessLog.Password, "acc-pass")
	}

	in2 := credFixture(t)
	setAllCreds(in2, credEraseSentinel)
	restoreOutboundCredentials(in2, cur)
	for i, p := range credentialPointers(in2) {
		if *p != "" {
			t.Fatalf("all-erase: field %d = %q, want cleared", i, *p)
		}
	}
}

// The erase sentinel behaves like the placeholder when it has no stored
// counterpart: it normalizes to empty, never persists as a literal value.
func TestRestoreEraseSentinelWithoutStoredCounterpartNormalizes(t *testing.T) {
	in := credFixture(t)
	setAllCreds(in, credEraseSentinel)
	restoreOutboundCredentials(in, new(config.Config))
	for i, p := range credentialPointers(in) {
		if *p != "" {
			t.Fatalf("orphan erase sentinel field %d = %q, want normalized empty", i, *p)
		}
	}
}

// GET /api/config never returns the erase sentinel (or a stored password).
func TestRedactedConfigCopyNeverReturnsEraseSentinel(t *testing.T) {
	cfg := credFixture(t)
	setAllCreds(cfg, credEraseSentinel)
	out, err := redactedConfigCopy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), credEraseSentinel) {
		t.Fatal("GET returned the erase sentinel")
	}
	for i, p := range credentialPointers(out) {
		if *p != credPlaceholder {
			t.Fatalf("field %d = %q, want placeholder", i, *p)
		}
	}
}

// S-4 end-to-end: GET masks url userinfo → the masked GET response is PUT
// back verbatim → the stored URL stays byte-identical (the closed loop never
// pollutes the stored config).
func TestAPIURLMaskRoundTripKeepsStored(t *testing.T) {
	center, err := configcenter.Open(t.TempDir()+"/url-roundtrip.db", urlCredFixture(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer center.Close()
	audit, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	srv := New(Options{SkipBootstrap: true, Center: center, Logs: audit, WebUI: webui.Handler("test")})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/config")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := readAllAndClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/config = %d, body %s", resp.StatusCode, body)
	}
	for _, m := range urlCredMarkers {
		if strings.Contains(string(body), m) {
			t.Fatalf("GET /api/config leaks url credential %q", m)
		}
	}
	if !strings.Contains(string(body), "es-user:******@es:9200") {
		t.Fatalf("masked url form missing from GET response")
	}

	var envelope struct {
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || len(envelope.Config) == 0 {
		t.Fatalf("unexpected GET envelope: %s (%v)", body, err)
	}
	reqBody, _ := json.Marshal(map[string]any{"note": "masked url round trip", "config": envelope.Config})
	resp2, err := http.Post(ts.URL+"/api/config/publish", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	pubBody, _ := readAllAndClose(resp2.Body)
	if resp2.StatusCode != http.StatusOK && resp2.StatusCode != http.StatusConflict {
		t.Fatalf("publish of masked url config = %d, body %s", resp2.StatusCode, pubBody)
	}
	if resp2.StatusCode == http.StatusConflict {
		t.Logf("publish of masked round trip is a no-op diff (stored already matches): %s", pubBody)
	}

	_, cur := center.Current()
	for _, tc := range []struct{ name, got, want string }{
		{"log_shipper", cur.LogShipper.URL, "http://es-user:es-pass@es:9200"},
		{"access_log", cur.AccessLog.URL, "https://acc-user:acc-url-pass@es:9201"},
		{"ai_audit.ship", cur.AiAudit.Ship.URL, "http://ai-user:ai-url-pass@es:9202"},
		{"webhook", cur.Webhook.URL, "https://wh-user:wh-url-pass@hook.example/x"},
		{"metrics.push", cur.Metrics.Push.URL, "http://push-user:push-url-pass@pg:9091/metrics"},
		{"ip_groups", cur.IPGroups[0].URL, "https://feed-user:feed-url-pass@feeds.example/list"},
	} {
		if tc.got != tc.want {
			t.Fatalf("stored %s polluted by masked round trip: %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// R-2: outbound URLs whose credentials MaskURLCredentials cannot splice out
// (no-"//" user:pass@ forms that url.Parse reports as scheme+opaque,
// unparseable URLs, userinfo without a password) must not echo plaintext on
// GET — they come back as credRedactedMarker. A legal URL that merely
// carries "@" in its query (?email=a@b.c, no userinfo) must NOT hit the
// marker, and a parseable password-bearing URL keeps the precise masked
// form instead of the whole-value marker.
func TestRedactedConfigCopyRedactsUnmaskableURLs(t *testing.T) {
	cfg := urlCredFixture(t)
	cfg.LogShipper.URL = "user:pass@host"                        // no "//": the masker cannot find the authority
	cfg.AccessLog.URL = "http://acc-user:acc-url-pass@:notaport" // unparseable (invalid port)
	cfg.AiAudit.Ship.URL = "http://ai-user@es:9202"              // userinfo without a password: masker returns it verbatim
	cfg.Webhook.URL = "http://hook.example/x?email=a@b.c"        // legal URL, "@" in query only
	cfg.Metrics.Push.URL = "http://push-user:push-url-pass@"     // parseable, password-bearing: masker handles it
	out, err := redactedConfigCopy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, got, want string }{
		{"log_shipper", out.LogShipper.URL, credRedactedMarker},
		{"access_log", out.AccessLog.URL, credRedactedMarker},
		{"ai_audit.ship", out.AiAudit.Ship.URL, credRedactedMarker},
		{"webhook", out.Webhook.URL, "http://hook.example/x?email=a@b.c"},
		{"metrics.push", out.Metrics.Push.URL, "http://push-user:******@"},
	} {
		if tc.got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// R-2 key invariant on the marker path: GET redacts the unmaskable forms to
// <redacted>, PUT restores the stored URL byte-for-byte — the marker is an
// echo of storage, never a replacement.
func TestRestoreRedactedMarkerRoundTripKeepsStored(t *testing.T) {
	cur := urlCredFixture(t)
	cur.LogShipper.URL = "user:pass@host"                        // the unmaskable form is also legal storage
	cur.AccessLog.URL = "http://acc-user:acc-url-pass@:notaport" // unparseable storage too
	in := urlCredFixture(t)
	in.LogShipper.URL = cur.LogShipper.URL
	in.AccessLog.URL = cur.AccessLog.URL
	maskOutboundCredentials(in) // simulate the console round-tripping a GET response
	if in.LogShipper.URL != credRedactedMarker || in.AccessLog.URL != credRedactedMarker {
		t.Fatalf("GET did not redact the unmaskable forms: %q / %q", in.LogShipper.URL, in.AccessLog.URL)
	}
	restoreOutboundCredentials(in, cur)
	if in.LogShipper.URL != cur.LogShipper.URL || in.AccessLog.URL != cur.AccessLog.URL {
		t.Fatalf("marker round trip polluted storage: %q / %q, want %q / %q",
			in.LogShipper.URL, in.AccessLog.URL, cur.LogShipper.URL, cur.AccessLog.URL)
	}
}

// A credRedactedMarker left in a field with no stored counterpart must not
// persist as a literal — it normalizes to empty, same rule as the
// placeholder/erase sentinels.
func TestRestoreRedactedMarkerWithoutCounterpartNormalizes(t *testing.T) {
	in := urlCredFixture(t)
	in.LogShipper.URL = credRedactedMarker
	in.IPGroups[0].URL = credRedactedMarker
	restoreOutboundCredentials(in, new(config.Config))
	if in.LogShipper.URL != "" || in.IPGroups[0].URL != "" {
		t.Fatalf("orphan marker = %q / %q, want normalized empty (sentinel never persisted)",
			in.LogShipper.URL, in.IPGroups[0].URL)
	}
}

// R-7: a mask token inside an unparseable URL must not persist as a literal
// credential — the parse-failure branch of normalizeMaskedURLPassword strips
// the token (the password degrades to empty) instead of echoing it back.
func TestNormalizeMaskedURLPasswordStripsTokenOnParseFailure(t *testing.T) {
	got := normalizeMaskedURLPassword("http://user:******@:notaport", "http://user:real@es:9200")
	if got != "http://user:@:notaport" {
		t.Fatalf("parse-failure token = %q, want %q (token stripped, empty password)", got, "http://user:@:notaport")
	}
	if strings.Contains(got, config.URLPasswordMask) {
		t.Fatal("the mask token must never survive the parse-failure branch")
	}
}

// End-to-end publish path: a masked URL that fails to parse loses the token
// when no stored counterpart exists, instead of persisting it verbatim.
func TestRestoreMaskedURLTokenNeverPersistsOnParseFailure(t *testing.T) {
	in := urlCredFixture(t)
	in.Metrics.Push.URL = "http://push-user:******@:notaport"
	restoreOutboundCredentials(in, new(config.Config))
	if in.Metrics.Push.URL != "http://push-user:@:notaport" {
		t.Fatalf("stored url = %q, want %q (token degraded to empty password)",
			in.Metrics.Push.URL, "http://push-user:@:notaport")
	}
}
