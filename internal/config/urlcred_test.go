package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestMaskURLCredentials(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"udp syslog target", "udp://ops:s3cret-pw@loghost:514", "udp://ops:******@loghost:514"},
		{"http target keeps path and query", "http://u:p@es:9200/_bulk?a=b", "http://u:******@es:9200/_bulk?a=b"},
		{"scheme-less form", "//u:p@h:514", "//u:******@h:514"},
		{"username only stays", "tcp://admin@h:514", "tcp://admin@h:514"},
		{"no userinfo stays", "udp://loghost:514", "udp://loghost:514"},
		{"bare host stays", "loghost:514", "loghost:514"},
		{"opaque form has no parseable userinfo", "user:pass@host:514", "user:pass@host:514"},
		{"unparseable port stays for value use", "udp://u:p@h:notaport", "udp://u:p@h:notaport"},
		{"empty stays", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MaskURLCredentials(tc.in); got != tc.want {
				t.Fatalf("MaskURLCredentials(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMaskURLForLogNeverEchoesCredentialShapes(t *testing.T) {
	// Parseable userinfo: precise mask, host stays for correlation.
	if got := maskURLForLog("udp://ops:s3cret-pw@loghost:514"); got != "udp://ops:******@loghost:514" {
		t.Fatalf("precise mask: %q", got)
	}
	if got := maskURLForLog("//u:p@h"); got != "//u:******@h" {
		t.Fatalf("scheme-less precise mask: %q", got)
	}
	// Credential-shaped but not precisely parseable: the whole input is
	// replaced — a password never reaches the log even for malformed URLs.
	for _, raw := range []string{"udp://u:p@h:notaport", "user:pass@host", "user:pass@host:514"} {
		got := maskURLForLog(raw)
		if got == raw || !strings.Contains(got, "redacted input") {
			t.Fatalf("credential-shaped input %q must be replaced, got %q", raw, got)
		}
		if strings.Contains(got, "pass") || strings.Contains(got, ":p@") {
			t.Fatalf("redaction descriptor leaked credential text: %q", got)
		}
	}
	// Nothing credential-shaped: unchanged.
	if got := maskURLForLog("udp://loghost:514"); got != "udp://loghost:514" {
		t.Fatalf("benign input altered: %q", got)
	}
}

// S-3: the validation-failure slog line must not carry the syslog URL's
// password; scheme/host/port stay for triage.
func TestSyslogURLCheckFailedLogMasksPassword(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if err := validateSyslogURL("udp://ops:s3cret-pw@loghost:514"); err == nil {
		t.Fatal("userinfo url must fail validation")
	}
	out := buf.String()
	if !strings.Contains(out, "loghost:514") {
		t.Fatalf("log must keep scheme/host/port for correlation: %s", out)
	}
	if !strings.Contains(out, "ops:******@") {
		t.Fatalf("log must carry the masked userinfo: %s", out)
	}
	if strings.Contains(out, "s3cret-pw") {
		t.Fatalf("password leaked into the server log: %s", out)
	}
}

// The unparseable-but-credential-shaped form (invalid port defeats
// url.Parse while user:pass@ survives verbatim) must not reach the log either.
func TestSyslogURLCheckFailedLogRedactsUnparseableInput(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if err := validateSyslogURL("udp://ops:s3cret-pw@loghost:notaport"); err == nil {
		t.Fatal("unparseable url must fail validation")
	}
	out := buf.String()
	if strings.Contains(out, "s3cret-pw") {
		t.Fatalf("password leaked into the server log: %s", out)
	}
	if !strings.Contains(out, "redacted input") {
		t.Fatalf("unparseable input must be replaced, got: %s", out)
	}
}
