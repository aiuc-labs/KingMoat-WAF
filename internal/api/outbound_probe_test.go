package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/store"
)

// selfSignedCert generates an in-memory self-signed TLS certificate for the
// localhost loopback (probe tests only).
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "probe-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// closedTCPAddr returns a loopback address whose listener is already closed
// (deterministic connection-refused target).
func closedTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// TestProbeHTTPAuthMatrix: the probe must send Basic auth and classify
// 401/403 as auth_failed (the legacy probe treated them as healthy), 5xx and
// other 4xx as server_error.
func TestProbeHTTPAuthMatrix(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		srvUser    string
		srvPass    string
		sendUser   string
		sendPass   string
		wantState  string
		wantReason string
	}{
		{name: "ok with correct auth", status: 200, srvUser: "u", srvPass: "p", sendUser: "u", sendPass: "p", wantState: probeStateOK},
		{name: "401 wrong password", status: 200, srvUser: "u", srvPass: "p", sendUser: "u", sendPass: "WRONG", wantState: probeStateFail, wantReason: reasonAuthFailed},
		{name: "401 no auth", status: 200, srvUser: "u", srvPass: "p", wantState: probeStateFail, wantReason: reasonAuthFailed},
		{name: "403 forbidden", status: 403, wantState: probeStateFail, wantReason: reasonAuthFailed},
		{name: "500 server error", status: 500, wantState: probeStateFail, wantReason: reasonServerError},
		{name: "404 other 4xx", status: 404, wantState: probeStateFail, wantReason: reasonServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.srvUser != "" {
					gotUser, gotPass, ok := r.BasicAuth()
					if !ok || gotUser != tc.srvUser || gotPass != tc.srvPass {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
				}
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			for _, b := range []struct{ name, probe string }{
				{"elasticsearch", "/_cluster/health"},
				{"loki", "/ready"},
				{"clickhouse", "/?query=SELECT%201"},
			} {
				res := probeHTTP(context.Background(), b.name, srv.URL, b.probe, tc.sendUser, tc.sendPass)
				if res.state != tc.wantState || res.reason != tc.wantReason {
					t.Fatalf("%s: state=%s reason=%s, want %s/%s (detail: %s)",
						b.name, res.state, res.reason, tc.wantState, tc.wantReason, res.detail)
				}
			}
		})
	}
}

// TestProbeHTTPNoRedirect: the probe must not chase 3xx responses (no
// credential leak to a redirect target).
func TestProbeHTTPNoRedirect(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	res := probeHTTP(context.Background(), "elasticsearch", srv.URL, "/redirect", "", "")
	if res.state != probeStateFail || res.reason != reasonServerError {
		t.Fatalf("redirect = %s/%s, want fail/server_error", res.state, res.reason)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("handler hit %d times, want 1 (redirect target must not be requested)", n)
	}
}

// TestProbeHTTPNoEnvProxy: the probe must ignore HTTP(S)_PROXY.
func TestProbeHTTPNoEnvProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	res := probeHTTP(context.Background(), "elasticsearch", srv.URL, "/_cluster/health", "", "")
	if res.state != probeStateOK {
		t.Fatalf("env proxy must be ignored for probe dials, got %s (%s)", res.state, res.detail)
	}
}

// TestProbeSyslogUDPDegraded: UDP can only prove address resolution — the
// verdict is degraded (ok stays true for legacy consumers), never a plain ok.
func TestProbeSyslogUDPDegraded(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	res := probeSink(context.Background(), &config.ShipperSettings{
		Type: "syslog", URL: "udp://" + pc.LocalAddr().String(),
	})
	if res.state != probeStateDegraded || res.reason != "" {
		t.Fatalf("udp = %s/%q, want degraded without reason", res.state, res.reason)
	}
	if !strings.Contains(res.detail, "best-effort") {
		t.Fatalf("udp detail must explain best-effort delivery: %s", res.detail)
	}
	// unparseable target → config problem, no network activity
	res2 := probeSink(context.Background(), &config.ShipperSettings{
		Type: "syslog", URL: "udp://[::1:514",
	})
	if res2.state != probeStateFail || res2.reason != reasonConfigIncomplete {
		t.Fatalf("bad udp target = %s/%s, want fail/config_incomplete", res2.state, res2.reason)
	}
}

// TestProbeSyslogTCPOK: a live TCP listener proves reachability; protocol can
// come from URL scheme or from the syslog.protocol override.
func TestProbeSyslogTCPOK(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	res := probeSink(context.Background(), &config.ShipperSettings{
		Type: "syslog", URL: "tcp://" + l.Addr().String(),
	})
	if res.state != probeStateOK {
		t.Fatalf("tcp = %s/%s (%s), want ok", res.state, res.reason, res.detail)
	}
	// protocol field overrides the URL scheme
	res2 := probeSink(context.Background(), &config.ShipperSettings{
		Type: "syslog", URL: "udp://" + l.Addr().String(),
		Syslog: &config.SyslogSettings{Protocol: "tcp"},
	})
	if res2.state != probeStateOK {
		t.Fatalf("protocol override = %s/%s (%s), want ok", res2.state, res2.reason, res2.detail)
	}
	// refused connection → unreachable
	res3 := probeSink(context.Background(), &config.ShipperSettings{
		Type: "syslog", URL: "tcp://" + closedTCPAddr(t),
	})
	if res3.state != probeStateFail || res3.reason != reasonUnreachable {
		t.Fatalf("tcp refused = %s/%s, want fail/unreachable", res3.state, res3.reason)
	}
}

// TestProbeSyslogTLSAlignment: the probe must honor tls_skip_verify exactly
// like the runtime transport (verify by default; skip when opted in).
func TestProbeSyslogTLSAlignment(t *testing.T) {
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake() // complete the handshake so the client sees the certificate
				}
				c.Close()
			}()
		}
	}()
	addr := l.Addr().String()

	// default (verify): the self-signed certificate must fail as tls_error
	res := probeSink(context.Background(), &config.ShipperSettings{
		Type: "syslog", URL: "tls://" + addr,
	})
	if res.state != probeStateFail || res.reason != reasonTLSError {
		t.Fatalf("tls verify = %s/%s (%s), want fail/tls_error", res.state, res.reason, res.detail)
	}
	// skip=true mirrors the runtime → degraded with an explicit hint
	res2 := probeSink(context.Background(), &config.ShipperSettings{
		Type:   "syslog",
		URL:    "tls://" + addr,
		Syslog: &config.SyslogSettings{Protocol: "tls", TLSSkipVerify: true},
	})
	if res2.state != probeStateDegraded {
		t.Fatalf("tls skip=true = %s/%s (%s), want degraded", res2.state, res2.reason, res2.detail)
	}
	if !strings.Contains(res2.detail, "证书未校验") {
		t.Fatalf("tls skip=true detail must hint at skipped verification: %s", res2.detail)
	}
}

// fakeS3 is a minimal S3-compatible endpoint simulating the verdict paths of
// HEAD bucket (BucketExists) and ListObjectsV2 (the read-only fallback).
type fakeS3 struct {
	headStatus int // status for HEAD /bucket
	listStatus int // status for GET /bucket?list-type=2 (0 = 200)
	listHits   atomic.Int64
	headHits   atomic.Int64
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		f.headHits.Add(1)
		if f.headStatus == http.StatusOK {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(f.headStatus) // no body: matches real HEAD semantics
		return
	}
	f.listHits.Add(1)
	status := f.listStatus
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	if status >= 400 {
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>denied</Message></Error>`))
		return
	}
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>bkt</Name><Prefix></Prefix><KeyCount>0</KeyCount><MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>`))
}

// TestProbeS3Verdicts: the s3 probe verifies credentials read-only via the
// minio client (BucketExists + the single-object list fallback), classifying
// auth errors, missing buckets and reachability distinctly.
func TestProbeS3Verdicts(t *testing.T) {
	noSSL := false
	cases := []struct {
		name       string
		headStatus int
		listStatus int
		wantState  string
		wantReason string
	}{
		{name: "ok", headStatus: 200, wantState: probeStateOK},
		{name: "auth failed on both", headStatus: 403, listStatus: 403, wantState: probeStateFail, wantReason: reasonAuthFailed},
		{name: "head denied but list works", headStatus: 403, wantState: probeStateOK},
		{name: "bucket missing", headStatus: 404, wantState: probeStateFail, wantReason: reasonBucketMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeS3{headStatus: tc.headStatus, listStatus: tc.listStatus}
			srv := httptest.NewServer(f)
			defer srv.Close()
			addr := strings.TrimPrefix(srv.URL, "http://")
			res := probeSink(context.Background(), &config.ShipperSettings{
				Type: "s3", Endpoint: addr, Bucket: "bkt", AccessKey: "AKIA-test", SecretKey: "sk-test", UseSSL: &noSSL,
			})
			if res.state != tc.wantState || res.reason != tc.wantReason {
				t.Fatalf("s3 = %s/%s (%s), want %s/%s", res.state, res.reason, res.detail, tc.wantState, tc.wantReason)
			}
		})
	}
}

// TestProbeS3Unreachable: dial failure short-circuits before any credential
// check and reports unreachable.
func TestProbeS3Unreachable(t *testing.T) {
	res := probeSink(context.Background(), &config.ShipperSettings{
		Type: "s3", Endpoint: closedTCPAddr(t), Bucket: "bkt", AccessKey: "ak", SecretKey: "sk",
	})
	if res.state != probeStateFail || res.reason != reasonUnreachable {
		t.Fatalf("s3 unreachable = %s/%s (%s), want fail/unreachable", res.state, res.reason, res.detail)
	}
}

// TestProbeS3IncompleteConfig: missing keys answer config_incomplete without
// any network activity.
func TestProbeS3IncompleteConfig(t *testing.T) {
	res := probeSink(context.Background(), &config.ShipperSettings{
		Type: "s3", Endpoint: "minio.internal:9000", Bucket: "bkt",
	})
	if res.state != probeStateFail || res.reason != reasonConfigIncomplete {
		t.Fatalf("s3 incomplete = %s/%s, want fail/config_incomplete", res.state, res.reason)
	}
}

// TestProbeKafkaFailure: a dead broker answers fail/unreachable.
func TestProbeKafkaFailure(t *testing.T) {
	res := probeSink(context.Background(), &config.ShipperSettings{
		Type: "kafka", Brokers: []string{closedTCPAddr(t)}, Topic: "kingmoat-audit",
	})
	if res.state != probeStateFail || res.reason != reasonUnreachable {
		t.Fatalf("kafka = %s/%s (%s), want fail/unreachable", res.state, res.reason, res.detail)
	}
}

// TestKafkaProbeTransportTLSAlignment: the kafka probe transport must mirror
// the shipper's tri-state tls_skip_verify (nil = legacy skip, explicit wins).
func TestKafkaProbeTransportTLSAlignment(t *testing.T) {
	yes, no := true, false
	tr, fail := kafkaProbeTransport(&sinkTarget{UseTLS: true})
	if fail.state != "" {
		t.Fatalf("unexpected failure: %s", fail.detail)
	}
	if tr.TLS == nil || !tr.TLS.InsecureSkipVerify {
		t.Fatal("nil tls_skip_verify must keep the legacy zero-config skip=true")
	}
	tr, _ = kafkaProbeTransport(&sinkTarget{UseTLS: true, TLSSkipVerify: &no})
	if tr.TLS == nil || tr.TLS.InsecureSkipVerify {
		t.Fatal("explicit tls_skip_verify=false must verify certificates")
	}
	tr, _ = kafkaProbeTransport(&sinkTarget{UseTLS: true, TLSSkipVerify: &yes})
	if tr.TLS == nil || !tr.TLS.InsecureSkipVerify {
		t.Fatal("explicit tls_skip_verify=true must skip verification")
	}
}

// TestProbeDetailRedaction: passwords and URL userinfo never reach detail.
func TestProbeDetailRedaction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	const pw = "Sup3r-Secret-Pass!"
	res := probeSink(context.Background(), &config.ShipperSettings{
		Type: "elasticsearch", URL: srv.URL, Username: "svc-account", Password: pw,
	})
	if res.state != probeStateFail || res.reason != reasonAuthFailed {
		t.Fatalf("probe = %s/%s, want fail/auth_failed", res.state, res.reason)
	}
	if strings.Contains(res.detail, pw) || strings.Contains(res.detail, "svc-account") {
		t.Fatalf("detail leaks credentials: %s", res.detail)
	}
	// userinfo embedded in the URL is stripped as well
	res2 := probeSink(context.Background(), &config.ShipperSettings{
		Type: "elasticsearch", URL: "http://alice:Url-Pass-123@" + strings.TrimPrefix(srv.URL, "http://"),
	})
	if strings.Contains(res2.detail, "Url-Pass-123") || strings.Contains(res2.detail, "alice") {
		t.Fatalf("detail leaks URL userinfo: %s", res2.detail)
	}
}

// TestProbeSinkConfigValidation: incomplete sections answer config_incomplete
// (or unsupported) without network activity.
func TestProbeSinkConfigValidation(t *testing.T) {
	cases := []struct {
		name       string
		sh         *config.ShipperSettings
		wantReason string
	}{
		{name: "nil section", sh: nil, wantReason: reasonConfigIncomplete},
		{name: "no type", sh: &config.ShipperSettings{}, wantReason: reasonConfigIncomplete},
		{name: "s3 no keys", sh: &config.ShipperSettings{Type: "s3", Endpoint: "m:9000", Bucket: "b"}, wantReason: reasonConfigIncomplete},
		{name: "kafka no brokers", sh: &config.ShipperSettings{Type: "kafka", Topic: "t"}, wantReason: reasonConfigIncomplete},
		{name: "kafka sasl without creds", sh: &config.ShipperSettings{Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t", SASL: "plain"}, wantReason: reasonConfigIncomplete},
		{name: "syslog bad scheme", sh: &config.ShipperSettings{Type: "syslog", URL: "http://10.0.0.5:514"}, wantReason: reasonConfigIncomplete},
		{name: "unknown type", sh: &config.ShipperSettings{Type: "bogus"}, wantReason: reasonUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := probeSink(context.Background(), tc.sh)
			if res.state != probeStateFail || res.reason != tc.wantReason {
				t.Fatalf("state=%s reason=%s (%s), want fail/%s", res.state, res.reason, res.detail, tc.wantReason)
			}
		})
	}
}

// TestLogshipTestResponseFields: the legacy endpoint keeps its four fields and
// appends state/reason; ok=true covers ok AND degraded.
func TestLogshipTestResponseFields(t *testing.T) {
	center, err := configcenter.Open(t.TempDir()+"/probe.db", seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer center.Close()
	srv := httptest.NewServer(New(Options{SkipBootstrap: true, Center: center}).Handler())
	defer srv.Close()

	post := func() map[string]any {
		t.Helper()
		resp, err := http.Post(srv.URL+"/api/logship/test", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("logship/test = %d", resp.StatusCode)
		}
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	// no shipper configured → fail/config_incomplete, legacy fields intact
	body := post()
	if body["ok"] != false {
		t.Fatalf("ok = %v, want false", body["ok"])
	}
	if body["state"] != probeStateFail || body["reason"] != reasonConfigIncomplete {
		t.Fatalf("state/reason = %v/%v, want fail/config_incomplete", body["state"], body["reason"])
	}
	if _, isStr := body["detail"].(string); !isStr {
		t.Fatalf("detail missing: %v", body)
	}

	// configured syslog UDP target → ok=true + state=degraded
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	cfg := seedCfg()
	cfg.LogShipper = &config.ShipperSettings{Type: "syslog", URL: "udp://" + pc.LocalAddr().String(), Syslog: &config.SyslogSettings{}}
	if _, err := center.Publish(cfg, "test", "probe"); err != nil {
		t.Fatal(err)
	}
	body2 := post()
	if body2["ok"] != true {
		t.Fatalf("ok = %v, want true for degraded udp", body2["ok"])
	}
	if body2["state"] != probeStateDegraded {
		t.Fatalf("state = %v, want degraded", body2["state"])
	}
	if body2["type"] != "syslog" {
		t.Fatalf("type = %v, want syslog", body2["type"])
	}
}

// ---------------------------------------------------------------------------
// Endpoint-level tests for POST /api/outbound/test and the legacy
// POST /api/logship/test facade (rbac, single-flight, read-only guarantees,
// body overlay semantics, channel reuse).
// ---------------------------------------------------------------------------

// probeTestHash composes a console-storable argon2id hash for test accounts
// (fixed salt, same format as the login tests).
func probeTestHash(password string) string {
	return "$argon2id$v=19$m=65536,t=3,p=4$" + mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash(password)
}

// outboundTestAPIServer builds an auth-enabled console server seeded with
// admin/operator/auditor accounts so the outbound-test RBAC gate is
// exercised (dev-mode servers skip auth entirely).
func outboundTestAPIServer(t *testing.T, cfg *config.Config) (*httptest.Server, *configcenter.Center, *Server, func(user, pass string) *http.Client) {
	t.Helper()
	hash := probeTestHash("hunter2")
	center, err := configcenter.Open(t.TempDir()+"/outbound-test.db", cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	seedStoreAdmin(t, center, hash)
	if _, err := center.Store().CreateUser("ops", probeTestHash("op-pass"), store.RoleOperator); err != nil {
		t.Fatal(err)
	}
	if _, err := center.Store().CreateUser("aud", probeTestHash("aud-pass"), store.RoleAuditor); err != nil {
		t.Fatal(err)
	}
	audit, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	srv := New(Options{SkipBootstrap: true, Center: center, Logs: audit, Auth: NewAuth(hash)})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	login := func(user, pass string) *http.Client {
		resp, err := http.Post(ts.URL+"/api/login", "application/json", bytes.NewReader(mustJSON(t, map[string]string{"username": user, "password": pass})))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login %s = %d", user, resp.StatusCode)
		}
		return &http.Client{Transport: roundTripperWithCookie{cookie: resp.Cookies()[0]}}
	}
	return ts, center, srv, login
}

// postProbeJSON posts an optional JSON payload and decodes the response body.
func postProbeJSON(t *testing.T, client *http.Client, url string, payload any) (int, map[string]any) {
	t.Helper()
	var resp *http.Response
	var err error
	if payload == nil {
		resp, err = client.Post(url, "application/json", nil)
	} else {
		resp, err = client.Post(url, "application/json", bytes.NewReader(mustJSON(t, payload)))
	}
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return resp.StatusCode, body
}

// newAuthSink returns an ES-shaped sink requiring exactly the given
// basic-auth credentials, counting every request.
func newAuthSink(t *testing.T, user, pass string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if user != "" {
			if u, p, ok := r.BasicAuth(); !ok || u != user || p != pass {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestOutboundTestAccessControl: unauthenticated → 401, auditor → 403,
// occupied single-flight slot → 429, unknown kind → 400, operator on an
// unconfigured console → 200 + fail/config_incomplete.
func TestOutboundTestAccessControl(t *testing.T) {
	ts, _, srv, login := outboundTestAPIServer(t, seedCfg())

	resp, err := http.Post(ts.URL+"/api/outbound/test", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", resp.StatusCode)
	}

	aud := login("aud", "aud-pass")
	if code, _ := postProbeJSON(t, aud, ts.URL+"/api/outbound/test", map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("auditor = %d, want 403", code)
	}

	ops := login("ops", "op-pass")
	if code, _ := postProbeJSON(t, ops, ts.URL+"/api/outbound/test", map[string]any{"kind": "bogus"}); code != http.StatusBadRequest {
		t.Fatalf("bad kind = %d, want 400", code)
	}

	srv.probeInflight.Store(1)
	if code, _ := postProbeJSON(t, ops, ts.URL+"/api/outbound/test", map[string]any{}); code != http.StatusTooManyRequests {
		t.Fatalf("in-flight = %d, want 429", code)
	}
	srv.probeInflight.Store(0)

	code, body := postProbeJSON(t, ops, ts.URL+"/api/outbound/test", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("operator = %d, want 200", code)
	}
	if body["state"] != probeStateFail || body["reason"] != reasonConfigIncomplete {
		t.Fatalf("state/reason = %v/%v, want fail/config_incomplete", body["state"], body["reason"])
	}
}

// TestOutboundTestOverlayAndReadOnly: body settings overlay the saved
// section (present keys override — including an explicit empty string —,
// absent keys keep the saved value); the probe never touches the config
// store (revision id, revision count and the saved config pointer are
// unchanged) and the audit entry carries no credential literals.
func TestOutboundTestOverlayAndReadOnly(t *testing.T) {
	const user, pass, wrong = "u", "S3cr3t-Pass", "Wr0ng-Pass!"
	sink, hits := newAuthSink(t, user, pass)
	cfg := seedCfg()
	cfg.LogShipper = &config.ShipperSettings{Type: "elasticsearch", URL: sink.URL, Username: user, Password: pass}
	ts, center, _, login := outboundTestAPIServer(t, cfg)
	ops := login("ops", "op-pass")
	ep := ts.URL + "/api/outbound/test"

	rev1, cfgPtr1 := center.Current()
	revs1, err := center.Store().ListRevisions(100)
	if err != nil {
		t.Fatal(err)
	}

	// absent keys keep the saved values → saved credentials pass
	code, body := postProbeJSON(t, ops, ep, map[string]any{})
	if code != http.StatusOK || body["state"] != probeStateOK {
		t.Fatalf("saved creds = %d %v/%v (%v), want ok", code, body["state"], body["reason"], body["detail"])
	}

	// a present key overrides: wrong password → auth_failed
	code, body = postProbeJSON(t, ops, ep, map[string]any{"settings": map[string]any{"password": wrong}})
	if code != http.StatusOK || body["state"] != probeStateFail || body["reason"] != reasonAuthFailed {
		t.Fatalf("wrong password = %d %v/%v (%v), want fail/auth_failed", code, body["state"], body["reason"], body["detail"])
	}

	// an explicit empty string overrides too: no basic auth header → 401
	code, body = postProbeJSON(t, ops, ep, map[string]any{"settings": map[string]any{"username": ""}})
	if code != http.StatusOK || body["reason"] != reasonAuthFailed {
		t.Fatalf("empty username = %d %v/%v (%v), want auth_failed", code, body["state"], body["reason"], body["detail"])
	}

	// read-only: revision id, count and the saved config pointer unchanged
	rev2, cfgPtr2 := center.Current()
	revs2, err := center.Store().ListRevisions(100)
	if err != nil {
		t.Fatal(err)
	}
	if rev1 != rev2 || cfgPtr1 != cfgPtr2 || len(revs1) != len(revs2) {
		t.Fatalf("config store mutated: rev %d→%d, same ptr %v, revisions %d→%d",
			rev1, rev2, cfgPtr1 == cfgPtr2, len(revs1), len(revs2))
	}
	if n := hits.Load(); n != 3 {
		t.Fatalf("sink hit %d times, want 3 (one per probe)", n)
	}

	// audit trail: action outbound.test with kind/state/target/latency and
	// WITHOUT any credential literal
	logs, err := center.Store().ListChangeLogs(50)
	if err != nil {
		t.Fatal(err)
	}
	found, sawFail := false, false
	for _, l := range logs {
		if l.Action != "outbound.test" {
			continue
		}
		found = true
		if strings.Contains(l.Detail, wrong) || strings.Contains(l.Detail, pass) {
			t.Fatalf("audit detail leaks credentials: %s", l.Detail)
		}
		if !strings.HasPrefix(l.Detail, "kind=audit state=") ||
			!strings.Contains(l.Detail, "target=") || !strings.Contains(l.Detail, "latency_ms=") {
			t.Fatalf("audit detail lacks the agreed fields: %s", l.Detail)
		}
		if strings.Contains(l.Detail, "state=fail") {
			sawFail = true
		}
	}
	if !found || !sawFail {
		t.Fatalf("outbound.test audit entries missing (found=%v sawFail=%v) among %d", found, sawFail, len(logs))
	}
}

// TestOutboundTestChannelReuse: access/ai sections with use_audit_channel on
// resolve through config.Resolve*Out + the runtime conversion — a body that
// only carries identity fields probes the SAVED audit channel (and the
// forced-enabled temp section), and a missing channel answers
// config_incomplete.
func TestOutboundTestChannelReuse(t *testing.T) {
	sink, hits := newAuthSink(t, "u", "S3cr3t-Pass")
	cfg := seedCfg()
	cfg.LogShipper = &config.ShipperSettings{Type: "elasticsearch", URL: sink.URL, Username: "u", Password: "S3cr3t-Pass"}
	cfg.AccessLog = &config.AccessLogSettings{Enabled: false, UseAuditChannel: true, Index: "kingmoat_access"}
	cfg.AiAudit = &config.AIAuditSettings{Ship: &config.AIAuditShipSettings{Enabled: false, UseAuditChannel: true, Index: "kingmoat_ai_sessions"}}
	ts, _, _, login := outboundTestAPIServer(t, cfg)
	ops := login("ops", "op-pass")
	ep := ts.URL + "/api/outbound/test"

	// access: the body only carries identity fields → the saved audit
	// channel is probed (type/url/auth all come from log_shipper)
	code, body := postProbeJSON(t, ops, ep, map[string]any{"kind": "access", "settings": map[string]any{"index": "kingmoat_access"}})
	if code != http.StatusOK || body["state"] != probeStateOK || body["type"] != "elasticsearch" {
		t.Fatalf("access reuse = %d %v/%v type=%v (%v), want ok/elasticsearch", code, body["state"], body["reason"], body["type"], body["detail"])
	}
	// ai: empty settings reuse the channel as well
	code, body = postProbeJSON(t, ops, ep, map[string]any{"kind": "ai", "settings": map[string]any{}})
	if code != http.StatusOK || body["state"] != probeStateOK || body["type"] != "elasticsearch" {
		t.Fatalf("ai reuse = %d %v/%v type=%v (%v), want ok/elasticsearch", code, body["state"], body["reason"], body["type"], body["detail"])
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("sink hit %d times, want 2", n)
	}

	// switch on but no saved channel → config_incomplete naming log_shipper
	cfg2 := seedCfg()
	cfg2.AccessLog = &config.AccessLogSettings{Enabled: false, UseAuditChannel: true}
	ts2, _, _, login2 := outboundTestAPIServer(t, cfg2)
	ops2 := login2("ops", "op-pass")
	code, body = postProbeJSON(t, ops2, ts2.URL+"/api/outbound/test", map[string]any{"kind": "access", "settings": map[string]any{}})
	if code != http.StatusOK || body["state"] != probeStateFail || body["reason"] != reasonConfigIncomplete {
		t.Fatalf("missing channel = %d %v/%v (%v), want fail/config_incomplete", code, body["state"], body["reason"], body["detail"])
	}
	if s, _ := body["detail"].(string); !strings.Contains(s, "log_shipper") {
		t.Fatalf("missing-channel detail must name log_shipper: %v", body["detail"])
	}
}

// TestLogshipTestLegacyCompat: the legacy endpoint keeps its fields, accepts
// an optional body as kind=audit (the body kind is IGNORED) and shares the
// gates with the unified endpoint.
func TestLogshipTestLegacyCompat(t *testing.T) {
	sink, hits := newAuthSink(t, "u", "S3cr3t-Pass")
	cfg := seedCfg()
	cfg.LogShipper = &config.ShipperSettings{Type: "elasticsearch", URL: sink.URL, Username: "u", Password: "S3cr3t-Pass"}
	ts, _, _, login := outboundTestAPIServer(t, cfg)
	ops := login("ops", "op-pass")
	ep := ts.URL + "/api/logship/test"

	// no body: the four legacy fields are present and mean what they meant
	code, body := postProbeJSON(t, ops, ep, nil)
	if code != http.StatusOK {
		t.Fatalf("no body = %d, want 200", code)
	}
	for _, k := range []string{"ok", "type", "latency_ms", "detail", "state"} {
		if _, ok := body[k]; !ok {
			t.Fatalf("legacy response missing %q: %v", k, body)
		}
	}
	if body["ok"] != true || body["type"] != "elasticsearch" {
		t.Fatalf("legacy fields = ok:%v type:%v", body["ok"], body["type"])
	}

	// a body with kind=ai is still pinned to the audit channel
	code, body = postProbeJSON(t, ops, ep, map[string]any{"kind": "ai", "settings": map[string]any{"password": "Wr0ng-Pass!"}})
	if body["state"] != probeStateFail || body["reason"] != reasonAuthFailed || body["type"] != "elasticsearch" {
		t.Fatalf("pinned audit = %v/%v type=%v, want fail/auth_failed/elasticsearch", body["state"], body["reason"], body["type"])
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("sink hit %d times, want 2", n)
	}
}

// TestProbeSyslogUDPBudgetBound: UDP resolution is ctx-aware — a canceled
// probe budget must abort the resolution and classify as timeout instead of
// letting a black-holed DNS server hold the single-flight slot beyond the
// ~8s budget. The verdict for a resolvable target stays degraded (only the
// failure path changed).
func TestProbeSyslogUDPBudgetBound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := probeSyslog(ctx, &sinkTarget{Type: "syslog", URL: "udp://budget-bound.invalid:514"})
	if res.state != probeStateFail || res.reason != reasonTimeout {
		t.Fatalf("canceled budget = %s/%s (%s), want fail/timeout", res.state, res.reason, res.detail)
	}

	// a healthy ctx still resolves loopback and answers degraded
	if res2 := probeSyslog(context.Background(), &sinkTarget{Type: "syslog", URL: "udp://127.0.0.1:514"}); res2.state != probeStateDegraded {
		t.Fatalf("resolvable target = %s/%s (%s), want degraded", res2.state, res2.reason, res2.detail)
	}
}

// TestAddOutboundSecretsUsernameNotRedacted: usernames are operator-visible
// config, not secrets — they must not enter the literal redaction table, or
// the blind strings.ReplaceAll corrupts detail text and the audit
// "target=host:port" field whenever the username is a common word. Passwords
// and s3 keys stay redacted.
func TestAddOutboundSecretsUsernameNotRedacted(t *testing.T) {
	const user, pass = "elastic", "S3cr3t-Access-Pass"
	cfg := &config.Config{
		AccessLog: &config.AccessLogSettings{
			Enabled: true, Type: "elasticsearch", URL: "http://elastic.internal:9200",
			Username: user, Password: pass,
		},
		AiAudit: &config.AIAuditSettings{Ship: &config.AIAuditShipSettings{
			Enabled: true, Type: "elasticsearch", URL: "http://ai.internal:9200",
			Username: user, Password: pass,
		}},
	}
	pr := newProbeRedactor()
	addOutboundSecrets(pr, cfg)

	detail := "elasticsearch 认证失败：目标返回 401（elastic.internal:9200，凭证 " + pass + "）"
	scrubbed := pr.scrub(detail)
	if strings.Contains(scrubbed, pass) {
		t.Fatalf("password must be redacted from detail: %s", scrubbed)
	}
	if !strings.Contains(scrubbed, "elastic") {
		t.Fatalf("username must not be rewritten in detail (common word stays readable): %s", scrubbed)
	}

	// the audit trail keeps host:port readable even when the host carries the
	// username as a substring
	if got := pr.scrub("elastic.internal:9200"); got != "elastic.internal:9200" {
		t.Fatalf("audit target must not be rewritten: %q", got)
	}
}

// TestSynthOutboundTargetVerbatimVerdicts pins the verdict TEXTS of the
// access/ai probe branches (A1-2): after collapsing the duplicated pipelines
// into resolveOutboundTarget, the state/reason/detail triple must stay
// verbatim — the section-absent and untyped config_incomplete texts, the
// shared use_audit_channel missing-channel text (pinned as a literal here so
// a constant rewording fails this test), and the validateTarget texts passed
// through unchanged. The "flat prefix" case additionally proves the ai branch
// still runs the runtime ShipSettings conversion (the deprecated flat prefix
// reaches the probe target through it).
func TestSynthOutboundTargetVerbatimVerdicts(t *testing.T) {
	cfg := seedCfg() // no outbound sections configured
	cases := []struct {
		name       string
		kind       string
		ov         *outboundOverlay
		wantTarget bool
		wantReason string
		wantDetail string
	}{
		{
			name: "access section absent", kind: "access", ov: &outboundOverlay{},
			wantReason: reasonConfigIncomplete, wantDetail: "access_log 外发未配置",
		},
		{
			name: "ai section absent", kind: "ai", ov: &outboundOverlay{},
			wantReason: reasonConfigIncomplete, wantDetail: "ai_audit.ship 外发未配置",
		},
		{
			name: "access reuse on without channel", kind: "access",
			ov:         &outboundOverlay{access: &config.AccessLogSettings{UseAuditChannel: true}},
			wantReason: reasonConfigIncomplete,
			wantDetail: "use_audit_channel 已开启，但防护日志通道（log_shipper）未配置，请先配置并保存防护日志外发",
		},
		{
			name: "ai reuse on without channel", kind: "ai",
			ov:         &outboundOverlay{aiShip: &config.AIAuditShipSettings{UseAuditChannel: true}},
			wantReason: reasonConfigIncomplete,
			wantDetail: "use_audit_channel 已开启，但防护日志通道（log_shipper）未配置，请先配置并保存防护日志外发",
		},
		{
			name: "access without type", kind: "access",
			ov:         &outboundOverlay{access: &config.AccessLogSettings{}},
			wantReason: reasonConfigIncomplete, wantDetail: "access_log 外发未配置",
		},
		{
			name: "ai without type", kind: "ai",
			ov:         &outboundOverlay{aiShip: &config.AIAuditShipSettings{}},
			wantReason: reasonConfigIncomplete, wantDetail: "ai_audit.ship 外发未配置",
		},
		{
			name: "access s3 without block keeps the validateTarget text", kind: "access",
			ov:         &outboundOverlay{access: &config.AccessLogSettings{Type: "s3"}},
			wantReason: reasonConfigIncomplete, wantDetail: "s3 需要配置 endpoint 与 bucket",
		},
		{
			name: "ai s3 without block keeps the validateTarget text", kind: "ai",
			ov:         &outboundOverlay{aiShip: &config.AIAuditShipSettings{Type: "s3"}},
			wantReason: reasonConfigIncomplete, wantDetail: "s3 需要配置 endpoint 与 bucket",
		},
		{
			// Flat prefix without an s3 block: the runtime conversion seeds the
			// s3 block, then validateTarget answers config_incomplete for the
			// missing endpoint/bucket — proving the conversion ran.
			name: "ai flat prefix seeds the s3 block through the conversion", kind: "ai",
			ov:         &outboundOverlay{aiShip: &config.AIAuditShipSettings{Type: "s3", Prefix: "kingmoat/ai"}},
			wantReason: reasonConfigIncomplete, wantDetail: "s3 需要配置 endpoint 与 bucket",
		},
		{
			name: "access complete section builds the target", kind: "access",
			ov:         &outboundOverlay{access: &config.AccessLogSettings{Type: "elasticsearch", URL: "http://es.internal:9200"}},
			wantTarget: true,
		},
		{
			name: "ai complete section builds the target", kind: "ai",
			ov:         &outboundOverlay{aiShip: &config.AIAuditShipSettings{Type: "elasticsearch", URL: "http://es.internal:9200"}},
			wantTarget: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, fail := synthOutboundTarget(tc.kind, tc.ov, cfg)
			if tc.wantTarget {
				if fail != nil || target == nil || target.Type == "" {
					t.Fatalf("want a probe target, got target=%v fail=%v/%s", target, fail, fail.detail)
				}
				return
			}
			if target != nil || fail == nil {
				t.Fatalf("want a config failure, got target=%v fail=%v", target, fail)
			}
			if fail.state != probeStateFail || fail.reason != tc.wantReason || fail.detail != tc.wantDetail {
				t.Fatalf("verdict drifted: state=%s reason=%s detail=%q, want %s/%s/%q",
					fail.state, fail.reason, fail.detail, probeStateFail, tc.wantReason, tc.wantDetail)
			}
		})
	}
	if missingAuditChannelMsg != "use_audit_channel 已开启，但防护日志通道（log_shipper）未配置，请先配置并保存防护日志外发" {
		t.Fatalf("missingAuditChannelMsg drifted: %q", missingAuditChannelMsg)
	}
}

// TestOutboundTestMissingChannelDetailEndpoint: the shared missing-channel
// verdict reaches the HTTP response verbatim for BOTH nested kinds (the
// endpoint renders the pipeline's fail result unmodified).
func TestOutboundTestMissingChannelDetailEndpoint(t *testing.T) {
	cfg := seedCfg()
	cfg.AccessLog = &config.AccessLogSettings{UseAuditChannel: true}
	cfg.AiAudit = &config.AIAuditSettings{Ship: &config.AIAuditShipSettings{UseAuditChannel: true}}
	ts, _, _, login := outboundTestAPIServer(t, cfg)
	ops := login("ops", "op-pass")
	ep := ts.URL + "/api/outbound/test"
	want := "use_audit_channel 已开启，但防护日志通道（log_shipper）未配置，请先配置并保存防护日志外发"
	for _, kind := range []string{"access", "ai"} {
		code, body := postProbeJSON(t, ops, ep, map[string]any{"kind": kind})
		if code != http.StatusOK || body["state"] != probeStateFail || body["reason"] != reasonConfigIncomplete {
			t.Fatalf("%s = %d %v/%v, want fail/config_incomplete", kind, code, body["state"], body["reason"])
		}
		if s, _ := body["detail"].(string); s != want {
			t.Fatalf("%s detail = %q, want %q", kind, s, want)
		}
	}
}

// TestOutboundSectionForceEnableUnknownTypeFailsFast pins C6: a section type
// outside the nestedOutboundSection closed set reports ok=false (the caller
// turns that into an explicit fail-fast verdict), and the two known types
// keep force-enable + usesChannel passthrough semantics unchanged.
func TestOutboundSectionForceEnableUnknownTypeFailsFast(t *testing.T) {
	if _, ok := outboundSectionForceEnable(&config.ShipperSettings{Type: "elasticsearch"}); ok {
		t.Fatal("a section type outside the closed set must report ok=false, not be probed silently")
	}
	access := &config.AccessLogSettings{UseAuditChannel: true}
	uses, ok := outboundSectionForceEnable(access)
	if !ok || !uses || !access.Enabled {
		t.Fatalf("access section = usesChannel %v / ok %v / enabled %v, want true/true/true", uses, ok, access.Enabled)
	}
	aiShip := &config.AIAuditShipSettings{}
	uses, ok = outboundSectionForceEnable(aiShip)
	if !ok || uses || !aiShip.Enabled {
		t.Fatalf("ai section = usesChannel %v / ok %v / enabled %v, want false/true/true", uses, ok, aiShip.Enabled)
	}
}

// TestValidateProbeSyslogURL pins the probe-side mirror of
// config.validateSyslogURL, including the userinfo rejection: the probe
// must refuse user:pass@ targets with the same Chinese, no-echo detail.
func TestValidateProbeSyslogURL(t *testing.T) {
	if pr := validateProbeSyslogURL("udp://logs.internal:514"); pr != nil {
		t.Fatalf("valid udp url rejected: %+v", pr)
	}
	if pr := validateProbeSyslogURL("//logs.internal:514"); pr != nil {
		t.Fatalf("scheme-less //host url rejected: %+v", pr)
	}
	if pr := validateProbeSyslogURL("logs.internal:514"); pr == nil ||
		!strings.Contains(pr.detail, "udp://host") {
		t.Fatalf("bare host must fail with the address-form detail, got %+v", pr)
	}
	if pr := validateProbeSyslogURL("http://logs.internal:514"); pr == nil ||
		!strings.Contains(pr.detail, "协议") {
		t.Fatalf("bad scheme must fail with the protocol detail, got %+v", pr)
	}
	for _, raw := range []string{"udp://admin:secret@logs.internal:514", "tcp://admin@logs.internal:514", "//admin:secret@logs.internal:514"} {
		pr := validateProbeSyslogURL(raw)
		if pr == nil || !strings.Contains(pr.detail, "用户名密码") {
			t.Fatalf("userinfo url %q must fail with the credential detail, got %+v", raw, pr)
		}
		if strings.Contains(pr.detail, "admin") || strings.Contains(pr.detail, "secret") {
			t.Fatalf("probe detail must not echo userinfo, got %q", pr.detail)
		}
	}
}
