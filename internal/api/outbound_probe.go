// Outbound-channel probe kernel: read-only connectivity + authentication
// checks for the six log-outbound sink types (elasticsearch, clickhouse,
// loki, s3, syslog, kafka), shared by the legacy POST /api/logship/test and
// the unified POST /api/outbound/test endpoints.
//
// Probe results use a three-state model (ok / degraded / fail) with a
// machine-readable reason and a redacted human-readable detail. Probing is
// strictly read-only: no test events, objects, messages or frames are ever
// written to the target.
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"

	"github.com/kingmoat/kingmoat/internal/aisession"
	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/s3sink"
	"github.com/kingmoat/kingmoat/internal/store"
)

// Three-state verdicts (response "state").
const (
	probeStateOK       = "ok"
	probeStateDegraded = "degraded"
	probeStateFail     = "fail"
)

// Machine-readable failure/degradation reasons (response "reason"). Keep in
// sync with the console contract: unreachable, auth_failed, tls_error,
// config_incomplete, server_error, timeout, bucket_missing, unsupported.
const (
	reasonUnreachable      = "unreachable"
	reasonAuthFailed       = "auth_failed"
	reasonTLSError         = "tls_error"
	reasonConfigIncomplete = "config_incomplete"
	reasonServerError      = "server_error"
	reasonTimeout          = "timeout"
	reasonBucketMissing    = "bucket_missing"
	reasonUnsupported      = "unsupported"
)

// probeStepTimeout bounds every single probe step (kept from the legacy
// probe), probeBudget bounds one whole request (multiple steps).
const (
	probeStepTimeout = 4 * time.Second
	probeBudget      = 8 * time.Second
)

// outboundProbeSinkTypes mirrors config.outboundSinkTypes (unexported there;
// the set is shared by the audit outbound and the reusing pipelines and is
// drift-guarded by the config package tests).
var outboundProbeSinkTypes = []string{"clickhouse", "elasticsearch", "loki", "s3", "syslog", "kafka"}

// probeCheck is one step of a multi-step probe walk (e.g. dial → s3).
type probeCheck struct {
	Step   string `json:"step"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// outboundProbeResponse is the unified three-state test payload. The legacy
// fields (ok / type / latency_ms / detail) keep their meaning; state / reason
// / checks are additive.
type outboundProbeResponse struct {
	State     string       `json:"state"`
	OK        bool         `json:"ok"`
	Type      string       `json:"type,omitempty"`
	LatencyMS int64        `json:"latency_ms"`
	Reason    string       `json:"reason,omitempty"`
	Detail    string       `json:"detail"`
	Checks    []probeCheck `json:"checks,omitempty"`
}

// probeResult is the internal three-state verdict of one sink probe.
type probeResult struct {
	state  string
	reason string
	detail string
	checks []probeCheck
}

func okProbe(detail string) probeResult {
	return probeResult{state: probeStateOK, detail: detail}
}

// degradedProbe: address/connectivity provable, end-to-end delivery or full
// authentication not provable with a read-only probe.
func degradedProbe(detail string) probeResult {
	return probeResult{state: probeStateDegraded, detail: detail}
}

func failProbe(reason, detail string) probeResult {
	return probeResult{state: probeStateFail, reason: reason, detail: detail}
}

func (r probeResult) withChecks(checks []probeCheck) probeResult {
	r.checks = checks
	return r
}

func checkOf(step string, r probeResult) probeCheck {
	return probeCheck{Step: step, State: r.state, Reason: r.reason}
}

// probeRedactor scrubs credential literals out of probe detail text. Library
// errors (http url.Error, config error %q echoes) can carry user input, so
// every detail goes through this before leaving the handler.
type probeRedactor struct {
	lits []string
}

func newProbeRedactor() *probeRedactor { return &probeRedactor{} }

func (pr *probeRedactor) addSecret(lit string) {
	if lit = strings.TrimSpace(lit); lit != "" {
		pr.lits = append(pr.lits, lit)
	}
}

// userinfoRe matches any scheme://userinfo@ prefix so URLs never leak a
// embedded username/password into detail text.
var userinfoRe = regexp.MustCompile(`(?i)([a-z][a-z0-9+.\-]*)://[^\s/@]+@`)

func (pr *probeRedactor) scrub(s string) string {
	for _, lit := range pr.lits {
		s = strings.ReplaceAll(s, lit, "***")
	}
	return userinfoRe.ReplaceAllString(s, "$1://***@")
}

func (pr *probeRedactor) scrubResult(r probeResult) probeResult {
	r.detail = pr.scrub(r.detail)
	return r
}

// sinkTarget is the normalized probe input shared by the three outbound
// section shapes (flat log_shipper, nested access_log, nested ai_audit.ship).
type sinkTarget struct {
	Type     string
	URL      string // http(s) backends, or the syslog target udp|tcp|tls://host[:port]
	Username string
	Password string

	// s3
	Endpoint      string
	Bucket        string
	AccessKey     string
	SecretKey     string
	Region        string // only the flat log_shipper shape carries a region
	Secure        bool   // s3 transport (https vs http), derived per shape
	S3RequireKeys bool   // flat shape: access_key/secret_key required (config.Validate parity)

	// kafka
	Brokers       []string
	Topic         string
	UseTLS        bool
	SASL          string
	TLSSkipVerify *bool

	// syslog
	Syslog *config.SyslogSettings
}

// shipperTarget normalizes the flat log_shipper section. The s3 endpoint
// derivation mirrors logshipper.newS3Target byte for byte: a scheme on the
// endpoint picks the transport, an explicit use_ssl overrides it, no scheme
// defaults to secure.
func shipperTarget(sh *config.ShipperSettings) *sinkTarget {
	t := &sinkTarget{
		Type:          strings.TrimSpace(sh.Type),
		URL:           sh.URL,
		Username:      sh.Username,
		Password:      sh.Password,
		Bucket:        sh.Bucket,
		AccessKey:     sh.AccessKey,
		SecretKey:     sh.SecretKey,
		Region:        sh.Region,
		S3RequireKeys: true,
		Brokers:       slices.Clone(sh.Brokers),
		Topic:         sh.Topic,
		UseTLS:        sh.UseTLS,
		SASL:          sh.SASL,
		TLSSkipVerify: sh.TLSSkipVerify,
		Syslog:        sh.Syslog,
	}
	endpoint := strings.TrimSpace(sh.Endpoint)
	secure := true
	if u, err := url.Parse(endpoint); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		endpoint = u.Host
		secure = u.Scheme == "https"
	}
	if sh.UseSSL != nil {
		secure = *sh.UseSSL
	}
	t.Endpoint = endpoint
	t.Secure = secure
	return t
}

// validateTarget mirrors the config-layer per-type outbound rules
// (Config.Validate for the flat shape, S3Settings.Validate /
// SyslogSettings.Validate / validateKafkaOutbound semantics for the nested
// shapes) so an incomplete section answers config_incomplete instead of a
// confusing transport error. nil = valid.
func validateTarget(t *sinkTarget) *probeResult {
	switch t.Type {
	case "elasticsearch", "clickhouse", "loki":
		if strings.TrimSpace(t.URL) == "" {
			return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete,
				detail: t.Type + " 外发未配置 url"}
		}
		u, err := url.Parse(strings.TrimSpace(t.URL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete,
				detail: t.Type + " url 必须是 http(s) 地址"}
		}
	case "s3":
		if strings.TrimSpace(t.Endpoint) == "" || strings.TrimSpace(t.Bucket) == "" {
			return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete,
				detail: "s3 需要配置 endpoint 与 bucket"}
		}
		if t.S3RequireKeys && (strings.TrimSpace(t.AccessKey) == "" || strings.TrimSpace(t.SecretKey) == "") {
			return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete,
				detail: "s3 需要配置 access_key 与 secret_key"}
		}
	case "syslog":
		sys := t.Syslog
		if sys == nil {
			sys = &config.SyslogSettings{}
		}
		if err := sys.Validate(); err != nil {
			return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete,
				detail: strings.TrimPrefix(err.Error(), "config: security: ")}
		}
		if res := validateProbeSyslogURL(t.URL); res != nil {
			return res
		}
	case "kafka":
		if nBrokers(t.Brokers) == 0 {
			return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete,
				detail: "kafka 至少需要配置一个 broker"}
		}
		if strings.TrimSpace(t.Topic) == "" {
			return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete,
				detail: "kafka 需要配置 topic"}
		}
		switch t.SASL {
		case "", "none", "plain", "scram-sha256":
		default:
			return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete,
				detail: "kafka sasl 必须是 none、plain 或 scram-sha256"}
		}
		if (t.SASL == "plain" || t.SASL == "scram-sha256") &&
			(strings.TrimSpace(t.Username) == "" || strings.TrimSpace(t.Password) == "") {
			return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete,
				detail: "kafka sasl " + t.SASL + " 需要同时配置 username 与 password"}
		}
	default:
		return &probeResult{state: probeStateFail, reason: reasonUnsupported,
			detail: "不支持的外发类型（可选：" + strings.Join(outboundProbeSinkTypes, "/") + "）"}
	}
	return nil
}

// validateProbeSyslogURL mirrors config.validateSyslogURL (unexported there):
// scheme udp://, tcp:// or tls:// plus host[:port], no path, no user:pass@
// userinfo; a bare "host:514" is rejected, only the scheme-less
// "//host[:port]" form is accepted (transport defaults to udp at the sink).
func validateProbeSyslogURL(raw string) *probeResult {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete,
			detail: "syslog url 必须是 udp://host[:514]、tcp://host[:514] 或 tls://host[:6514]"}
	}
	switch strings.ToLower(u.Scheme) {
	case "udp", "tcp", "tls", "":
		if u.Path != "" && u.Path != "/" {
			return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete,
				detail: "syslog url 不能包含路径"}
		}
		if u.User != nil {
			return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete,
				detail: "syslog url 不能包含用户名密码（user:pass@）"}
		}
		return nil
	default:
		return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete,
			detail: "syslog url 协议必须是 udp、tcp 或 tls"}
	}
}

func nBrokers(brokers []string) int {
	n := 0
	for _, b := range brokers {
		if strings.TrimSpace(b) != "" {
			n++
		}
	}
	return n
}

// probeSinkTarget runs the per-type read-only probe against a validated
// target and scrubs credential literals out of the result.
func probeSinkTarget(ctx context.Context, t *sinkTarget) probeResult {
	pr := newProbeRedactor()
	pr.addSecret(t.Password)
	pr.addSecret(t.AccessKey)
	pr.addSecret(t.SecretKey)
	if u, err := url.Parse(strings.TrimSpace(t.URL)); err == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok {
			pr.addSecret(pw)
		}
	}
	var res probeResult
	switch t.Type {
	case "elasticsearch":
		res = probeHTTP(ctx, "elasticsearch", t.URL, "/_cluster/health", t.Username, t.Password)
	case "loki":
		res = probeHTTP(ctx, "loki", t.URL, "/ready", t.Username, t.Password)
	case "clickhouse":
		res = probeHTTP(ctx, "clickhouse", t.URL, "/?query=SELECT%201", t.Username, t.Password)
	case "s3":
		res = probeS3(ctx, t)
	case "kafka":
		res = probeKafka(ctx, t)
	case "syslog":
		res = probeSyslog(ctx, t)
	default:
		res = failProbe(reasonUnsupported, "不支持的外发类型")
	}
	return pr.scrubResult(res)
}

// probeHTTP probes an ES/Loki/ClickHouse HTTP endpoint with optional Basic
// auth. The client never honors environment proxies and never follows
// redirects, so the probe can neither be detoured through HTTP(S)_PROXY nor
// leak the credentials to a redirect target. A 401/403 is an authentication
// failure (the legacy probe wrongly reported those as healthy).
func probeHTTP(ctx context.Context, name, base, probe, username, password string) probeResult {
	base = strings.TrimSpace(base)
	client := &http.Client{
		Timeout: probeStepTimeout,
		// Do not follow redirects: a 3xx is surfaced instead of chased, so
		// credentials can never leak to a redirect target.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy: nil, // never honor HTTP(S)_PROXY for probe dials
		},
	}
	target := strings.TrimRight(base, "/") + probe
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return failProbe(reasonConfigIncomplete, name+" url 无法解析")
	}
	if username != "" {
		req.SetBasicAuth(username, password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return classifyTransportErr(name, err)
	}
	defer resp.Body.Close()
	// Bounded drain; the body is never echoed back.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return okProbe(fmt.Sprintf("%s 响应 %d（可达，认证通过）", name, resp.StatusCode))
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return failProbe(reasonAuthFailed,
			fmt.Sprintf("%s 认证失败：目标返回 %d（用户名或密码错误）", name, resp.StatusCode))
	case resp.StatusCode >= 500:
		return failProbe(reasonServerError, fmt.Sprintf("%s 服务端错误：目标返回 %d", name, resp.StatusCode))
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return failProbe(reasonServerError,
			fmt.Sprintf("%s 响应 %d（探测不跟随重定向）", name, resp.StatusCode))
	default:
		return failProbe(reasonServerError, fmt.Sprintf("%s 响应 %d", name, resp.StatusCode))
	}
}

// classifyTransportErr maps a client.Do error onto the three-state model.
func classifyTransportErr(name string, err error) probeResult {
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || isTimeoutErr(err):
		return failProbe(reasonTimeout, name+" 连接超时")
	case isCertErr(err) || strings.Contains(strings.ToLower(msg), "tls:"):
		return failProbe(reasonTLSError, name+" TLS 握手失败："+msg)
	default:
		return failProbe(reasonUnreachable, name+" 连接失败："+msg)
	}
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isCertErr reports whether the error is a TLS certificate-verification
// failure (distinct from plain unreachability: the target answered).
func isCertErr(err error) bool {
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &unknown) || errors.As(err, &host) || errors.As(err, &invalid) ||
		errors.Is(err, x509.ErrUnsupportedAlgorithm) ||
		strings.Contains(strings.ToLower(err.Error()), "certificate")
}

// probeDialResult probes a raw endpoint (kept from the legacy probeDial, now
// three-state).
func probeDialResult(network, addr string, timeout time.Duration) probeResult {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		if isTimeoutErr(err) {
			return failProbe(reasonTimeout, network+" 连接超时："+addr)
		}
		return failProbe(reasonUnreachable, network+" 连接失败："+addr+": "+err.Error())
	}
	conn.Close()
	return okProbe(network + " 连接成功：" + addr)
}

// probeS3 verifies the S3 credentials read-only: TCP reachability first
// (distinguishes unreachable from auth_failed), then the minio-go bucket
// check via the shipping client package (SigV4 handled by minio-go; no
// hand-written signing, no new dependency).
func probeS3(ctx context.Context, t *sinkTarget) probeResult {
	dres := probeDialResult("tcp", s3DialAddr(t.Endpoint, t.Secure), probeStepTimeout)
	checks := []probeCheck{checkOf("dial", dres)}
	if dres.state != probeStateOK {
		return dres.withChecks(checks)
	}
	bctx, cancel := context.WithTimeout(ctx, probeStepTimeout)
	defer cancel()
	exists, err := s3sink.ProbeBucket(bctx, &config.S3Settings{
		Endpoint:  t.Endpoint,
		Bucket:    t.Bucket,
		AccessKey: t.AccessKey,
		SecretKey: t.SecretKey,
		UseSSL:    t.Secure,
	}, t.Region)
	switch {
	case err == nil && exists:
		return okProbe("s3 凭据有效，桶可访问（只读探测，未验证写权限）").withChecks(append(checks,
			probeCheck{Step: "s3", State: probeStateOK}))
	case err == nil && !exists:
		return failProbe(reasonBucketMissing,
			fmt.Sprintf("s3 桶 %q 不存在（或无权访问）", t.Bucket)).withChecks(append(checks,
			probeCheck{Step: "s3", State: probeStateFail, Reason: reasonBucketMissing}))
	default:
		reason, detail := classifyS3Err(err)
		return failProbe(reason, detail).withChecks(append(checks,
			probeCheck{Step: "s3", State: probeStateFail, Reason: reason}))
	}
}

// s3DialAddr derives the host:port for the probe-only TCP reachability step.
// The runtime client receives the endpoint verbatim; this derivation only
// feeds net.DialTimeout.
func s3DialAddr(endpoint string, secure bool) string {
	host := strings.TrimSpace(endpoint)
	if u, err := url.Parse(host); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		host = u.Host
	}
	if !strings.Contains(host, ":") {
		if secure {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return host
}

// classifyS3Err maps a minio error onto the three-state model. InvalidAccessKeyId
// / SignatureDoesNotMatch are definitive credential failures; AccessDenied is
// reported as an auth/authorization failure with the bucket-permission caveat.
func classifyS3Err(err error) (string, string) {
	var er minio.ErrorResponse
	if errors.As(err, &er) {
		switch {
		case er.Code == "InvalidAccessKeyId" || er.Code == "InvalidAccessKeyIdNotFound" || er.Code == "SignatureDoesNotMatch":
			return reasonAuthFailed, "s3 认证失败：" + er.Code + "（access_key 或 secret_key 错误）"
		case er.Code == "AccessDenied" || er.StatusCode == 401 || er.StatusCode == 403:
			return reasonAuthFailed, "s3 认证/授权失败：AccessDenied（凭据被拒绝，或凭据有效但无该桶的访问权限）"
		case er.Code == "NoSuchBucket":
			return reasonBucketMissing, "s3 桶不存在"
		case er.StatusCode >= 500:
			return reasonServerError, fmt.Sprintf("s3 服务端错误：目标返回 %d", er.StatusCode)
		case er.Code != "":
			return reasonServerError, "s3 目标返回错误：" + er.Code
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeoutErr(err) {
		return reasonTimeout, "s3 探测超时"
	}
	return reasonUnreachable, "s3 连接失败：" + err.Error()
}

// kafkaProbeTransport builds the kafka transport, mirroring the shipper
// runtime: TLS honors the tri-state tls_skip_verify (nil keeps the legacy
// zero-config "certificates NOT verified"); SASL plain / scram-sha256 reuse
// Username/Password.
func kafkaProbeTransport(t *sinkTarget) (*kafka.Transport, probeResult) {
	tr := &kafka.Transport{DialTimeout: probeStepTimeout, MetadataTTL: probeStepTimeout, IdleTimeout: probeStepTimeout}
	if t.UseTLS {
		skip := true
		if t.TLSSkipVerify != nil {
			skip = *t.TLSSkipVerify
		}
		tr.TLS = &tls.Config{InsecureSkipVerify: skip} //nolint:gosec // mirrors the shipper transport
	}
	switch t.SASL {
	case "plain":
		tr.SASL = plain.Mechanism{Username: t.Username, Password: t.Password}
	case "scram-sha256":
		m, err := scram.Mechanism(scram.SHA256, t.Username, t.Password)
		if err != nil {
			return nil, failProbe(reasonConfigIncomplete, "kafka SASL 初始化失败："+err.Error())
		}
		tr.SASL = m
	}
	return tr, probeResult{}
}

// probeKafka fetches broker metadata with the shipper's SASL/TLS parameters.
// Metadata proves reachability + SASL acceptance; it does NOT verify the
// PRODUCE ACL. SASL failure classification is heuristic (kafka-go surfaces
// most SASL rejections as transport-layer text).
func probeKafka(ctx context.Context, t *sinkTarget) probeResult {
	tr, fail := kafkaProbeTransport(t)
	if fail.state != "" {
		return fail
	}
	cl := &kafka.Client{Addr: kafka.TCP(t.Brokers...), Timeout: probeStepTimeout, Transport: tr}
	kctx, cancel := context.WithTimeout(ctx, probeStepTimeout)
	defer cancel()
	req := &kafka.MetadataRequest{}
	topic := strings.TrimSpace(t.Topic)
	if topic != "" {
		req.Topics = []string{topic}
	}
	resp, err := cl.Metadata(kctx, req)
	if err != nil {
		return classifyKafkaErr(err)
	}
	detail := fmt.Sprintf("kafka metadata 成功（brokers=%d）", len(resp.Brokers))
	for _, tp := range resp.Topics {
		if tp.Error != nil {
			// Requested topic absent: normal under broker auto-create, so
			// degraded instead of fail.
			return degradedProbe(detail + "；topic " + topic + " 暂不存在（依赖 broker 自动建题时属正常，未验证写入权限）")
		}
	}
	return okProbe(detail + "（只读探测，未验证 PRODUCE 权限）")
}

// classifyKafkaErr maps a metadata error onto the three-state model; SASL
// rejections are recognized by error-text heuristics (documented limitation).
func classifyKafkaErr(err error) probeResult {
	msg := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.DeadlineExceeded) || isTimeoutErr(err):
		return failProbe(reasonTimeout, "kafka 探测超时")
	case strings.Contains(msg, "sasl") || strings.Contains(msg, "authentication") ||
		strings.Contains(msg, "unauthorized") || strings.Contains(msg, "credentials"):
		return failProbe(reasonAuthFailed, "kafka 认证失败（SASL 握手被拒）："+err.Error())
	default:
		return failProbe(reasonUnreachable, "kafka 连接失败："+err.Error())
	}
}

// probeSyslog checks the syslog target without ever sending a syslog frame:
// UDP only resolves the address (delivery is best-effort → degraded), TCP
// proves the listener, TLS proves the listener plus the certificate policy —
// with InsecureSkipVerify read from the section so the probe matches the
// runtime transport.
func probeSyslog(ctx context.Context, t *sinkTarget) probeResult {
	sys := t.Syslog
	if sys == nil {
		sys = &config.SyslogSettings{}
	}
	proto := strings.ToLower(strings.TrimSpace(sys.Protocol))
	if proto == "" {
		if i := strings.Index(t.URL, "://"); i > 0 {
			proto = strings.ToLower(t.URL[:i])
		} else {
			proto = "udp" // bare host[:port] target; the sink defaults to udp
		}
	}
	addr := syslogTargetAddr(t.URL)
	switch proto {
	case "udp":
		// ctx-aware resolution keeps the UDP path inside the global probe
		// budget: the package-level net.ResolveUDPAddr resolved with no
		// deadline, so a black-holed DNS server could hold the single-flight
		// slot far past the ~8s budget and starve other operators' probes
		// with 429s. Only resolvability is checked — never a datagram.
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr // bare host[:port] target without a port suffix
		}
		if _, err := net.DefaultResolver.LookupIPAddr(ctx, host); err != nil {
			if ctx.Err() != nil {
				return failProbe(reasonTimeout, "udp 地址解析超时（探测总预算已用尽）："+addr)
			}
			return failProbe(reasonUnreachable, "udp 地址解析失败："+err.Error())
		}
		return degradedProbe("udp 目标地址可解析；UDP 无法确认对端在监听，投递为 best-effort")
	case "tcp":
		return probeDialResult("tcp", addr, probeStepTimeout)
	case "tls":
		d := &net.Dialer{Timeout: probeStepTimeout}
		td := &tls.Dialer{NetDialer: d, Config: &tls.Config{InsecureSkipVerify: sys.TLSSkipVerify}} //nolint:gosec // opt-in via tls_skip_verify, mirrors the runtime transport
		conn, err := td.DialContext(ctx, "tcp", addr)
		if err != nil {
			switch {
			case errors.Is(err, context.DeadlineExceeded) || isTimeoutErr(err):
				return failProbe(reasonTimeout, "tls 连接超时："+addr)
			case isCertErr(err):
				return failProbe(reasonTLSError, "tls 证书校验失败："+err.Error())
			default:
				return failProbe(reasonUnreachable, "tls 连接失败："+addr+": "+err.Error())
			}
		}
		conn.Close()
		if sys.TLSSkipVerify {
			return degradedProbe("tls 连接成功；证书未校验（与运行时 tls_skip_verify=true 一致）")
		}
		return okProbe("tls 连接成功（证书校验通过）")
	default:
		return failProbe(reasonConfigIncomplete, "syslog 协议必须是 udp、tcp 或 tls")
	}
}

// syslogTargetAddr strips the scheme from a syslog target URL, leaving
// host[:port] for dialing (mirrors the legacy probe and the sink).
func syslogTargetAddr(raw string) string {
	if i := strings.Index(raw, "://"); i > 0 {
		return raw[i+3:]
	}
	return raw
}

// ---------------------------------------------------------------------------
// Endpoint layer: POST /api/outbound/test (the legacy POST /api/logship/test
// delegates here with kind pinned to audit). The overlay + synthesis below
// answer the operator question "which channel would delivery actually use",
// and the probe stays strictly READ-ONLY: no revision is published, the
// config store is never written, no index/object/topic/message/frame is ever
// created on the target. The only persisted trace is the management
// change-audit entry (action "outbound.test").
//
// SSRF posture (accepted trade-off, documented): private-network and loopback
// targets are deliberately NOT blocked — production SIEM/ES/MinIO/rsyslog
// endpoints legitimately live on private networks, and blocking them would
// kill the feature. The boundary is the combination of operator-role RBAC,
// the global single-flight gate (≤1 in-flight probe, extra requests answer
// 429), the ~8s total budget, the per-sink protocol whitelist, no-redirect +
// no-env-proxy HTTP dials, redacted responses and the audit trail. Residual
// risk: a compromised operator session can still use this endpoint for slow
// internal port probing (~7 probes/min with the 4s step timeout); the
// change-audit entry keeps that traceable.
// ---------------------------------------------------------------------------

// outboundTestRequest is the POST /api/outbound/test body. kind selects the
// outbound section (audit | access | ai); settings is a partial JSON object
// of the corresponding config section, overlaid on the saved values (see
// overlayOutbound). An absent/empty body tests the saved configuration
// as-is.
type outboundTestRequest struct {
	Kind     string          `json:"kind,omitempty"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

// handleOutboundTest serves POST /api/outbound/test.
func (s *Server) handleOutboundTest(w http.ResponseWriter, r *http.Request) {
	s.runOutboundTest(w, r, "")
}

// runOutboundTest is the shared runner for the unified endpoint (forceKind=""
// → kind from the body) and the legacy POST /api/logship/test (forceKind=
// "audit" → the body kind is ignored, matching the pre-unification
// behavior). Gates: operator role, global single-flight (429), ~8s total
// budget across ALL probe steps (not per backend).
func (s *Server) runOutboundTest(w http.ResponseWriter, r *http.Request, forceKind string) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	if !s.probeInflight.CompareAndSwap(0, 1) {
		writeErr(w, http.StatusTooManyRequests, simpleError("外发探测正在进行中，请等待当前探测完成后再试"))
		return
	}
	defer s.probeInflight.Add(-1)

	var req outboundTestRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, simpleError("外发探测：请求体读取失败"))
		return
	}
	if strings.TrimSpace(string(body)) != "" {
		if err := json.Unmarshal(body, &req); err != nil {
			writeErr(w, http.StatusBadRequest, simpleError("外发探测：请求体必须是 JSON 对象"))
			return
		}
	}
	kind := req.Kind
	if forceKind != "" {
		kind = forceKind
	}
	if kind == "" {
		kind = "audit"
	}
	switch kind {
	case "audit", "access", "ai":
	default:
		writeErr(w, http.StatusBadRequest, simpleError("外发探测：kind 必须是 audit、access 或 ai"))
		return
	}

	_, cfg := s.opts.Center.Current()
	ov, err := overlayOutboundSections(kind, req.Settings, cfg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, simpleError("外发探测：settings 无法解析为对应配置节（"+err.Error()+"）"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), probeBudget)
	defer cancel()
	start := time.Now()
	t, fail := synthOutboundTarget(kind, ov, cfg)
	var res probeResult
	if fail != nil {
		res = *fail
	} else {
		res = probeSinkTarget(ctx, t)
	}
	// Belt-and-suspenders redaction: the kernel already scrubbed the probed
	// target's secrets; this pass also covers the saved sections'
	// credentials (channel reuse) before the detail reaches the response or
	// the audit entry.
	pr := newProbeRedactor()
	addOutboundSecrets(pr, cfg)
	if t != nil {
		pr.addSecret(t.Password)
		pr.addSecret(t.AccessKey)
		pr.addSecret(t.SecretKey)
	}
	res.detail = pr.scrub(res.detail)

	latency := time.Since(start).Milliseconds()
	hp := targetHostPort(t)
	if hp == "" {
		hp = "-"
	}
	// Change-audit trail: kind/state/type/host:port/latency only — never a
	// credential literal, never a full URL with userinfo.
	s.recordChange(r, "outbound.test", kind,
		fmt.Sprintf("kind=%s state=%s type=%s target=%s latency_ms=%d",
			kind, res.state, targetType(t), pr.scrub(hp), latency))

	writeJSON(w, http.StatusOK, outboundProbeResponse{
		State:     res.state,
		OK:        res.state == probeStateOK || res.state == probeStateDegraded,
		Type:      targetType(t),
		LatencyMS: latency,
		Reason:    res.reason,
		Detail:    res.detail,
		Checks:    res.checks,
	})
}

// outboundOverlay holds the overlaid sections; only the entry selected by
// kind is populated (see overlayOutboundSections).
type outboundOverlay struct {
	shipper *config.ShipperSettings
	access  *config.AccessLogSettings
	aiShip  *config.AIAuditShipSettings
}

// overlayOutboundSections deep-copies the saved section selected by kind
// (via a JSON round-trip, so no pointer aliases into the live runtime config
// — the probe must never mutate the Brokers/S3/Syslog sub-structures the
// running pipelines read) and applies the body settings on top: keys present
// in the body override the saved value (including explicit false / empty
// strings), keys absent from the body keep the saved value. A nil/empty
// settings tests the saved section as-is; a section absent from the saved
// config starts from the zero value.
func overlayOutboundSections(kind string, raw json.RawMessage, cfg *config.Config) (*outboundOverlay, error) {
	ov := &outboundOverlay{}
	switch kind {
	case "audit":
		sh, err := overlayOutbound(cfg.LogShipper, raw)
		if err != nil {
			return nil, err
		}
		ov.shipper = sh
	case "access":
		al, err := overlayOutbound(cfg.AccessLog, raw)
		if err != nil {
			return nil, err
		}
		ov.access = al
	case "ai":
		var saved *config.AIAuditShipSettings
		if cfg.AiAudit != nil {
			saved = cfg.AiAudit.Ship
		}
		ship, err := overlayOutbound(saved, raw)
		if err != nil {
			return nil, err
		}
		ov.aiShip = ship
	}
	return ov, nil
}

// overlayOutbound is the generic deep-copy-then-overlay primitive.
func overlayOutbound[T any](saved *T, raw json.RawMessage) (*T, error) {
	out := new(T)
	if saved != nil {
		b, err := json.Marshal(saved)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, out); err != nil {
			return nil, err
		}
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// missingAuditChannelMsg is the shared verdict for a nested section riding
// the use_audit_channel switch while the audit outbound (log_shipper) is
// absent — the publish-time cross-validation rejects the same shape. It used
// to be duplicated verbatim in the kind=access and kind=ai branches; pin it
// once so the two branches can never drift apart again.
const missingAuditChannelMsg = "use_audit_channel 已开启，但防护日志通道（log_shipper）未配置，请先配置并保存防护日志外发"

// unconfiguredOutbound is the config_incomplete verdict for a nested section
// that is absent or carries no usable sink type.
func unconfiguredOutbound(sectionLabel string) *probeResult {
	return incompleteOutbound(sectionLabel + " 外发未配置")
}

// nestedOutboundSection is the closed set of nested outbound section types
// the probe synthesizes targets for (kind=access / kind=ai).
type nestedOutboundSection interface {
	config.AccessLogSettings | config.AIAuditShipSettings
}

// outboundSectionForceEnable force-enables the temp section in place (the
// probe answers what delivery WOULD use) and reports whether the section
// rides the use_audit_channel switch. ok=false marks a section outside the
// nestedOutboundSection closed set — resolveOutboundTarget turns that into
// an explicit fail-fast verdict instead of silently probing with a
// defaulted usesChannel=false (C6: the type switch must answer every case).
func outboundSectionForceEnable(section any) (usesChannel, ok bool) {
	switch v := section.(type) {
	case *config.AccessLogSettings:
		v.Enabled = true // the probe answers what delivery WOULD use
		return v.UseAuditChannel, true
	case *config.AIAuditShipSettings:
		v.Enabled = true
		return v.UseAuditChannel, true
	default:
		return false, false
	}
}

// resolveOutboundTarget is the SINGLE construction pipeline behind the
// kind=access and kind=ai branches of synthOutboundTarget, answering "which
// channel would delivery actually use":
//   - a nil section answers config_incomplete;
//   - the temp section is force-enabled (the probe answers what delivery
//     WOULD use) and, when it rides the use_audit_channel switch, checked
//     against the saved channel (missingAuditChannelMsg when log_shipper is
//     absent);
//   - the section runs through the SAME config resolver the runtime
//     rebuilders use (config.ResolveAccessOut / ResolveAIShipOut — probe and
//     runtime share one effective-section semantic),
//   - the resolved section is converted into the probe target (kind=ai goes
//     through the runtime aisession.ShipSettings conversion there, including
//     the deprecated flat use_ssl/prefix fallback),
//   - and the target passes the config-parity validateTarget gate.
//
// resolve and toProbeTarget are the ONLY per-kind differences; the verdict
// texts, the force-enable and the channel check are defined exactly once
// here. fail != nil → the request never reaches the probe stage (config
// problem, t == nil).
func resolveOutboundTarget[S nestedOutboundSection](
	section *S,
	channel *config.ShipperSettings,
	sectionLabel string,
	resolve func(*S, *config.ShipperSettings) *S,
	toProbeTarget func(*S) *sinkTarget,
) (*sinkTarget, *probeResult) {
	if section == nil {
		return nil, unconfiguredOutbound(sectionLabel)
	}
	usesChannel, known := outboundSectionForceEnable(any(section))
	if !known {
		return nil, incompleteOutbound(sectionLabel + " 外发段落类型不受支持")
	}
	if usesChannel && channel == nil {
		return nil, incompleteOutbound(missingAuditChannelMsg)
	}
	res := resolve(section, channel)
	if res == nil {
		return nil, unconfiguredOutbound(sectionLabel)
	}
	t := toProbeTarget(res)
	if strings.TrimSpace(t.Type) == "" {
		return nil, unconfiguredOutbound(sectionLabel)
	}
	if fail := validateTarget(t); fail != nil {
		return nil, fail
	}
	return t, nil
}

// synthOutboundTarget builds the probe target for one outbound kind from the
// overlaid section + the saved config:
//   - kind=audit probes the (overlaid) log_shipper section itself;
//   - kind=access/ai share the single resolveOutboundTarget pipeline (see
//     there): force-enable + the use_audit_channel missing-channel verdict +
//     the runtime resolvers + the runtime-shaped probe target + the
//     config-parity validation — with use_audit_channel=true the probe tests
//     the SAVED audit-channel parameters (type/url/auth/batch/s3/syslog/
//     kafka) plus the section's own identity fields — never the section's
//     ignored in-section channel fields.
func synthOutboundTarget(kind string, ov *outboundOverlay, cfg *config.Config) (*sinkTarget, *probeResult) {
	switch kind {
	case "audit":
		return synthShipperTarget(ov.shipper)
	case "access":
		return resolveOutboundTarget(ov.access, cfg.LogShipper, "access_log",
			config.ResolveAccessOut, accessTarget)
	case "ai":
		return resolveOutboundTarget(ov.aiShip, cfg.LogShipper, "ai_audit.ship",
			config.ResolveAIShipOut, func(res *config.AIAuditShipSettings) *sinkTarget {
				eff := aisession.ShipSettings(*res) // the runtime conversion (incl. the deprecated flat use_ssl/prefix fallback)
				return accessTarget(&eff)
			})
	}
	// The runner validates kind before calling; unreachable in practice.
	return nil, incompleteOutbound("未知的外发类别")
}

// incompleteOutbound is the config_incomplete verdict helper.
func incompleteOutbound(detail string) *probeResult {
	return &probeResult{state: probeStateFail, reason: reasonConfigIncomplete, detail: detail}
}

// synthShipperTarget validates the (overlaid) log_shipper section and
// normalizes it into the probe target; shared by synthOutboundTarget and
// probeSink. An absent/empty section answers config_incomplete.
func synthShipperTarget(sh *config.ShipperSettings) (*sinkTarget, *probeResult) {
	if sh == nil || strings.TrimSpace(sh.Type) == "" {
		return nil, incompleteOutbound("未配置日志外发通道")
	}
	t := shipperTarget(sh)
	if res := validateTarget(t); res != nil {
		return nil, res
	}
	return t, nil
}

// probeSink performs the read-only connectivity + authentication check for a
// log_shipper section (three-state result; kernel entry for the flat shape).
func probeSink(ctx context.Context, sh *config.ShipperSettings) probeResult {
	t, fail := synthShipperTarget(sh)
	if fail != nil {
		return *fail
	}
	return probeSinkTarget(ctx, t)
}

// accessTarget normalizes a nested access_log-shaped section (config.
// AccessLogSettings — also the conversion target of aisession.ShipSettings)
// into the probe target, mirroring accesslog.NewGeneric field use: the
// nested s3 block (S3Settings, plain-HTTP default), the section's own
// username/password for the HTTP backends, and the syslog/kafka transports.
// The nested s3 shape does NOT require access/secret keys (config parity:
// S3Settings.Validate requires only endpoint and bucket).
func accessTarget(al *config.AccessLogSettings) *sinkTarget {
	t := &sinkTarget{
		Type:          strings.TrimSpace(al.Type),
		URL:           al.URL,
		Username:      al.Username,
		Password:      al.Password,
		Brokers:       slices.Clone(al.Brokers),
		Topic:         al.Topic,
		UseTLS:        al.UseTLS,
		SASL:          al.SASL,
		TLSSkipVerify: al.TLSSkipVerify,
		Syslog:        al.Syslog,
	}
	if al.S3 != nil {
		t.Endpoint = strings.TrimSpace(al.S3.Endpoint)
		t.Bucket = al.S3.Bucket
		t.AccessKey = al.S3.AccessKey
		t.SecretKey = al.S3.SecretKey
		t.Secure = al.S3.UseSSL
	}
	return t
}

// targetType returns the effective sink type for the response ("" when the
// probe never reached a target).
func targetType(t *sinkTarget) string {
	if t == nil {
		return ""
	}
	return t.Type
}

// targetHostPort extracts the host:port for the audit trail entry (s3
// endpoint, first kafka broker, or the parsed URL host). It never includes
// userinfo or credentials — on a parse failure it returns "".
func targetHostPort(t *sinkTarget) string {
	if t == nil {
		return ""
	}
	switch t.Type {
	case "s3":
		hp := strings.TrimSpace(t.Endpoint)
		if u, err := url.Parse(hp); err == nil && u.Host != "" {
			hp = u.Host
		}
		return hp
	case "kafka":
		for _, b := range t.Brokers {
			if v := strings.TrimSpace(b); v != "" {
				return v
			}
		}
		return ""
	default:
		u, err := url.Parse(strings.TrimSpace(t.URL))
		if err != nil || u.Host == "" {
			return ""
		}
		return u.Host
	}
}

// addOutboundSecrets feeds every saved outbound credential into the
// redactor (belt-and-suspenders: probe details must not echo saved secrets
// either, e.g. through config-layer error echoes).
func addOutboundSecrets(pr *probeRedactor, cfg *config.Config) {
	if cfg == nil {
		return
	}
	if sh := cfg.LogShipper; sh != nil {
		pr.addSecret(sh.Password)
		pr.addSecret(sh.AccessKey)
		pr.addSecret(sh.SecretKey)
	}
	if al := cfg.AccessLog; al != nil {
		// Username is deliberately NOT a redaction literal (parity with the
		// shipper branch below): scrub is a blind strings.ReplaceAll, so a
		// common username ("elastic", "minio", "waf") would corrupt detail
		// text and the audit "target=host:port" field. Passwords, access and
		// secret keys stay redacted. Residual risk: a kafka SASL error could
		// theoretically echo the username — it is operator-visible config,
		// not a secret.
		pr.addSecret(al.Password)
		if al.S3 != nil {
			pr.addSecret(al.S3.AccessKey)
			pr.addSecret(al.S3.SecretKey)
		}
	}
	if cfg.AiAudit != nil && cfg.AiAudit.Ship != nil {
		s := cfg.AiAudit.Ship
		pr.addSecret(s.Password)
		if s.S3 != nil {
			pr.addSecret(s.S3.AccessKey)
			pr.addSecret(s.S3.SecretKey)
		}
	}
}
