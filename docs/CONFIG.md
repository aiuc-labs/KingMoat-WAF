# KingMoat WAF 配置参考

配置以 JSON 表达，来源可以是静态文件（`-config`）或控制台发布的 revision
（内容结构完全一致）。所有字段校验失败（`Config.Validate`）都会拒绝启动 /
拒绝发布，线上流量保持旧配置（fail-static）。

> 本文列常用字段与说明；完整字段与最新默认值以仓库根目录
> [config.example.json](../config.example.json) 与 `internal/config` 源码为准。

# 顶层字段

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `listen_http` | string | 必填 | 数据面 HTTP 监听地址（如 `":80"`、`"127.0.0.1:8080"`） |
| `listen_https` | string | `""` | 数据面 HTTPS 监听地址；站点 TLS 证书 + SNI |
| `audit_log_dir` | string | `"logs"` | 攻击日志目录：SQLite 库 `audit.db`（FTS5 全文索引）+ 每日快照 `archive/`；本地访问日志库 `access-logs.db`（`access_log_record` 开启时生成）也在此目录，见 [AccessLogRecordSettings](#accesslogrecordsettings访问日志本地留存顶层-access_log_record) |
| `audit_retention_days` | int | `7` | 本地攻击日志保留天数（0/未设置=7，负数=永不清理），由每日归档任务执行；修改需重启。保留期过大→本库变大、检索变慢，建议配合外发使用 |
| `body_buffer_budget_mb` | int | `256` | **请求体检测聚合内存预算**：限制全部在途请求「检测缓冲」占用字节数之和（站点级 `body_limit_bytes` 只限单个请求，本项限并发×上限）；超预算的请求返回 **503（`proxy/body_buffer_exhausted`）**——刻意 fail-closed，内存压力下绝不静默降级为不检测。按读取分块递增记账，小 body 只占小额度；0/未设置=默认 256，负数=不限制（不推荐），上限 65536（64 GB）。发布即热生效 |
| `audit_archive` | object | 开启 | 每日 DB 快照归档，见 [AuditArchiveSettings](#auditarchivesettings) |
| `audit_query` | object | 空 | 日志查询治理：并发上限/超时/紧急降级，见 [AuditQuerySettings](#auditquerysettings)；发布即热生效 |
| `metrics` | object | 空 | 可选 Prometheus 文本端点（/metrics，控制台认证内），见 [MetricsSettings](#metricssettings)；发布热生效 |
| `telemetry` | object | 空 | 匿名安装统计（**默认关**）：`{ "enabled": true }` 开启后仅上报随机安装 ID / 版本 / OS 架构 / 安装方式；`DO_NOT_TRACK` 环境变量优先级更高；连续 3 次不可达自动停止；详见 README 遥测声明 |
| `acme_email` | string | `""` | 全局 ACME 联系邮箱（站点防护页工具栏/设置页配置）；站点启用 `acme` 且未单独配置 email 时使用 |
| `console` | object | 空 | 管理面访问限制：`allowed_ips`（IP/CIDR 列表，空 = 不限制；对控制台所有请求生效，含登录） |
| `security` | object | 空 | 控制台安全策略：会话超时/登录防爆破/密码策略，见 [ConsoleSecuritySettings](#consolesecuritysettings) |
| `webhook` | object | 空 | 告警推送，见 [WebhookSettings](#webhooksettings) |
| `log_shipper` | object | 空 | 审计日志外发，见 [ShipperSettings](#shippersettings) |
| `policy` | object | 空 | 全局策略：CRS 阈值 / 自定义 SecLang 规则 / 全局 IP 黑白名单，见 [Policy](#policy) |
| `access_log` | object | 空 | 全量访问日志管道，见 [AccessLogSettings](#accesslogsettings全量访问日志管道) |
| `access_log_record` | object | 空 | 访问日志本地留存（**默认关**，与 `access_log` 外发完全独立），见 [AccessLogRecordSettings](#accesslogrecordsettings访问日志本地留存顶层-access_log_record) |
| `ai_audit` | object | 空 | AI 会话审计（捕获/采样/脱敏/保留/外发），见 [AIAuditSettings](#aiauditsettings) |
| `risks` | object | 空 | 专项风险引擎，见 [RisksSettings](#riskssettings) |
| `api_assets` | object | 空 | API 资产被动学习（默认关），见 [API-ASSETS.md](API-ASSETS.md) |
| `disk_guard` | object | 默认开启 | 日志磁盘占用守卫（数据盘 >90% 时 FIFO 清理归档与最旧事件至 65%），见 [DiskGuardSettings](#diskguardsettings) |
| `capture_requests` | bool | `false` | 审计事件附带脱敏请求头与 body 快样（隐私敏感，默认关） |
| `ip_groups` | array | `[]` | 订阅 IP 组，见 [IPGroupSettings](#ipgroupsettings) |
| `sites` | array | 必填 | 防护站点列表，见 [Site](#site) |

# Site

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `domains` | string[] | 必填 | 匹配的域名（Host / SNI，忽略大小写） |
| `mode` | string | `"intercept"` | `intercept` 拦截 / `monitor` 只记录不拦截（灰度） |
| `upstream` | object | 必填 | 上游池：`{"nodes":[{"address":"host:port","weight":1}],"algorithm":"wrr"}`；algorithm：`wrr` 加权轮询（默认）/ `least_conn` 最少连接 / `source_ip` 源 IP 会话保持；HTTPS 上游可用 `sni_host` 固定握手 SNI（与 `sni_forward` 互斥）、`verify_tls` 严格校验上游证书（默认关） |
| `tls_cert` / `tls_key` | string | `""` | 站点 PEM 证书/私钥路径（两者成对必填） |
| `tls_profile` | string | `"moderate"` | HTTPS 加密套件组：`strong`（仅 AEAD，6 套件）/ `moderate`（默认，AEAD + ECDHE-CBC-SHA1）/ `compatible`（moderate + ECDHE-CBC-SHA256）。全部 TLS 1.2 起步、TLS 1.3 始终可用；套件清单见 tlsprofile.go |
| `acme` | object | 空 | 自动证书，见 [ACMESettings](#acmesettings) |
| `health` | object | 空 | 上游健康检查，见 [HealthSettings](#healthsettings) |
| `redirect_to_https` | bool | `false` | HTTP 监听器对本站返回 308 到 HTTPS（需 TLS 证书或 acme + listen_https）；`/.well-known/` 前缀豁免 |
| `http2_enabled` | bool | `true` | 站点 TLS 握手的 HTTP/2 协商（缺省/`true` = h2 + HTTP/1.1；`false` = 仅 HTTP/1.1） |
| `waf` | object | 空 | 见 [WAFSettings](#wafsettings) |
| `security` | object | 空 | 防护阶段集合，见 [SecuritySettings](#securitysettings) |
| `real_ip` | object | 空 | 可信代理真实客户端 IP 解析，见 [RealIPSettings](#realipsettings) |
| `headers` | object | 空 | 转发前请求头改写（set/add/del），见 [HeaderRewrite](#headerrewrite) |

# Policy（全局策略，策略管理页）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `inbound_threshold` | int | 5 | CRS 入站异常评分阈值，详见 [docs/CRS-ANOMALY-SCORING.md](CRS-ANOMALY-SCORING.md) |
| `outbound_threshold` | int | 4 | CRS 出站异常评分阈值，详见 [docs/CRS-ANOMALY-SCORING.md](CRS-ANOMALY-SCORING.md) |
| `custom_rules` | string | `""` | 全局 SecLang 规则文本（追加在 CRS 之后，发布时编译校验） |
| `global_acl` | object | 空 | `{"blacklist":[...],"whitelist":[...]}`，先于站点 ACL 生效；条目同站点 ACL（IP/CIDR/group:）。顺序：全局白名单 → 全局黑名单 → 站点白名单 → 站点黑名单，白名单命中即放行并跳过后续全部检测 |
| `matchers` | array | `[]` | 条件组合规则（MicroEngine 式）：`{name, enabled, sites[], action, logic, conditions[{field,op,value}], disable_stages[], log_enabled}`；field：client_ip/hostname/path/uri/method/user_agent/referer/body/header:X/query:Y/cookie:Z；op：eq/neq/contains/not_contains/prefix/suffix/regex/cidr/in；action：deny/allow/monitor/disable；action=disable 时 `disable_stages` 列出对该站点关闭的检测模块（coraza/semantic/botdetect/botchallenge/ratelimit/captcha，或 `coraza:<分类>` 仅关单个 CRS 检测分类，如 `coraza:sqli`——同一规则内禁止 `coraza` 与 `coraza:<分类>` 混用）；命中后站点级持续生效（发布新配置或删除规则后恢复），`coraza:<分类>` 通过发布时预编译的变体引擎切换（每站点 ≤4 条分类规则、全局 ≤64 个变体，超限发布被拒）；disable 命中与其他动作一致由 `log_enabled` 门控（控制台对 disable 规则默认开启）；规则名称必须唯一（重名发布被拒）；`log_enabled` 开启后 deny 以外的命中写攻击日志 |
| `waf_categories` | array | 空(nil) | CRS 检测分类全局默认：列出启用的分类（sqli/xss/rce/lfi/rfi/php/generic/session/java/scanner），未配置 = 全部启用；站点可用 `waf.categories` 单独覆盖；发布时校验非法值与上限（per-site 分类 disable 规则 ≤4、全局变体 ≤64） |

检测流水线顺序（security 各子块全部可选，缺省即关闭对应阶段）：

```
ACL → 攻击惩罚（penalty）→ GeoIP → Exceptions → Matcher（含 disable 动作）→ BotDetect → Captcha(或 Bot JS 质询) → CC 限流 → 语义检测(libinjection) → Coraza/CRS
站点身份认证（auth）在流水线之前；响应侧：敏感信息过滤 → 动态防护
```

# WAFSettings

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `true` | 站点级开关（缺省即开启） |
| `custom_rules_file` | string | `""` | 自定义 SecLang 规则文件路径 |
| `body_limit_bytes` | int | 8388608 | 请求体接受上限（默认 8 MiB；超限按「超限动作」处理，控制台站点抽屉「请求体上限」可配）。检测缓冲全内存，聚合上限由顶层 `body_buffer_budget_mb` 兜底 |
| `body_inspect_bytes` | int | 262144 | **引擎检测窗口（默认 256 KB）**：仅 body 前 N 字节送入检测引擎，窗口外内容原样转发并记访问日志 `body_skip=prefix` + `kingmoat_body_bypass_total`（可审计）。背景：全量 CRS 扫描 urlencoded body 实测约 170 KB/s（剖析 95% 耗时在 coraza 规则算子正则），默认 8 MiB 窗口意味着单个 8 MiB 请求烧 ~47 CPU 秒（自建 DoS 面）；256 KB 窗口把最坏 CPU 压到 ~1.5 s/请求，且典型表单/JSON（< 256 KB）仍全量检测。设为 ≥ `body_limit_bytes` 恢复全量扫描旧行为；发布即热生效 |
| `body_over_limit` | string | `"reject"` | `reject`(413) / `bypass`（流式透传，仅头检测——存在大包绕过面） / `stream`（深检前缀，余量原样透传——推荐大包场景）。超限放行的流量同样记 `body_skip` 并计入 `kingmoat_body_bypass_total`。另：body 读无进展超 60s 返回 **408（`proxy/body_idle`）**，读取中断/客户端放弃返回 400（`proxy/body_read`），检测内存预算耗尽返回 503（`proxy/body_buffer_exhausted`） |
| `categories` | array | 空(nil) | 站点级 CRS 检测分类裁剪：列出启用的分类，未配置 = 全部启用（向后兼容），空列表 `[]` = 仅加载基础设施规则（协议校验/阻塞评分/响应分析，不可关）；关闭分类的规则**不加载**（零性能损耗）；与策略级 `waf_categories`、微引擎 `coraza:<分类>` disable 叠加时只能收窄不能扩大 |
| `body_stream_paths` | array | 空 | **深检前缀路径（两态请求体策略）**：列出的路径前缀（最长匹配）超限时**不走 `body_over_limit`**，而是只深检 `body_inspect_bytes` 窗口后流式放行——专供上传接口；未列出的路径仍按 `body_over_limit`（默认 413）。每条需 `/` 开头、无空白/`?`、去重、≤ 64 条；放宽只认服务端声明的前缀（不认客户端头，防伪造绕过校验）；命中路径的超限流量记 `body_skip=prefix` + `kingmoat_body_bypass_total`（可审计）。控制台：站点编辑 → 「请求体上限」 → 深检前缀路径列表 |

# SecuritySettings

## acl（ACLSettings）

```json
{
  "blacklist": ["203.0.113.7", "10.0.0.0/8", "group:threat-feed"],
  "whitelist": ["192.168.0.0/16"]
}
```

- 条目支持单 IP、CIDR、`group:<name>`（引用顶层 `ip_groups`）。
- 白名单命中 → 请求标记可信，跳过后续所有检测阶段。
- `group:` 引用不存在的组会被配置校验拒绝。

## ratelimit（RateLimitSettings，CC 防护）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `requests` | int | 必填 | 窗口内允许次数 |
| `window_sec` | int | 60 | 固定窗口长度 |
| `key` | string | `"ip"` | `ip` / `ip+uri` |
| `action` | string | `"deny"` | `deny`(403) / `throttle`(429) |

## bot（BotSettings，轻量 JS 质询）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `secret` | string | 随机 | HMAC 密钥；为空则每次重启失效 |
| `cookie_name` | string | `km_challenge` | 通行 Cookie 名 |
| `ttl_min` | int | 60 | 通行有效期（分钟） |

站点同时启用 `captcha` 时，本阶段被滑块验证码替代。

## captcha（CaptchaSettings，滑块人机验证）

```json
{"enabled": true, "secret": "<hmac-secret>", "cookie_name": "km_captcha", "ttl_min": 60, "tolerance": 8}
```

无通行 Cookie 的客户端收到自包含 SVG 滑块页；拖动到缺口容差范围内即签发
HMAC 签名通行 Cookie。校验端点固定为 `/.well-known/km-captcha/verify`。

## geo（GeoSettings，GeoIP 封禁）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `db_path` | string | `""` | MaxMind mmdb 文件路径。留空使用内置 DB-IP Country Lite 国家库（随版本内置，开箱即用）；填写路径则使用自备 mmdb（如 GeoLite2-Country.mmdb），文件不存在或不可读时配置构建直接失败（fail-static，发布报错），不会静默降级 |
| `blacklist` | string[] | `[]` | ISO 3166-1 alpha-2 国家码，如 `["KP","RU"]` |
| `whitelist` | string[] | `[]` | 白名单模式：仅列出的国家放行 |
| `whitelist_trusted` | bool | `false` | 白名单命中是否同时跳过后续所有检测 |

`blacklist` 与 `whitelist` 二选一使用（同时配置时 whitelist 优先）。

行为说明：geo 先于自定义规则与 CRS 执行；国家查询失败（如库中无该 IP 记录）时放行该请求。站点声明启用 geo 但运行引擎缺失对应映射（如热重载失败保留旧引擎）时，数据面限频输出 Warn 日志（每站点每分钟最多 1 条，`geo: configured but engine missing - check hot-reload failures`），请求仍放行、不会误拦。**口径说明**：攻击日志的来源地区（`geo_country`）与地理封锁判定**同源**——站点配置自定义 `db_path` 时，该站点请求的日志来源地区与 geo 封禁使用同一站点 geo 引擎、同一份库；站点未配置自定义库（或未启用 geo / 静态模式）时两者都回落内置 DB-IP 国家库。**已知残余差异**：多个站点各配不同自定义库时，总览地理统计（`GET /api/stats/geo`）仍按其既有实现取**第一个 geo-enabled 站点**的自定义库做全局单库聚合，不逐站点分库（见 [docs/API.md](API.md) 的 `geo_country` 注记）。

## auth（AuthSettings，站点身份认证）

```json
{"realm": "Internal", "users": [
  {"username": "ops", "password_hash": "$argon2id$v=19$..."},
  {"username": "dev", "password": "quick-plain-pw"}
]}
```

- 整站 HTTP Basic 认证（401 + `WWW-Authenticate`），防未授权访问。
- 每用户 `password`（明文，内网快捷）与 `password_hash`（argon2id，
  `kmwafctl hash-password` 生成）二选一。

## semantic（SemanticSettings，轻量语义检测）

```json
{"enabled": true, "check_query": true, "check_body": true}
```

基于 libinjection 的 SQLi/XSS 语义识别（路径、查询参数、Referer、缓冲
body），独立于 CRS 规则集。拦截规则名：`semantic/sqli`、`semantic/xss`。
注意：这是轻量语义层，不是完整 AST 引擎；与 CRS 互补而非替代。

## resp_filter（RespFilterSettings，响应敏感信息过滤）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `action` | string | `"mask"` | `mask` 脱敏 / `block` 整体拦截 |
| `presets` | string[] | `[]` | `phone`（CN 手机号）/ `idcard`（CN 身份证）/ `secret`（AK/SK 形态） |
| `patterns` | array | `[]` | 自定义：`[{"name":"my-id","regex":"\\b[0-9]{18}\\b"}]`（RE2 语法，不支持 lookbehind） |
| `body_limit` | int | 8388608 | 响应体扫描上限 |

## dynamic（DynamicSettings，动态防护）

```json
{"enabled": true, "min_bytes": 512, "max_bytes": 1048576}
```

对 text/html 响应逐请求 AES-GCM 加密并由注入的 WebCrypto 解码器还原，
线上字节形态每次访问都不同。**仅 HTTPS（安全上下文）生效**；压缩响应、
超限 body 自动跳过。动态站点会删除上游请求的 `Accept-Encoding`。

# RealIPSettings（真实客户端 IP）

站点部署在 LB/CDN 后时，TCP 对端是代理而非真实客户端。配置可信代理范围后，只有当请求的直接对端落在 `trusted_proxies` 内，才从指定头解析客户端 IP；ACL、GeoIP、限流、Bot、matcher、WAF（CRS REMOTE_ADDR）及所有日志/审计均改用解析结果。非可信对端永不信任其头（防伪造）。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 开关 |
| `header` | string | `"X-Forwarded-For"` | 承载客户端链的头名 |
| `trusted_proxies` | string[] | 必填（开启时） | 允许设置该头的对端 IP/CIDR 列表（如 `"10.0.0.0/8"`） |

解析规则：从链最右端向左跳过可信代理，首个非可信地址即客户端；全部可信时取最左端；头缺失/无合法 IP 时回退 TCP 对端。

```json
"real_ip": { "enabled": true, "trusted_proxies": ["10.0.0.0/8", "172.16.0.0/12"] }
```

# HeaderRewrite（请求头改写）

转发前对出站请求头执行用户配置的 set/add/del（在内置 X-Forwarded-* 处理之后执行，显式配置优先）。值支持占位符：`$client_ip`（真实客户端 IP）、`$remote_addr`（TCP 对端）、`$host`、`$scheme`、`$trace_id`、`$hdr.<Name>`（复制入站头，缺失时该操作跳过）。

| 字段 | 类型 | 说明 |
|---|---|---|
| `set` | object | 替换（或新增）出站头：`{"X-Real-IP": "$client_ip"}` |
| `add` | object | 追加不替换 |
| `del` | string[] | 删除出站头（内部追踪头外发前清除） |

Host/Content-Length/Transfer-Encoding/Connection 等框架与逐跳头禁止改写（配置加载时报错）。

```json
"headers": {
  "set": { "X-Client-Real-IP": "$client_ip", "X-Forwarded-User": "$hdr.X-Authenticated-User" },
  "del": ["X-Internal-Trace"]
}
```

# HealthSettings（上游健康）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 主动探测（定时 GET `path`，2xx/3xx 视为健康） |
| `path` | string | `"/"` | 探测路径 |
| `interval_sec` | int | 10 | 探测间隔 |
| `timeout_sec` | int | 3 | 探测超时 |
| `passive` | bool | `true` | 被动熔断（上游 5xx/连接失败累计） |
| `fail_threshold` | int | 3 | 连续失败次数触发熔断 |
| `cooldown_sec` | int | 30 | 熔断冷却时长 |

不健康节点自动摘除；全部不健康时 fail-open（轮询兜底，让错误在上游暴露）。

# ACMESettings（自动证书）

```json
{"email": "ops@example.com", "staging": false}
```

基于 Let's Encrypt（TLS-ALPN-01 于 HTTPS 监听器，HTTP-01 于 80 端口自动
短路）。`staging: true` 使用测试 CA。正式证书缓存在工作目录 `acme-cache/`；
staging 环境申请的测试证书单独缓存在 `acme-cache-staging/`，
与正式证书目录隔离、互不混用。

# WebhookSettings（告警推送）

```json
{"url": "https://hooks.example.com/kingmoat", "timeout_sec": 5}
```

每个 blocked/challenged 事件 POST 一条 Event JSON（与 `/api/logs` 条目一致）。
异步有界队列（1024），背压丢弃并计入 `kingmoat_audit_dropped_total`。

# ShipperSettings（审计日志外发）

```json
{"type": "clickhouse", "url": "http://ch:8123", "index": "kingmoat_events", "batch_size": 100, "flush_sec": 5}
{"type": "elasticsearch", "url": "http://es:9200", "index": "kingmoat"}
{"type": "loki", "url": "http://loki:3100", "index": "kingmoat"}
{"type": "s3", "endpoint": "minio.example.com:9000", "bucket": "waf-logs", "access_key": "...", "secret_key": "...", "prefix": "kingmoat/audit", "upload_archives": true}
{"type": "syslog", "url": "udp://siem.example.com:514", "index": "kingmoat", "syslog": {"format": "rfc5424"}}
{"type": "kafka", "brokers": ["kafka1.example.com:9092", "kafka2.example.com:9092"], "topic": "kingmoat-audit"}
```

- `clickhouse`：HTTP 接口 `POST {url}/?query=INSERT INTO <index> FORMAT JSONEachRow`，
  每行一条事件 JSON；表需自建，示例：
  ```sql
  CREATE TABLE kingmoat_events (
    ts String, trace_id String, site String, client_ip String,
    method String, path String, status Int32, action String,
    rule String, reason String, bot_class String
  ) ENGINE = MergeTree ORDER BY ts;
  ```
- `elasticsearch`：`POST {url}/_bulk`（索引 `index-YYYY.MM.DD`）
- `loki`：`POST {url}/loki/api/v1/push`（label `app=index`）
- `s3`：任意 S3 兼容对象存储（MinIO / 阿里云 OSS / 华为云 OBS / AWS S3），
  事件批量打包为 gzip NDJSON 对象上传至 `<prefix>/YYYY/MM/DD/audit-HHMMSS-xxxx.ndjson.gz`。
  - `endpoint`：`host[:port]`，可带 `http(s)://` 前缀；**无 scheme 时默认走 TLS**（同 `https://`），`http://` 明文，`use_ssl` 可显式覆盖。注意：该默认仅适用于本节平铺字段形态；`access_log.s3` / `ai_audit.ship.s3` 嵌套块的 `use_ssl` 默认 `false`（明文 HTTP），见对应小节
  - `bucket` / `access_key` / `secret_key` 必填；`region` 可选
  - `prefix`：对象键前缀，默认 `kingmoat/audit`
  - `upload_archives`：同时把每日 SQLite 快照上传到 `<prefix>/archives/`（异地容灾）
- `syslog`：标准 syslog（RFC 5424 / RFC 3164），每条事件一帧，MSG 为事件 JSON
  单行，APP-NAME 取 `index`。`url` 指定目标：`udp://siem:514`、`tcp://siem:514`
  或 `tls://siem:6514`；`syslog` 子对象必填（可为空对象 `{}` 取默认；存量缺块旧形态加载时自动合成默认块，见 [存量旧形态的加载期归一化](#存量旧形态的加载期归一化)）：

  | 字段 | 类型 | 默认 | 说明 |
  |---|---|---|---|
  | `protocol` | string | URL scheme | 传输：`udp` / `tcp` / `tls`（覆盖 URL scheme） |
  | `format` | string | `rfc5424` | 消息格式：`rfc5424`（IETF）/ `rfc3164`（BSD） |
  | `framing` | string | `octet` | TCP/TLS 帧：`octet`（RFC 6587，RFC 5424 默认）/ `newline`（传统，RFC 3164 默认） |
  | `facility` | int | `16` (local0) | 0..23；`0` 表示未设置并取默认 |
  | `severity` | int | `6` (info) | 0..7；`0` 表示未设置并取默认；blocked/challenged 事件固定为 4（warning） |
  | `hostname` | string | 本机主机名 | syslog HOSTNAME 字段 |
  | `app_name` | string | 取 `index` | syslog APP-NAME / tag |
  | `tls_skip_verify` | bool | `false` | `tls://` 目标的证书校验开关：默认 `false` = **校验证书链**，`true` 才跳过校验 |

  UDP 一条事件一个数据报；TCP/TLS 按 `framing` 分帧，写失败自动重连重试一次；
  拨号/写超时由 `timeout_sec`（默认 5s）约束，外发失败只记日志不影响业务。
- `kafka`：每条事件一个 JSON 消息写入 `brokers` + `topic`（有 `trace_id` 时作为消息 key）；
  `use_tls` 开启 TLS（默认明文）；`sasl` 复用 `username`/`password` 作 SASL 凭据
  （`plain` / `scram-sha256`，空 = 不认证，两者必填）；`tls_skip_verify` 为三态：
  **缺省（不写）= 不校验 broker 证书**（保持自签 broker 兼容的旧默认），
  显式 `false` 才校验证书链，`true` 同样跳过校验。开启 `use_tls` 且未显式设置
  `tls_skip_verify` 时，外发连接构建会输出一条 WARN 日志提示证书校验被关闭
  （防护日志 / 访问日志 / AI 会话外发同语义；生产环境建议显式
  `tls_skip_verify: false`）。
- `username` / `password`：HTTP Basic 认证，适用于 `clickhouse` / `elasticsearch` / `loki`
  （内网自建后端常要求）；留空不发送 Authorization 头。

> 未配置 webhook / log_shipper 时，控制台日志页会提示“日志仅存于本机”的风险提醒。

# AuditArchiveSettings（每日 DB 快照归档）

```json
{"enabled": true, "retention_days": 30}
```

每天首次跨日时对攻击日志库做一致性快照（`VACUUM INTO`）并 gzip 为
`<audit_log_dir>/archive/audit-YYYYMMDD.db.gz`，随后执行保留期清理：

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `true` | 每日快照开关（显式 `false` 关闭） |
| `retention_days` | int | `30` | 本地快照文件保留天数（<=0 永久保留）；配合 `s3` 的 `upload_archives` 可实现异地长存 |

快照恢复：解压后直接用任意 SQLite 工具打开，`events` 表含全字段，`raw`
列为事件完整 JSON。

# AuditQuerySettings（日志查询治理，热生效）

```json
{"degraded": false, "max_concurrent": 2, "timeout_ms": 5000}
```

控制台的历史/趋势查询运行在独立 query_only 只读连接池（与审计写入互不
争抢），并统一经过查询闸门：

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `degraded` | bool | `false` | 紧急降级开关：`true` 时所有日志查询返回 503，控制台查询负载归零，转发不受影响 |
| `max_concurrent` | int | `2` | 并发查询上限（1–8），满载请求立即 429 |
| `timeout_ms` | int | `5000` | 单次查询超时（1000–30000），超时返回 504 |

> 保留期（`audit_retention_days` / `audit_archive.retention_days`）为启动时
> 快照，修改需重启；本段设置随配置发布热生效。

# PenaltySettings（攻击惩罚，热生效）

```json
{"enabled": true, "window_sec": 600, "threshold": 20, "ban_sec": 3600, "action": "deny", "throttle_per_min": 10}
```

同一源 IP 在统计窗口内累计 ≥ threshold 次「拦截 + 挑战」即触发惩罚：
`deny`（临时封禁，惩罚期内全部拒绝）或 `throttle`（每分钟仅放行
throttle_per_min 个请求，超出 429）。状态存内存：发布配置或重启后清空。
白名单命中（global/site ACL）与误报例外优先于惩罚；命中记录在攻击日志
（规则 `penalty/engine`）。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 引擎开关 |
| `window_sec` | int | `600` | 统计窗口（秒） |
| `threshold` | int | `20` | 触发阈值（拦截+挑战次数） |
| `ban_sec` | int | `3600` | 惩罚时长（秒） |
| `action` | string | `deny` | `deny` 临时封禁 / `throttle` 严格限速 |
| `throttle_per_min` | int | `10` | throttle 模式下每分钟放行数 |

# MetricsSettings（可选 Prometheus 指标端点，热生效）

```json
{"enabled": false}
```

开启后 `GET /metrics` 输出 Prometheus 文本格式指标（请求/拦截/BOT 计数、
队列深度与丢弃 gauge、Go runtime），位于控制台认证面内（匿名不可抓取）；
默认关闭，关闭时该端点返回 404。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 是否暴露 /metrics 端点 |

# AccessLogSettings（全量访问日志管道）

```json
{"enabled": true, "type": "clickhouse", "url": "http://ch:8123", "index": "kingmoat_access", "sample_pct": 100, "batch_size": 200, "flush_sec": 5}
{"enabled": true, "type": "syslog", "url": "tcp://siem.example.com:514", "index": "kingmoat_access", "syslog": {"format": "rfc5424", "framing": "octet"}}
{"enabled": true, "type": "kafka", "brokers": ["kafka1.example.com:9092"], "topic": "kingmoat-access"}
```

每个转发/拦截/挑战/重定向请求记录一条（ts、trace_id、site、client_ip、method、
path、query、status、bytes、latency_ms、user_agent、outcome、rule），批量推送到
六类后端之一（ClickHouse 表 `index`，同样 JSONEachRow / ES bulk 日索引 /
Loki push / S3 gzip NDJSON 对象 / syslog / Kafka，后端语义同
[ShipperSettings](#shippersettings)）；APP-NAME 取 `index`，blocked/challenged 请求以
warning 级发送。本管道自身不在本地落盘（把访问日志留在本地检索用独立的
`access_log_record` 节，见 [AccessLogRecordSettings](#accesslogrecordsettings访问日志本地留存顶层-access_log_record)，两节完全独立互不影响）；`sample_pct` 支持确定性采样（如 10 = 仅记录 10%）；
背压丢弃计入 metrics。热路径仅支付一次有界队列发送 + 轻量状态包装（透传
Flush/Hijack，WebSocket/SSE 不受影响）。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 管道开关 |
| `use_audit_channel` | bool | `false` | 复用 `log_shipper` 通道，见 [外发通道复用（use_audit_channel）](#外发通道复用use_audit_channel) |
| `type` | string | 必填（启用时） | `clickhouse` / `elasticsearch` / `loki` / `s3` / `syslog` / `kafka` |
| `url` | string | `""` | HTTP 后端 base URL；syslog 为目标（`udp://` / `tcp://` / `tls://`）；s3 不用 |
| `index` | string | `kingmoat_access` | 表 / ES 索引前缀 / Loki label / syslog APP-NAME（bucket 由 `s3` 块给出） |
| `sample_pct` | int | `100` | 确定性采样 1–100 |
| `batch_size` | int | `200` | 批量条数 |
| `flush_sec` | int | `5` | 冲刷间隔（秒） |
| `timeout_sec` | int | `5` | 单次写出超时（秒） |
| `username` / `password` | string | `""` | HTTP Basic（`clickhouse` / `elasticsearch` / `loki`）；同时是 kafka SASL 凭据（`sasl` 为 `plain`/`scram-sha256` 时必填） |
| `s3` | object | — | `type:"s3"` 时**必须提供嵌套 `s3` 块**（新建/提交配置发布被拒；存量平铺旧形态加载时自动归一化，见 [存量旧形态的加载期归一化](#存量旧形态的加载期归一化)）：`endpoint`（`host[:port]`）/ `bucket` 必填，`prefix` / `access_key` / `secret_key` / `use_ssl`（默认 `false` = 明文 HTTP，需 TLS 显式 `true`，与 `log_shipper` 平铺形态的无 scheme 默认 TLS 不同） |
| `syslog` | object | — | `type:"syslog"` 时**必须携带 `syslog` 子块**（新建/提交缺块发布被拒；存量缺块旧形态加载时自动合成默认块，见 [存量旧形态的加载期归一化](#存量旧形态的加载期归一化)），字段同 [ShipperSettings 的 syslog 表](#shippersettings) |
| `brokers` / `topic` | array/string | — | `type:"kafka"`：broker 列表（至少一个）与 topic（必填） |
| `use_tls` / `sasl` / `tls_skip_verify` | bool/string | — | kafka 传输：TLS（默认明文）/ SASL 机制（`plain` / `scram-sha256` / `none`）/ 三态证书校验（缺省 = 不校验，同 `log_shipper`） |

# AccessLogRecordSettings（访问日志本地留存，顶层 `access_log_record`）

把开启站点的访问日志留存在本地 SQLite 库（`<audit_log_dir>/access-logs.db`，WAL，单表），**无需配置外发即可在控制台「访问日志」页查询**。与本文件其余配置节的关键区别：**默认完全关闭**，配置中没有本节（或 `mode:"off"`）时行为与未提供该功能的版本字节级一致。

**与外发节 `access_log` 完全独立**：开/关外发不影响本地记录，反之亦然；外发 `sample_pct` 采样只作用于外发投递，**不影响本地留存**——开启记录的站点全量落库。「全部站点」（`mode:"all"`）不含未匹配任何站点的请求（空站点标签，不属于任何站点）。

```json
{
  "access_log_record": {
    "mode": "sites",
    "sites": ["shop.example.com", "api.example.com"],
    "retention_days": 7,
    "max_disk_mb": 1024,
    "batch_size": 256,
    "flush_sec": 1
  }
}
```

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `mode` | string | `off` | `off`（默认，不记录）/ `all`（全部站点）/ `sites`（仅 `sites` 列表内站点） |
| `sites` | string[] | `[]` | 仅 `mode:"sites"` 时生效：站点**首域名**（`sites[].domains[0]`，比对前转小写）。引用未配置的站点**发布/加载即拒**，错误信息附全部有效站点名清单；列表为空同样被拒 |
| `retention_days` | int | `7` | 按天保留 1–90（0 = 默认 7），每日任务清理超期数据 |
| `max_disk_mb` | int | `1024` | 库文件磁盘上限（db + wal + shm 合计）128–10240 MB（0 = 默认 1024）。顶格配置且库接近满时，控制台「访问日志」页的 5 秒轮询里的行数统计（全表计数）可能逼近读超时，表现为 `record.rows` 短暂归零——不影响写入与查询，减小档位可恢复实时性 |
| `batch_size` | int | `256` | 批量入库条数 64–2048（0 = 默认 256） |
| `flush_sec` | int | `1` | 批量冲刷间隔（秒）1–60（0 = 默认 1） |

维护语义（`internal/accesslog` SQLite sink，后台执行、不阻塞请求路径）：

- **保留期清理**：按天任务删除超过 `retention_days` 的记录；启动时立即执行一次维护（避免频繁重启的实例永远等不到首个周期）；
- **磁盘上限**：容量检查由两个触发器驱动——累计写入量达到 `max(max_disk_mb/8, 16MB)` 阈值即额外触发一轮检查，15 分钟周期检查始终保留为兜底；超限按最旧优先逐天淘汰，直至估算活跃数据降到上限的 **80%**（软限：两次检查之间写入的峰值可临时超过上限）；
- **数据盘低水位保护**：库所在数据盘剩余空间低于 `max(1.2×max_disk_mb, 512MB)` 时，先对超出库容量上限的部分再补一轮淘汰；仍低则**暂停落盘**（入站请求计丢弃数，不影响业务流量），余量恢复后自动恢复记录。低水位暂停对应 `disk_low_paused` 告警（常规容量淘汰对应 `capacity_evicted`），均出现在 `GET /api/status` 的 `runtime_alerts`（见 [docs/API.md](API.md)）；
- **关闭不删数据**：把 `mode` 改回 `off` 只停止记录，已留存数据保留在库中、停止记录期间不自动清理（重新开启记录后恢复按期清理）；**关闭期间仍可在控制台「本地历史」（`GET /api/access_logs/history`）只读检索这些残留**（以磁盘只读方式打开库，参数与响应形态与开启态一致）；需要立即释放空间用控制台「立即清空」（见下）。

**入库前脱敏与截断（隐私要点）**：

- **query 敏感参数掩码**：凭据/个人标识类参数的值统一掩码为 `***`，键名与非敏感参数原样保留；无法解析为键值形态的整段 query 同样掩码。匹配在**归一化后的键名**上进行：百分号解码循环至稳定（上限 2 轮，双重编码如 `%2561pi_key` 可命中，三重及以上编码不在威胁模型内、不解码）、小写化、全角/同形字折叠（如 `ＡＰＩ＿ＫＥＹ`、西里尔 `о` 伪写 `tоken`）、剔除全部非字母数字字符，因此 `Token=` / `api-key` / `session_id` / `API%2DKEY` 均命中。分段以 `&` 与 `;` 两个分隔符切分。敏感键集合含精确键（`at` / `pass` / `sid` / `sign` / `auth` / `authorization` / `otp` / `code` / `tel` / `mail` / `connectsid` 等）与子串族（`token` / `secret` / `password` / `pwd` / `apikey` / `session` / `signature` / `email` / `mobile` / `idcard` 等）；`pass` 子串族是**显式取舍**：`compass` / `passport` / `bypass` / `surpass` / `passthrough` 等含 pass 的良性键值也会被掩（宁掩勿漏）。超长键截断到 256 字节后再归一化匹配，长键不再绕过脱敏；通用键名 `key` 本身不在敏感集（`key=value` 不掩），无值的空参数（如 `token=`）也无密可泄、原样保留。字段长度上限（超限截断，按 UTF-8 字节边界）：`query` 2048 字节、`user_agent` 512 字节、`path` 1024 字节。
- **path 内嵌凭据脱敏**：仅替换高信号凭据形态的路径段为 `<masked>`，其余段落逐字保留（路径结构可读，如 `/api/v1/users/<masked>/profile`）。掩码形状：32 位以上连续 hex（md5/sha1/sha256 摘要、无连字符 UUID，可作下载文件名包裹如 `<32hex>.pdf`）、标准 UUID（8-4-4-4-12 hex）、三段式 JWT（header 以 `eyJ` 开头）、`sk-` / `bearer-` / `bearer%20` 前缀凭据（剩余部分为 token 形态或 ≥16 字节 base64url）、24 位以上大小写+数字三类混合 base64url、32 位以上含数字的 base64url。保留形态（永不掩码）：纯数字 ID、版本段（`v1` / `v2.0`）、日期段（`2026-10-13`）、常规文件名（`report.pdf`）及短于 16 字节的段落；≥24 位大小写数字混合的普通单词段同样会被掩（宁掩勿漏）。

记录内容为转发/拦截元数据（ts/trace_id/site/client_ip/method/path/query/status/bytes/latency_ms/user_agent/outcome/rule/attack_type），不含请求/响应 body。

查询与清理入口（all-in-one 控制台）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/access_logs/history` | 本地历史分页检索（见 [docs/API.md](API.md)）；与外发无关，未配置外发也可查；关闭记录后仍可只读检索残留数据 |
| GET | `/api/access_logs` | 实时内存尾；响应内 `record` 对象上报本地留存状态（enabled/mode/retention_days/max_disk_mb/size_bytes/evicted/rows/oldest_ts/dropped/residual） |
| POST | `/api/access_logs/purge` | **仅 admin**：清空本地访问日志并回收文件空间，落一条控制台变更审计；未开启记录/无库时安全返回 0 |

队列溢出丢弃数与积压深度经 `/metrics` 暴露：`kingmoat_accesslog_local_dropped_total`、`kingmoat_accesslog_local_queue_depth`。`dropped` 计入所有入库前丢弃：队列溢出、数据盘低水位暂停、关闭竞态与批量写库失败（不只队列溢出）。static 纯文件模式同样支持本地留存（启动时按配置文件生效），但无控制台与查询/清理 API。

# 外发通道复用（use_audit_channel）

`access_log` 与 `ai_audit.ship` 支持开启 `use_audit_channel`，直接复用攻击日志外发（`log_shipper`）已配置的通道，避免为每类日志重复维护同一套后端连接：

- **默认关**；开启时通道参数（后端 `type`、`url`、认证、批量/冲刷参数、s3/syslog/kafka 传输）全部取自 `log_shipper`，本节的同名通道字段被忽略但**保留原值**——关闭开关即可切回，无需重填；
- **身份字段仍属本节**：`index`（表 / ES 索引前缀 / Loki label）、`sample_pct`、S3 对象前缀（`s3.prefix`）、syslog APP-NAME（`syslog.app_name`）——攻击 / 访问 / AI 会话三类日志不会共享同一个存储身份；
- 开启而 `log_shipper` 未配置时，**发布直接拒绝**（错误形如 `config: access_log.use_audit_channel is on but the audit-log outbound (log_shipper) is not configured`）；
- `log_shipper` 通道变更后，复用方随本次发布自动重建并继续复用；通道未变时修改本节被忽略的通道字段不会触发重建。

# 存量旧形态的加载期归一化

两类旧形态配置在**加载时自动归一化**，存量数据升级后不会因新校验被判非法而导致进程拒绝启动（`configcenter.Open` / `config.Load` 失败）：

- `access_log` 以**平铺字段**（`endpoint` / `bucket` / `prefix` / `access_key` / `secret_key` / `use_ssl`）声明 `type:"s3"` 且无嵌套 `s3` 块：存在的平铺字段整体搬入嵌套 `s3` 块；
- `ai_audit.ship` 声明 `type:"s3"` 且无嵌套 `s3` 块时，已废弃的平铺 `prefix` / `use_ssl` 字段以 **move 语义**迁入嵌套 `s3` 块（迁入后平铺字段置空，迁移幂等）；
- `log_shipper` / `access_log` / `ai_audit.ship` 任一节 `type:"syslog"` 但缺 `syslog` 子块：自动合成默认块（`protocol` 由 `url` 的 scheme 推导——`tcp://` / `tls://` 对应同名传输，其余含裸 host 默认 `udp`；`format=rfc5424`）。

归一化边界：

- 仅发生在**加载路径**（静态配置文件加载、控制台配置库存量修订与种子加载、历史修订回滚），生效时打 **WARN 日志**并逐项列出归一化内容；同一次加载的归一化/降级事实还会出现在 `/api/status` 的 `load_notes` 字段与控制台顶部横幅（含「日志外发」「AI 会话审计」两个设置页签的就近提示），成功发布后清空、不回写库内修订，见 [docs/API.md](API.md) 的 `GET /api/status`；
- **幂等且不改写历史**：合规配置字节级透传；库内存量修订保持原样，每次启动按相同规则重新推导（回滚产生的**新修订**则存归一化后的形态）；
- **发布校验对提交内容保持严格**：新建/修改配置仍必须使用嵌套 `s3` 块与 `syslog` 块，非法形态提交发布即拒——归一化只兜存量加载，不放行新写入。

# RisksSettings（专项风险引擎，顶层 `risks`）

控制台「API 安全」页配置；规则语义与规则表见 [API-ASSETS.md](API-ASSETS.md)。

```json
{"enabled": true, "scan_interval_hours": 24, "zombie_days": 30, "notify_webhook": "https://hooks.example/xxx"}
```

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 风险引擎开关（observe-only，不阻断） |
| `scan_interval_hours` | int | `0`（关） | 周期自动全量扫描间隔，1–168 小时，0 = 不周期扫描（仅手动「立即扫描」）；随发布热生效，无需重启 |
| `bruteforce` | object | 30 次 / 300s | R3 登录爆破阈值（`count`/`window_sec`） |
| `zombie_days` | int | `30` | R5 僵尸 API 判定天数 |
| `notify_webhook` | string | `""` | 新发现风险 POST 通知地址 |

> 历史说明：早期版本存在 `risks.cron` 字段，从未接线生效（调度从未实现），已移除；历史配置中的该键被忽略，行为无变化。

# AIAuditSettings（AI 会话审计，顶层 `ai_audit`）

自动识别经过 WAF 的 LLM API 调用并捕获请求报文与模型输出全文（OpenAI / Anthropic / Gemini 及百度千帆、阿里 DashScope、MiniMax、商汤 SenseNova 等国产协议，OpenAI 兼容端点由路径后缀规则覆盖）。控制台「AI 会话审计」页检索，设置页「AI 会话审计」Tab 配置；**保存发布后即时生效（无需重启）**。默认关闭。

```json
{
  "enabled": true,
  "sample_pct": 100,
  "max_request_bytes": 32768,
  "max_response_bytes": 65536,
  "redact_content": true,
  "include_embeddings": false,
  "include_unknown": false,
  "retention_days": 30,
  "ship": {"enabled": true, "type": "elasticsearch", "url": "http://es:9200", "index": "kingmoat_ai_sessions"}
}
```

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 捕获开关；仅命中 LLM 形态的请求才进入捕获管线 |
| `sample_pct` | int | `100` | 采样率 1–100（按会话计） |
| `max_request_bytes` | int | `32768` | 单会话请求捕获上限 4096–524288 字节，超出截断并打 `trunc_in` 标记 |
| `max_response_bytes` | int | `65536` | 模型输出捕获上限 4096–524288 字节，超出截断并打 `trunc_out` 标记 |
| `redact_content` | bool | `true` | 入库/外发前脱敏：sk-/Bearer/xox/AKIA、凭据 JSON 字段、口令形参、32+ hex 高信号串掩码为 `[REDACTED]`；关闭后对话全文明文，请确认业务允许 |
| `include_embeddings` | bool | `false` | 是否审计 embeddings 调用（响应为向量无审计价值，默认仅记录请求元数据） |
| `include_unknown` | bool | `false` | 记录 LLM 形态但未识别协议的调用（provider=unknown，仅元数据 + 截断原始请求） |
| `retention_days` | int | `30` | 会话库保留期 1–365，每日自动清理 |
| `ship` | object | — | 中心外发（可选，默认关）：六类后端与传输选项同 [`access_log`](#accesslogsettings)，见下方 ship 字段表与 [外发通道复用（use_audit_channel）](#外发通道复用use_audit_channel) |

**ship 字段**（与 `access_log` 同构，六类后端）：

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 外发开关 |
| `use_audit_channel` | bool | `false` | 复用 `log_shipper` 通道，见 [外发通道复用](#外发通道复用use_audit_channel) |
| `type` | string | 必填（启用时） | `clickhouse` / `elasticsearch` / `loki` / `s3` / `syslog` / `kafka`；ES 为 `POST {url}/_bulk` 日索引（`{index}-YYYY.MM.DD`） |
| `url` | string | `""` | HTTP 后端 base URL；syslog 为目标（`udp://` / `tcp://` / `tls://`）；s3 不用 |
| `index` | string | `kingmoat_ai_sessions` | 表 / ES 索引前缀 / Loki label / syslog APP-NAME |
| `sample_pct` | int | `100` | 外发采样 1–100（与上方捕获 `sample_pct` 相互独立）；控制台可配（滑杆） |
| `batch_size` / `flush_sec` / `timeout_sec` | int | `200` / `5` / `5` | 批量与冲刷参数（同 `access_log`） |
| `username` / `password` | string | `""` | HTTP Basic（`clickhouse` / `elasticsearch` / `loki`）；同时是 kafka SASL 凭据 |
| `s3` | object | — | `type:"s3"` 时**必须提供嵌套 `s3` 块**（新建/提交配置发布被拒；存量平铺旧形态加载时自动归一化，见 [存量旧形态的加载期归一化](#存量旧形态的加载期归一化)）：`endpoint` / `bucket` 必填，`prefix`（默认 `kingmoat/ai`）/ `access_key` / `secret_key` / `use_ssl`（默认 `false` = 明文 HTTP） |
| `syslog` | object | — | `type:"syslog"` 时**必须携带 `syslog` 子块**（新建/提交缺块发布被拒；存量缺块旧形态加载时自动合成默认块，见 [存量旧形态的加载期归一化](#存量旧形态的加载期归一化)）；APP-NAME 取本节 `index`，不与另两类日志共享身份 |
| `brokers` / `topic` / `use_tls` / `sasl` / `tls_skip_verify` | — | — | kafka 五字段，规则同 [`log_shipper`](#shippersettings)（`tls_skip_verify` 缺省 = 不校验证书） |
| `use_ssl` / `prefix`（平铺） | — | — | **已废弃**：存量旧形态在加载时自动迁入嵌套 `s3` 块（move 语义，见 [存量旧形态的加载期归一化](#存量旧形态的加载期归一化)），新配置一律用嵌套 `s3` 块 |

行为要点：多模态图片/音频/视频一律替换为 `[IMG/AUDIO/VIDEO base64 len=N]` 占位符；非流式响应 tee、SSE 逐行聚合（OpenAI delta / Anthropic content_block_delta / Gemini candidates / DashScope `is_end` 等），15 分钟挂起兜底定案（`interrupted` 标记）；会话数据落 `<数据目录>/ai-sessions-central.db`（SQLite，WAL），与审计日志库独立。

# IPGroupSettings（IP 组订阅）

```json
[{"name": "threat-feed", "url": "https://feeds.example.com/bad-ips.txt", "interval_min": 60},
 {"name": "corp-nets", "file": "/etc/kingmoatwaf/corp.txt"}]
```

列表格式：每行一个 IP/CIDR，`#` 注释。ACL 中以 `"group:<name>"` 引用；
刷新失败保留上次快照。

# 环境变量（管理面）

| 变量 | 说明 |
|---|---|
| `KMWAF_ADMIN_HASH`（旧 `KINGMOAT_ADMIN_HASH` 仍回退读取） | 控制台管理员 argon2id 哈希；未设置时控制台认证**自动武装**（生成随机会话密钥并启用登录），创建唯一的内置账号 `kmadmin`，初始口令取自 `KMWAF_BOOTSTRAP_PASSWORD`，未设置时随机生成 24 位写入控制台数据目录下 `initial-admin-password.txt`（0600），首次登录强制改密；预设该变量用于把管理凭据锚定为自选强口令 |
| `KMWAF_ADMIN_TOTP`（旧 `KINGMOAT_ADMIN_TOTP` 仍回退读取） | 可选 base32 TOTP 密钥，启用后登录需动态码 |

# ConsoleSecuritySettings（控制台安全策略）

顶层 `security` 对象（用户管理 → 安全设置页）:

```json
{
  "password_min_len": 12,
  "password_complexity": true,
  "password_max_age_days": 90,
  "password_history_count": 3,
  "session_timeout_min": 240,
  "login_max_failures": 10,
  "login_lockout_min": 15
}
```

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `password_min_len` | int | `8` | 创建用户/改密的最小口令长度（存量口令不受影响） |
| `password_complexity` | bool | `false` | 要求口令同时包含大写、小写字母与数字 |
| `password_max_age_days` | int | `0` | 口令最长使用天数，登录时强制改密（0 = 关闭） |
| `password_history_count` | int | `0` | 禁止复用最近 N 次口令（0 = 关闭，上限 24） |
| `session_timeout_min` | int | `0` | 控制台会话有效期（分钟，0 = 12h）；启动时快照，修改需重启 |
| `login_max_failures` | int | `10` | 锁定窗口内同源 IP 登录失败上限（低于 3 按 3 计） |
| `login_lockout_min` | int | `15` | 登录失败滑动锁定窗口（分钟） |

# 完整示例

见仓库根目录 [config.example.json](../config.example.json)；各防护块示例见
[README](../README.md)。

# DiskGuardSettings（日志磁盘占用守卫）

```json
{"enabled": true, "high_pct": 90, "low_pct": 65, "interval_sec": 300}
```

仅监控**数据盘**（审计库所在卷）参与占比评比。超过 `high_pct`（默认 90%）时按
历史优先先进先出清理：先删最旧的每日归档快照（archive/*.db.gz），再按天删除
最旧的活动事件，直至降到 `low_pct`（默认 65%）或无可清理。每个清理周期都有
结构化日志（disk guard: ...）。`enabled: false` 可关闭（不推荐）。
