# KingMoat WAF REST API 参考

控制台 API（WebUI 与 `/api/*` 同源），由 all-in-one 模式（`kingmoatwaf -console-addr`）提供。

> 本文列核心端点；完整端点清单以控制台 `/openapi.json` 为准。

- Base URL：`http://<console-host>:<console-port>`（端口由 `-console-addr` 指定，一键部署默认 `8443`）
- 数据格式：请求/响应均为 JSON（UTF-8）
- 错误格式：`{"error": "<message>"}`，配合标准 HTTP 状态码。未认证（401）与权限不足（403）返回中文文案（如 `未登录或会话已失效，请重新登录`、`权限不足：该操作需要管理员（admin）权限`，403 文案内注明所需角色）；登录链路的三个机器码 `totp_required` / `invalid credentials` / `password_change_required` **保留英文原样**（前端按 code 匹配）

## 认证

未设置环境变量 `KMWAF_ADMIN_HASH`（argon2id 哈希，`kmwafctl hash-password` 生成，支持 `-stdin`）时，控制台认证**自动武装**：首次启动生成随机会话密钥并强制启用登录，创建唯一的内置账号 `kmadmin`，其初始口令由 `KMWAF_BOOTSTRAP_PASSWORD` 指定，未指定时随机生成 24 位写入控制台数据目录下的 `initial-admin-password.txt`（0600），首次登录强制改密。预设该变量用于把管理凭据锚定为自选强口令，跳过初始口令窗口期（控制台绑定非回环地址前务必预设）。

两步验证：

- **全局（兼容）**：设置 `KMWAF_ADMIN_TOTP`（base32 密钥）后，所有账号登录必须携带 6 位动态码；
- **逐用户（推荐）**：管理员在「用户管理」为单个账号启用 TOTP（扫码 + 动态码确认），仅该账号登录需要动态码；账号自身 MFA 优先于全局密钥。

四种凭证方式：

| 方式 | 用法 | 适用 |
|---|---|---|
| Session Cookie | `POST /api/login` 获取 `km_session` Cookie（12h 有效，TLS 下带 Secure 标志） | Web 控制台 / 浏览器 |
| HTTP Basic | `Authorization: Basic base64(<user>:<password>)` | 脚本 / CI |
| API Key（Bearer） | `Authorization: Bearer kma1_<id>_<secret>`，继承所属账号角色，可在用户管理页生成/撤销 | 脚本 / Prometheus 采集 |

登出（吊销全部已签发会话并清 Cookie）：`POST /api/logout`。

> 开启逐用户或全局 TOTP 的账号经 HTTP Basic 访问会被拒绝（Basic 无动态码通道，失败计入防爆破锁定）；API Key（Bearer）是独立凭证，不受 MFA 影响。

未认证访问返回 `401`。`/metrics` 挂在控制台端口，与其他 API 一样受控制台认证保护；`metrics.enabled` 默认 `false`，关闭时该端点返回 404。

```bash
# 登录
curl -c cookies.txt -X POST http://127.0.0.1:8081/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<pw>","totp":"123456"}'

# 之后带 Cookie 调用
curl -b cookies.txt http://127.0.0.1:8081/api/status

# 或直接 Basic
curl -u admin:<pw> http://127.0.0.1:8081/api/status

# 或使用用户管理页签发的 API Key（继承账号角色）
curl -H 'Authorization: Bearer kma1_1a2b3c4d_xxxxxxxxxxxx' http://127.0.0.1:8081/api/status
```

## 端点总览

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| POST | `/api/login` | 免 | 登录（password [+ totp]） |
| POST | `/api/logout` | 免 | 登出并吊销会话 |
| GET | `/api/status` | 是 | 版本 / revision / 站点数 / 时间 |
| GET | `/api/config` | 是 | 当前生效配置与 revision |
| POST | `/api/config/publish` | 是 | 发布新配置（校验通过即热生效） |
| GET | `/api/revisions` | 是 | 配置版本历史 |
| POST | `/api/revisions/{id}/rollback` | 是 | 回滚到指定 revision（生成新 revision） |
| GET | `/api/logs?limit=N` | 是 | 最近攻击/挑战/重定向事件（内存环，默认 100，上限 1000） |
| GET | `/api/access_logs` | 是 | 全量访问日志实时内存尾（默认 200，上限 2000；响应含 `record` 本地留存状态对象） |
| GET | `/api/access_logs/history` | 是 | 访问日志本地历史检索（`access_log_record` 落库数据；分页 + 过滤，见下文） |
| POST | `/api/access_logs/purge` | admin | 清空本地访问日志库并回收空间（破坏性，落控制台变更审计；未开启记录时安全返回 0） |
| GET | `/api/stats` | 是 | 今日拦截/挑战/观察计数 |
| GET | `/api/certificates` | 是 | TLS 证书清单（来源/主体/到期时间） |
| GET | `/api/users` | admin | 控制台用户列表（RBAC，含 MFA/API Key 状态） |
| POST | `/api/users` | admin | 新增用户（username/password/role） |
| PATCH | `/api/users/{username}` | admin | 改角色/密码/禁用（最后一个启用管理员受保护） |
| DELETE | `/api/users/{username}` | admin | 删除用户 |
| POST | `/api/users/{username}/apikey` | admin | 生成（或轮换）API Key，明文仅返回一次 |
| DELETE | `/api/users/{username}/apikey` | admin | 撤销 API Key |
| POST | `/api/users/{username}/mfa/setup` | admin | 发起 TOTP 注册（返回密钥/otpauth URL/二维码） |
| POST | `/api/users/{username}/mfa/confirm` | admin | 动态码确认，激活该账号 MFA |
| DELETE | `/api/users/{username}/mfa` | admin | 关闭该账号 MFA |
| GET | `/api/me` | 是 | 当前账号身份与凭据状态（username/role/api_key_id/totp_enabled） |
| POST | `/api/me/apikey` | 是 | 自助签发（或轮换）自己的 API Key |
| DELETE | `/api/me/apikey` | 是 | 自助撤销自己的 API Key |
| POST | `/api/me/mfa/setup` | 是 | 自助发起自己的 MFA 注册（扫码+确认） |
| POST | `/api/me/mfa/confirm` | 是 | 自助确认激活自己的 MFA |
| DELETE | `/api/me/mfa` | 是 | 自助关闭自己的 MFA |
| GET | `/api/audit/changes?limit=N` | 是 | 控制台管理操作变更审计（谁/何时/做了什么，最多 500） |
| GET | `/api/policy/exceptions` | 是 | 误报加白例外列表 |
| POST | `/api/policy/exceptions` | operator | 新增加白例外（site/path/prefix/rule_id/comment），发布热生效 |
| DELETE | `/api/policy/exceptions/{index}` | operator | 撤销加白例外（发布热生效） |
| GET | `/api/policy/disable-state` | 是 | 当前各站点被禁用的检测模块/CRS 分类快照（微引擎 disable 规则命中后的实时状态，发布重置） |
| GET | `/api/ipgroups` | 是 | IP 组订阅列表（条目数/预览/最后错误） |
| POST | `/api/ipgroups/{name}/refresh` | operator | 手动刷新订阅组 |
| POST | `/api/outbound/test` | operator | 外发连通性与认证测试（只读探测，可带未保存的局部配置；不落库不发布，并发单飞返回 429） |
| POST | `/api/logship/test` | operator | 旧版防护日志外发探测（兼容保留，`kind` 被钉为 `audit`、请求体 `kind` 被忽略，但请求体 `settings` 局部覆盖仍生效；建议改用 `/api/outbound/test`） |
| GET | `/api/ai_sessions` | auditor | AI 会话审计记录列表（`?site=&provider=&q=&limit=&offset=`；未配置中心库时返回空集） |
| POST | `/api/system/restart` | admin | 向 systemd 异步提交 kingmoatwaf 服务重启（body 可选 `delay_seconds` 0–60；仅 systemd 形态可用，否则 501） |
| GET | `/metrics` | 是 | Prometheus 指标（挂在控制台端口、受控制台认证保护；`metrics.enabled` 默认关闭，关闭时 404） |
| GET | `/api/upgrade/status` | admin | 在线升级状态：当前版本 + 最新版本（60s 缓存，`?refresh=1` 跳过）+ 进行中任务 + 历史 |
| POST | `/api/upgrade/check` | admin | 强制版本检查（绕过缓存并以新结果回填） |
| POST | `/api/upgrade/start` | admin | 启动升级任务（空 `target_version` = 最新；409 任务进行中 / 429 失败冷却） |
| GET | `/api/upgrade/task?id=` | admin | 查询单个升级任务（404 未知 id） |

## 角色权限矩阵（RBAC）

| 操作 | admin | operator | auditor |
|---|---|---|---|
| 仪表盘/日志/资产/风险/证书查看 | ✓ | ✓ | ✓ |
| 清空本地访问日志（`/api/access_logs/purge`） | ✓ | ✗ | ✗ |
| 配置发布 / 回滚 | ✓ | ✓ | ✗ |
| 风险扫描 / 状态处置 / 资产忽略 / AI 报告 | ✓ | ✓ | ✗ |
| 外发连通性/认证测试 | ✓ | ✓ | ✗ |
| 用户管理 | ✓ | ✗ | ✗ |

未认证访问返回 `401`（文案 `未登录或会话已失效，请重新登录`）；角色不足返回 `403`（文案形如 `权限不足：该操作需要操作员（operator）权限`，按所需角色显示）。

## POST /api/outbound/test

外发通道连通性与认证测试（operator+）：在**不保存、不发布**的前提下探测目标后端能否连通、凭据是否有效。覆盖六类外发（`elasticsearch` / `clickhouse` / `loki` / `s3` / `syslog` / `kafka`），`kind` 选择要探测的配置节：`audit`（防护日志外发 `log_shipper`，缺省值）/ `access`（访问日志外发 `access_log`）/ `ai`（AI 会话外发 `ai_audit.ship`）。

全程只读、无任何写副作用——不建索引、不写对象、不发事件、不落库、不发布配置；唯一留痕是控制台变更审计（只记 kind/state/type/目标 host:port/耗时，不含凭据）。

请求体（可整体省略，省略或传 `{}` 即探测已保存配置）：

```json
{"kind": "audit", "settings": {"url": "http://es-new.internal:9200", "password": "new-pw"}}
```

- `kind`：`audit` / `access` / `ai`，缺省按 `audit` 处理；其他值返回 400。
- `settings`：对应配置节的**局部覆盖**——出现的键覆盖已保存配置（含显式 `false` 与空串），未出现的键保留已保存值；改完地址/密码可直接测，无需先保存发布。
- 服务端按「有效节」解析（与运行时同源）：`use_audit_channel` 开启时探测的就是投递实际会用的防护日志通道 + 本节身份字段；开关开启而 `log_shipper` 未配置时返回 `config_incomplete`。

各类型探测点（全部只读）：Elasticsearch `GET /_cluster/health`、ClickHouse `GET /?query=SELECT 1`、Loki `GET /ready`（三者携带已配置 Basic 凭据、不跟随重定向、不使用环境代理），S3 只读校验凭据与桶（TCP 拨号 + minio-go 桶检查），kafka Metadata（含 SASL 握手），syslog TCP 连接 / TLS 握手 / UDP 地址解析。

响应（HTTP 200，结论在 body；示例为 s3 的两步探测）：

```json
{
  "state": "ok",
  "ok": true,
  "type": "s3",
  "latency_ms": 87,
  "detail": "s3 凭据有效，桶可访问（只读探测，未验证写权限）",
  "checks": [
    {"step": "dial", "state": "ok"},
    {"step": "s3", "state": "ok"}
  ]
}
```

| 字段 | 说明 |
|---|---|
| `state` | `ok`（连通且认证通过）/ `degraded`（可达，但端到端投递或完整认证无法以只读方式证明）/ `fail`（失败，见 `reason`） |
| `ok` | 兼容旧字段：`state` 为 `ok` 或 `degraded` 时为 `true` |
| `type` | 实际探测的外发类型；配置不完整未触达目标时缺省 |
| `latency_ms` | 整次探测耗时（单步超时 4 秒，总预算约 8 秒） |
| `reason` | 失败/降级原因枚举，见下表；成功时缺省 |
| `detail` | 脱敏后的人类可读说明（凭据字面量与 URL userinfo 已掩码为 `***`） |
| `checks` | 分步结果数组（`{step, state, reason?}`）；仅多步探测返回（当前仅 s3：`dial` → `s3`），单步类型缺省 |

`reason` 枚举（共 8 个）：

| 值 | 含义 |
|---|---|
| `unreachable` | 连接失败（网络不可达 / DNS 解析失败） |
| `auth_failed` | 认证失败：HTTP 后端返回 401/403、S3 凭据被拒（含桶权限拒绝）、kafka SASL 握手被拒 |
| `tls_error` | TLS 握手或证书校验失败 |
| `config_incomplete` | 配置节不完整：缺 url / endpoint+bucket / access_key+secret_key / brokers / topic，SASL 取值非法或凭据缺失，syslog url 协议非法，`use_audit_channel` 开启但 `log_shipper` 未配置等 |
| `server_error` | 对端返回错误状态码（非 2xx）：5xx、非 401/403 的其他 4xx（如 404），以及探测不跟随的 3xx 重定向 |
| `timeout` | 连接 / 解析 / 探测超时（单步 4 秒，总预算 8 秒） |
| `bucket_missing` | S3 桶不存在（或无权访问） |
| `unsupported` | 不支持的外发类型（六类之外） |

`degraded` 典型场景（可达但只读探测无法证明端到端投递）：

- syslog `udp://`：仅能证明目标地址可解析，UDP 无法确认对端在监听，投递为 best-effort；
- syslog `tls://` 且 `tls_skip_verify: true`：TLS 连接成功但证书未校验（与运行时传输行为一致）；
- kafka：Metadata 成功但 topic 尚不存在（依赖 broker 自动建题时属正常，PRODUCE 权限不验证）。

状态码：

- `200`：探测完成，结论看 `state`（含 `config_incomplete`——配置问题也是探测结论，不是请求错误）；
- `400`：`kind` 非法，或请求体 / `settings` 无法解析为对应配置节；
- `403`：角色不足（需 operator 及以上，文案 `权限不足：该操作需要操作员（operator）权限`）；
- `429`：全局单飞——同一时刻全实例仅允许一个探测在途，并发请求直接拒绝。

> 旧端点 `POST /api/logship/test` 兼容保留（见端点总览）：`kind` 被钉为 `audit`、请求体 `kind` 被忽略，`settings` 局部覆盖仍生效；建议改用本端点。

---

## 在线升级（admin）

控制台在线升级（系统设置 → 版本与升级）提供 4 个端点，均要求 admin 角色，由升级管道服务支撑。

### GET /api/upgrade/status

设置页快照：

```json
{
  "version": "v1.0.0-stable",
  "latest": {"version": "v1.0.1-stable", "update_available": true, "notes": "...", "assets_url": "..."},
  "running_task": null,
  "history": []
}
```

- `version`：当前运行版本；`latest`：最近一次成功检查的结果（`null` 表示尚无成功检查），API 层 60s TTL 缓存，检查失败不缓存（下次调用自动重试）；`?refresh=1` 跳过缓存强制在线检查；
- `running_task`：进行中的升级任务（空闲为 `null`）；`history`：历史任务。

### POST /api/upgrade/check

强制版本检查（绕过缓存并以新结果回填）。

- `200`：`{"version":"v1.0.0-stable","update_available":true,"notes":"...","assets_url":"..."}`
- `400`：当前版本号不可用（部署问题）
- `502`：版本源不可达/检查失败

### POST /api/upgrade/start

启动升级任务。请求体 `{"target_version": ""}`（空 = 最新版本；空 body 亦可）。同一时刻仅允许一个任务。

- `200`：`{"task_id": "..."}`
- `409`：`{"error":"已有升级任务进行中","task":{...}}`（附进行中的任务，客户端可直接转为轮询该任务）
- `429`：上一次失败后的冷却窗口内拒绝重试
- `400`：目标版本非法或不在发布列表中

### GET /api/upgrade/task?id=

轮询单个任务（缺 `id` 返回 400，未知 `id` 返回 404），响应为任务对象。

任务状态机：`detecting → downloading → verifying → replacing → restarting → success`，任一阶段失败即 `failed` 并进入冷却窗口；任务级 `success` 表示「服务重启已提交」，升级完成后服务自动重启，升级前自动在安装目录留滚动备份（见 [deploy/README.md](../deploy/README.md) 6.3）。

### 模块未接线（501）

当前部署形态不支持在线升级（static 模式或构建时未含该模块）时，以上端点统一返回 `501` 并附原因，而非易误导的 404/500。

---

## POST /api/login

```json
{"username": "admin", "password": "<密码>", "totp": "123456"}
```

- `username`：缺省时视为 `admin`。
- `totp`：账号启用了逐用户 MFA，或部署设置了全局 `KMWAF_ADMIN_TOTP` 时必填。
- `200`：`{"ok":true,"role":"admin","username":"admin","totp":false}` + `Set-Cookie: km_session=...`
- `401`：`{"error":"invalid credentials"}`（密码错误 / 账号禁用 / 未知用户名）或 `{"error":"totp_required"}`（密码正确但缺动态码或动态码错误，同样计入防爆破计数）
- `429`：`{"error":"登录失败次数过多，请稍后再试"}` + `Retry-After`（同一来源 IP 15 分钟内失败达 10 次后触发滑动窗口锁定，成功登录即清零；Basic 认证失败共用同一计数器）
- `400`：`{"error":"控制台认证未启用，无法通过账号登录"}`（仅当认证模块未装配时；未设置 `ADMIN_HASH` 不会走到这里——认证会自动武装）

## GET /api/status

```json
{"version":"v1.0.0-stable","revision":3,"sites":2,"time":"2026-09-15T08:00:00Z"}
```

配置加载期出现过归一化/降级（含首装种子与回滚成功后的加载）时，响应额外携带 `load_notes` 字符串数组：逐条说明对当前生效配置做了什么（如外发节旧形态迁移、降级关闭及原始校验错误）。字段**仅在非空时出现**：加载干净时无此键，下一次成功发布后清空；库内修订保持原样不回写。控制台顶部横幅与「日志外发」「AI 会话审计」两个设置页签展示同一内容，见 [docs/CONFIG.md](CONFIG.md) 存量旧形态的加载期归一化。

响应另可携带 `runtime_alerts` 数组：本地访问日志留存（`access_log_record`）的运行期异常，**仅在存在活跃告警时出现**（健康时无此键）。每项形如 `{"code":"queue_full","level":"warning","message":"…","since":"2026-10-13T02:00:00Z"}`：`message` 为中文运维话术，`since` 为该异常首次置起的时刻（RFC3339）；`level` 取 `warning` 或 `critical`。**与 `load_notes` 的区别**：`load_notes` 是配置加载事实，下一次成功发布即清空；`runtime_alerts` 是运行期异常，条件消失才消失（不因发布配置而清空）。四类告警：

| code | level | 含义与解除条件 |
|---|---|---|
| `queue_full` | warning | 本地写入队列已满、入站记录被丢弃（背压）；队列排空至半容量以下后解除 |
| `disk_low_paused` | critical | 数据盘剩余空间低于安全水位 `max(1.2×max_disk_mb, 512MB)`，先补一轮淘汰、仍低则暂停落盘（入站计入 `record.dropped`）；余量恢复后自动恢复记录并解除 |
| `capacity_evicted` | warning | 库文件超出容量上限，已按最旧优先淘汰；容量回到上限内后解除 |
| `db_write_failed` | critical | 本地库批量写入失败（磁盘/数据库异常），失败条目计入丢弃；**保持到下一次批量写入完全成功**才解除，部分行失败的批次不会解除 |

其余细节（触发阈值、磁盘保护语义）见 [docs/CONFIG.md](CONFIG.md) 的 AccessLogRecordSettings 维护语义。

## GET /api/config

```json
{"revision": 3, "config": { /* 完整 Config JSON，见 docs/CONFIG.md */ }}
```

## POST /api/config/publish

请求体（config 为完整配置对象，发布前服务端执行 `Config.Validate`）：

```json
{"note": "开通站点 b.local", "config": { ... }}
```

- `200`：`{"revision": 4, "apply": {"revision": 4, "status": "applied", "error": ""}}` —— 校验通过、落库、热生效（原子替换，失败保留旧配置）；`apply.status`：`applied`（数据面已加载）/ `failed`（数据面加载失败，旧配置继续生效，error 携带原因）/ `pending`（无数据面消费者或超时）
- `400`：`{"error":"config: sites[1].upstream.nodes is empty"}` —— 校验失败不落库（含微引擎上限：per-site 分类 disable 规则 ≤4、全局变体 ≤64）

发布失败不影响线上流量（fail-static）。

## POST /api/config/site/publish

单站点写入（operator+）：只提交一个站点定义，服务端在活跃配置上做 upsert，不必回传整份配置。自动化/资产同步用它开通或改动单个站点最省事。

```json
{
  "domain": "app.example.com",
  "note": "资产同步：开通 app.example.com",
  "comment": "归属：数据平台组 / 负责人：张三",
  "site": {"domains": ["app.example.com"], "upstream": {"nodes": [{"address": "10.0.0.12:8080"}]}}
}
```

- `domain`：站点定位键（大小写不敏感）；缺省时取 `site.domains[0]`；匹配不到任何现有站点则追加为新站点。
- `comment`：**站点备注**（如归属部门、负责人、工单号），最多 500 字符。语义：
  - 传字符串（含空串 `""`）：直接覆盖备注（空串即清空）；
  - **整个字段不出现**：保留该域名现有站点的备注不变——自动化重复写入同一个站点不会把管理员写的备注冲掉；
  - 也接受把备注写在 `site.comment` 里（兼容整份站点对象的客户端），优先级：请求级 `comment` > 非空 `site.comment` > 现有备注。
  - 500 字符上限只约束**本次提交的值**；继承自存量配置的超长备注不会被拒（避免历史数据让站点无法再编辑/启停）。全量发布 `POST /api/config/publish` 同样在写入时校验该上限。
  - 并发发布采用 last-writer-wins：两个请求同时改同一站点时后提交的备注生效。
- `200`：`{"revision": 5, "domain": "app.example.com", "apply": {"revision": 5, "status": "applied", "error": ""}}`
- `409`：`{"error":"no_changes"}` —— 提交内容与活跃配置等价（含备注未变），不创建新版本
- `400`：校验失败（备注超长报 `config: site.comment 最多 500 个字符（当前 N）`）

## GET /api/revisions

```json
[
  {"id":4,"created_at":"2026-09-15T08:01:00Z","author":"admin","note":"rollback"},
  {"id":3,"created_at":"2026-09-15T08:00:10Z","author":"admin","note":"smoke-v3"}
]
```

## POST /api/revisions/{id}/rollback

将历史 revision 内容重新发布为新 revision（版本库只追加、不可改写）。

- `200`：`{"revision":5,"rolled_back_to":3}`
- `400`：revision 不存在

## GET /api/logs?limit=N

事件对象（`capture_requests` 开启时含脱敏后的 `headers` 与 `body` 快样）：

```json
{
  "ts": "2026-09-15T08:00:05.123+08:00",
  "trace_id": "641d2596a6195a8b",
  "site": "a.local",
  "client_ip": "1.2.3.4",
  "geo_country": "CN",
  "method": "GET",
  "path": "/?id=1' OR '1'='1",
  "status": 403,
  "user_agent": "curl/8",
  "action": "blocked",
  "rule": "semantic/sqli",
  "reason": "SQL injection semantics detected (libinjection s&sos)",
  "body_bytes": 0,
  "headers": {"Authorization": "***", "X-Custom": "v"},
  "body": ""
}
```

`action` 取值：`blocked` / `challenged` / `monitor` / `redirected`。
`geo_country` 为攻击来源的 ISO 3166-1 alpha-2 国家码（写入时与地理封锁判定**同源**解析；私网/回环/链路本地/CGNAT 来源、公网无记录、解析失败或库缺失时为空串，且空串不序列化）。控制台在日志列表/详情「来源地区」及总览等处将两字母码显示为简体中文（HTML 报表保留 DB-IP 英文署名，许可要求）。**口径说明**：站点配置自定义 `geo.db_path` 时，该站点请求的 `geo_country` 与 geo 封禁判定使用同一站点 geo 引擎、同一份库；无自定义库（或未启用 geo 的站点/静态模式）时回落内置 DB-IP 国家库。多站点各配不同自定义库时，总览地理统计（`GET /api/stats/geo`）仍按其既有实现取第一个 geo-enabled 站点库做全局单库聚合（不逐站点分库）。
`headers` 中 `Authorization`、`Cookie`、`Set-Cookie`、`Proxy-Authorization`、`X-Api-Key`
固定脱敏为 `***`。

## GET /api/access_logs

全量访问日志的实时内存尾（外发管道常驻环，跨重建存活；不依赖本地留存开关）：

```json
{
  "enabled": true,
  "count": 4096,
  "items": [ { "ts": "...", "site": "a.local", "client_ip": "...", "method": "GET", "path": "/", "status": 200, "outcome": "forwarded" } ],
  "record": {"enabled": false, "mode": "off", "retention_days": 7, "max_disk_mb": 1024, "size_bytes": 0, "evicted": 0, "rows": 0, "oldest_ts": "", "dropped": 0, "residual": false}
}
```

- 查询参数：`limit`（默认 200，上限 2000）、`site`（子串）、`q`（关键字）、`outcome`（精确）；
- `record`：本地留存状态对象（`access_log_record`，见 [docs/CONFIG.md](CONFIG.md)），与实时尾相互独立——`record.enabled` 只描述本地库，不描述外发/实时尾；`rows`/`oldest_ts` 上报已留存数据（关闭记录后仍能看到留存状态，停止记录期间不自动清理（重新开启记录后恢复按期清理））；`residual` 为 `true` 表示「已停止记录但本地仍有可检索残留」（`enabled=false` 且库内仍有可查询数据，供控制台区分提示）；`dropped` 为入库前丢弃累计，队列溢出、数据盘低水位暂停、关闭竞态与批量写库失败均计入（不只队列溢出）；`size_bytes` 为 db+wal+shm 合计；`evicted` 为磁盘上限触发的最旧优先淘汰累计条数。

## GET /api/access_logs/history

本地访问日志历史检索（`access_log_record` 落库数据；RBAC 与 `GET /api/access_logs` 相同，任意已认证控制台身份可用）：

| 参数 | 说明 |
|---|---|
| `page` / `page_size` | 分页（默认 1 / 100，单页上限 1000；兼容旧参数 `limit` 同义于 `page_size`） |
| `site` | 站点域名子串匹配 |
| `outcome` | 精确匹配（forwarded / blocked / challenged / monitor_forwarded / redirected） |
| `ip` | 客户端 IP 前缀匹配 |
| `q` | 关键字（path / user_agent / rule / client_ip / trace_id） |
| `since` / `until` | 时间窗，RFC3339；格式非法返回 `400`（不静默忽略，避免被误当成全库扫描） |

返回 `{"items": [...], "total": N, "page": N, "page_size": N, "record": {...}}`，条目为入库前的同一套脱敏与截断结果（query 敏感参数掩码 `***`、path 凭据段掩 `<masked>`、长度上限见 CONFIG.md），`record` 语义同上一节。条目字段 `body_skip` 标识**请求体未经完整检测**的超限放行流量：`bypass`（完全未检测，仅头部阶段）/ `prefix`（仅深检了前 `body_limit_bytes`）——空值 = 完整检测（或未走到缓冲阶段）；控制台访问日志详情抽屉以「请求体检测」行展示，配合 `kingmoat_body_bypass_total` 指标审计「哪些流量跳过了检测」。记录开启时查询走本地库读池；**未开启记录（或句柄已摘除）时回落到磁盘只读查询**（`mode=ro` + `query_only`，回落永不写入），查询参数与响应形态与开启态一致——已留存的残留数据在关闭期间仍可检索，此时 `record.enabled: false`、`record.residual: true`。库文件缺失/损坏时降级为空页（仍返回 200，非错误，可自由轮询）。

## POST /api/access_logs/purge

**破坏性操作，仅 admin**（operator/auditor 返回 `403`）：删除本地访问日志库全部已落库记录并回收文件空间（DELETE + VACUUM + WAL checkpoint truncate），返回 `{"purged": N, "record": {...}}`（行已删除但空间回收失败时仍返回 200，额外携带 `warning` 字段说明）；清空动作落一条控制台变更审计。未开启记录/库不存在时安全返回 `purged: 0`。关闭记录（`mode:"off"`）不会删除已留存数据——关闭期间仍可在「本地历史」只读检索，停止记录期间不自动清理（重新开启记录后恢复按期清理），需要立即释放空间才用本端点。

## GET /api/stats

```json
{"revision":3,"sites":1,"blocked_today":12,"challenged_today":3,"monitor_today":0}
```

## GET /api/certificates

```json
[
  {
    "site": "a.local",
    "source": "file",
    "domains": ["a.local"],
    "subject": "a.local",
    "issuer": "R3",
    "not_before": "2026-09-01T00:00:00Z",
    "not_after": "2026-11-30T00:00:00Z"
  },
  {"site":"b.local","source":"acme","domains":["b.local"],"subject":"managed by ACME (auto-renew)"}
]
```

## GET /metrics

Prometheus 文本格式。核心指标：

| 指标 | 标签 | 说明 |
|---|---|---|
| `kingmoat_requests_total` | site, outcome | outcome: forwarded / blocked / challenged / monitor_forwarded / redirected |
| `kingmoat_stage_hits_total` | stage | 各检测阶段命中次数（acl/geo/captcha/bot/ratelimit/semantic/coraza/auth…） |
| `kingmoat_upstream_errors_total` | site | 上游请求失败数 |
| `kingmoat_config_reloads_total` | outcome | ok / failed |
| `kingmoat_audit_dropped_total` | — | 审计队列溢出丢弃数 |
| `kingmoat_accesslog_dropped_total` | — | 访问日志外发队列溢出丢弃数 |
| `kingmoat_accesslog_local_dropped_total` | — | 访问日志本地留存入库前丢弃累计（`access_log_record`；队列溢出、数据盘低水位暂停、写库失败等均计入） |
| `kingmoat_accesslog_local_queue_depth` | — | 访问日志本地留存待入库积压条数（`access_log_record`） |
| `kingmoat_body_bypass_total` | site, policy | 请求体未经完整检测的超限放行数（policy=bypass 完全未检测 / prefix 仅深检前缀），与访问日志 `body_skip` 同源 |
| `kingmoat_body_guard_rejected_total` | site | 因请求体检测聚合内存预算（`body_buffer_budget_mb`）耗尽而被拒（503 `proxy/body_buffer_exhausted`）的请求数 |
| `kingmoat_body_idle_aborts_total` | site | 请求体读无进展超时（60s）而被中断（408 `proxy/body_idle`）的请求数 |

---

## 数据面站点端点（非管理 API）

| 路径 | 说明 |
|---|---|
| `/.well-known/acme-challenge/*` | ACME HTTP-01 挑战应答（启用 ACME 时挂载；挑战路径先于数据面命中 ACME 引擎，生产/staging 双槽按 token 归属应答，其余路径回落数据面；重定向豁免。TLS-ALPN-01 挑战不走 HTTP：由 443 监听常驻协商 ALPN `acme-tls/1` 后直通引擎应答） |
| `/.well-known/km-captcha/verify` | 滑块验证校验端点（GET，参数 token/x/back；成功签发 `km_captcha` Cookie） |
