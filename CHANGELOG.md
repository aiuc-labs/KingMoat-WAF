# 更新日志

## v1.0.0-stable（2026-10-29）· 首个正式版

KingMoat WAF 社区版首次发布。单二进制交付，内置 Coraza + OWASP CRS 与 Vue 3 控制台，
默认 SQLite 存储，开箱即可承担站点反向代理与签名/语义/行为三层防护。

### 交付形态

- **all-in-one（推荐）**：数据面与控制台同一进程，共享 SQLite，单文件部署
- **静态配置文件**：纯文件配置，无控制台，适合不可变基础设施
- 一键安装脚本（systemd）/ docker-compose / Windows 服务/手工运行

### 核心能力

**不限量**

- 站点数与并发不设限（无许可证配额）；多站点 Host 路由、加权轮询、主动健康检查 + 被动熔断、SNI 多证书 TLS、WebSocket 透传

**权威上游规则**

- Coraza v3 + OWASP CRS 4.x 直接嵌入二进制（无外部规则文件，离线可用），请求体全量缓冲检测
- libinjection SQLi/XSS 语义层，独立于 CRS 的第二道防线
- CRS 阈值/异常评分、黑白名单、IP 组订阅、微引擎自定义规则均可在控制台图形化配置；攻击日志一键加白自动生成放行规则（幂等，防重复）

**数据面防护**

- CC 限流（固定窗口，deny/throttle）、滑块验证码（SVG + HMAC 通行 Cookie）、轻量 JS 质询
- IP/CIDR 黑白名单 + 订阅式 IP 组、GeoIP 国家黑白名单（内置 DB-IP 国家库开箱即用，可选自备 mmdb）
- 整站 HTTP Basic（argon2id）、HTTPS 308 跳转、真实客户端 IP 识别（trusted proxies）
- 响应过滤（手机号/身份证/密钥预设 + 自定义正则）、动态防护（HTML 响应 AES-GCM 加密 + WebCrypto 还原）
- 双模式：`intercept` 命中即拦 / `monitor` 只记录不拦截；上游故障 502 友好页
- 请求体两态策略：拒绝（413）/ 流式透传 / 深检前缀（大文件上传场景），超限放行流量带 `body_skip` 审计标记
- 审计日志：SQLite 按天归档 + 内存环实时查询，可选请求快照（脱敏）；攻击事件标注来源地区（中文显示）
- 访问日志本地留存（默认关）：落本地 SQLite，按天保留 + 磁盘上限自动淘汰，入库前敏感参数掩码

**AI 能力（只读 + 审计）**

- 内嵌 LLM 安全分析师：SSE 流式对话、日志一键问 AI、定时日报与突增主动报告；OpenAI 兼容多模板 + 自定义接入；出站动态脱敏（返回自动还原）；硬编码只读工具表，无写路径；可选 MCP 端点
- AI 会话审计：识别经 WAF 的 LLM API 调用（OpenAI / Anthropic / Gemini 及国内外主流兼容端点），非流式 tee + SSE 逐行聚合，命中才捕获；内置 sk-/Bearer/AKIA/口令字段脱敏；控制台检索全文，可外发至 ClickHouse / Elasticsearch / Loki / S3 / syslog / Kafka

**风险引擎与资产梳理**

- R1–R7 observe-only 风险引擎（敏感暴露 / 未授权线索 / 登录爆破 / 影子 API / 僵尸 API / 管理面暴露 / 明文敏感参数），周期自动扫描 + 手动扫描，新发现 webhook 通知
- API 资产梳理：响应后观测旁路学习（路径归一化 + 标签 + 候选降噪，独立 SQLite 库，默认关）
- BOT 爬虫识别：UA 三分类 + 客户端指纹 + 频率信号，与 JS 挑战联动

**控制面与可运维性**

- SQLite 版本化配置库：revision 追加不可改写、一键回滚；热更新原子生效，发布失败保留旧配置
- Web 控制台（Vue 3）：站点图形化配置、日志行内详情抽屉、证书、API 安全、AI 会话审计、AI 助手；RBAC 三级 + MFA + API Key；构建产物 embed，部署仍单文件
- 证书管理：站点 PEM + Let's Encrypt 自动申请续签（ACME，TLS-ALPN-01 + HTTP-01），staging 与生产缓存隔离
- 告警与外发：webhook 事件推送；ClickHouse / Elasticsearch / Loki / S3 / syslog / Kafka 日志外发，通道可复用并支持一键连通性测试
- Prometheus `/metrics`、REST API（核心端点见 `docs/API.md`，完整清单由控制台 `/openapi.json` 提供）

### 安全基线

- **首次启动管理员口令随机生成**：未设置 `KMWAF_ADMIN_HASH` 时创建内置账号 `kmadmin`，初始口令由 `KMWAF_BOOTSTRAP_PASSWORD` 指定或随机生成并写入数据目录 `initial-admin-password.txt`（0600），首次登录强制改密，二进制与文档均不含固定口令
- **凭据只写不回显**：`GET /api/config` 对外发渠道凭据统一返回占位符，保存时占位/空值即保留原值
- **SSRF 防护**：出站抓取（URL 提取、RSS、AI 文档）拦截私网、回环、CGNAT、云厂商 metadata 与基准测试网段，限制重定向跳数与响应体
- **客户端指纹**：仅取 `Accept*` / `Sec-Fetch-*` / `Sec-CH-UA-Platform` 的值做摘要，攻击者无法通过添加自定义头更换限速桶
- **在线升级**：安装目录可写 / systemctl / root 三条件探测、同目录原子替换 + 滚动备份 + 启动失败自愈回滚；支持对 `checksums.txt` 的 Ed25519 分离签名验签（内嵌公钥时 fail-closed，本版未内嵌）
- **构建与供应链**：统一 `no_fs_access` 构建标签（coraza 不再探测本地文件系统）；第三方许可证门禁按 linux/windows 双平台枚举（66 模块 0 违规）；每包附 `SBOM.txt`；控制台产物与源码偏离即拒绝打包

### 已知限制

- 限流 / 验证码 / 会话状态为单机内存态，多实例部署需自行前置共享限流层
- 访问日志本地留存默认关闭，按天保留策略仅在开启记录期间生效
- 多节点集中管理、界面品牌个性化不在本版范围
- 匿名安装统计默认关闭，仅上报版本/平台/架构等白名单字段，支持 `DO_NOT_TRACK`

### 许可

Mulan PSL v2（木兰宽松许可证，第 2 版），详见 `LICENSE`。