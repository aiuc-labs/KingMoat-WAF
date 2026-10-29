<template>
  <div>
    <div class="km-toolbar km-sticky">
      <el-button type="primary" :disabled="!can('operator')" @click="openEdit(-1)"><el-icon><Plus /></el-icon>&nbsp;添加站点</el-button>
      <el-button :disabled="!can('operator')" @click="publishForm" :loading="publishing">发布配置（热生效）</el-button>
      <el-button :disabled="!can('operator')" @click="rollbackPrev">↩ 回滚上一版本</el-button>
      <div class="grow"></div>
      <el-tag v-if="!dirty" effect="plain" type="success" class="km-tag">● revision #{{ rev }} 已发布 · 热生效</el-tag>
      <el-tag v-else effect="plain" type="warning" class="km-tag">有未发布变更（草稿）</el-tag>
      <div class="km-seg">
        <span class="seg-item" :class="{ on: mode === 'form' }" @click="mode = 'form'">图形化</span>
        <span class="seg-item" :class="{ on: mode === 'json' }" @click="mode = 'json'">JSON（高级）</span>
      </div>
    </div>

    <!-- 图形化：站点表格（配置项全部在「编辑」抽屉内维护） -->
    <div v-if="mode === 'form'">
      <el-card shadow="never" :body-style="{ padding: 0 }">
        <div class="km-card-head">
          <span class="km-card-title">站点列表（{{ form.sites.length }}）</span>
          <div class="extra" style="display:flex;align-items:center;gap:10px">
            <el-input v-model="siteFilter" size="small" style="width:220px" placeholder="筛选：域名 / 名称 / 备注 / 源站 IP" clearable />
            <el-select v-model="healthFilter" size="small" style="width:150px" placeholder="源站健康状态" clearable>
              <el-option label="健康" value="healthy" />
              <el-option label="降级" value="degraded" />
              <el-option label="故障" value="down" />
              <el-option label="无数据" value="none" />
            </el-select>
            <el-select v-model="modeFilter" size="small" style="width:140px" placeholder="防护状态" clearable>
              <el-option label="拦截" value="intercept" />
              <el-option label="观察" value="monitor" />
              <el-option label="禁用" value="disabled" />
            </el-select>
            <span class="km-dim" style="font-size:12px">健康状态按上游探测快照判定；无数据时退回今日流量</span>
          </div>
        </div>
        <el-table :data="pagedSites" size="small" style="width:100%" border @sort-change="onSiteSortChange">
          <el-table-column label="站点名称" prop="name" min-width="180" resizable sortable="custom">
            <template #default="{ row }">
              <span style="font-weight:600">{{ row.s.name || '(未命名站点)' }}</span>
            </template>
          </el-table-column>
          <el-table-column label="站点域名" prop="domain" min-width="220" resizable sortable="custom">
            <template #default="{ row }">
              <div class="km-mono" style="font-size:12px;line-height:1.6;word-break:break-all">{{ (row.s.domains || []).join('、') || '-' }}</div>
            </template>
          </el-table-column>
          <el-table-column label="健康状态" prop="health" min-width="120" resizable sortable="custom">
            <template #default="{ row }">
              <el-tooltip placement="top" effect="dark" :show-after="150">
                <template #content>
                  <div style="white-space:pre-line;line-height:1.7;max-width:520px">{{ healthTip(row) }}</div>
                </template>
                <el-tag size="small" :type="healthOf(row).type" effect="plain" class="km-tag">{{ healthOf(row).text }}</el-tag>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="防护状态" prop="mode" min-width="110" resizable sortable="custom">
            <template #default="{ row }">
              <el-tag size="small" :type="modeTag(row.s).type" effect="dark" class="km-tag">{{ modeTag(row.s).text }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="上游" min-width="200" show-overflow-tooltip resizable>
            <template #default="{ row }">
              <span class="km-mono" style="font-size:12px">{{ (row.s.upstream?.nodes || [])[0]?.address || '-' }}</span>
              <span v-if="(row.s.upstream?.nodes || []).length > 1" class="km-dim" style="font-size:11px"> +{{ (row.s.upstream?.nodes || []).length - 1 }}</span>
            </template>
          </el-table-column>
          <el-table-column label="防护能力" min-width="340" resizable>
            <template #default="{ row }">
              <span style="display:inline-flex;flex-wrap:wrap;gap:6px">
                <el-tag v-if="wafOn(row.s)" size="small" effect="plain" class="km-tag">WAF</el-tag>
                <el-tag v-if="sec(row.s).semantic?.enabled" size="small" effect="plain" class="km-tag">语义</el-tag>
                <el-tag v-if="sec(row.s).captcha?.enabled" size="small" effect="plain" class="km-tag">滑块</el-tag>
                <el-tag v-if="sec(row.s).ratelimit" size="small" effect="plain" class="km-tag">CC</el-tag>
                <el-tag v-if="sec(row.s).geo?.enabled" size="small" effect="plain" class="km-tag">GeoIP</el-tag>
                <el-tag v-if="sec(row.s).auth" size="small" effect="plain" class="km-tag">Basic</el-tag>
                <el-tag v-if="sec(row.s).acl?.blacklist?.length || sec(row.s).acl?.whitelist?.length" size="small" effect="plain" class="km-tag">ACL</el-tag>
                <el-tag v-if="sec(row.s).dynamic?.enabled" size="small" effect="plain" class="km-tag">动态防护</el-tag>
                <el-tag v-if="sec(row.s).resp_filter?.enabled" size="small" effect="plain" class="km-tag">脱敏</el-tag>
                <el-tag v-if="row.s.redirect_to_https" size="small" effect="plain" class="km-tag">HTTPS 跳转</el-tag>
                <el-tag v-if="row.s.acme" size="small" effect="plain" class="km-tag">ACME</el-tag>
                <el-tag v-if="row.s.health?.enabled" size="small" effect="plain" class="km-tag">健康检查</el-tag>
                <el-tag v-if="(row.s.waf?.body_stream_paths || []).length" size="small" type="success" effect="plain" class="km-tag">深检前缀 ×{{ (row.s.waf?.body_stream_paths || []).length }}</el-tag>
              </span>
            </template>
          </el-table-column>
          <el-table-column label="今日请求" prop="requests" width="120" align="right" resizable sortable="custom">
            <template #default="{ row }">{{ (row.st.requests || 0).toLocaleString() }}</template>
          </el-table-column>
          <el-table-column label="攻击" prop="attacks" width="90" align="right" resizable sortable="custom">
            <template #default="{ row }">
              <span :style="row.st.attacks > 0 ? 'color:var(--km-red);font-weight:700' : 'color:var(--km-txt-3)'">{{ (row.st.attacks || 0).toLocaleString() }}</span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="200" resizable>
            <template #default="{ row }">
              <el-button link type="primary" size="small" :disabled="!can('operator')" @click="openEdit(row.i)">编辑</el-button>
              <el-tooltip :content="row.s.disabled ? '启用站点（立即热生效）' : '禁用站点（立即热生效）'" placement="top">
                <el-switch size="small" :model-value="!row.s.disabled" :disabled="!can('operator') || toggling === row.i"
                           @change="() => toggleSite(row.i)" style="margin:0 8px" />
              </el-tooltip>
              <el-button link type="danger" size="small" :disabled="!can('operator')" @click="removeSite(row.i)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <el-empty v-if="!form.sites.length" description="暂无站点，点击左上角新增" :image-size="70" />
        <el-empty v-else-if="!filteredSites.length" description="无匹配站点" :image-size="70" />
        <div v-if="filteredSites.length > sitePageSize" style="display:flex;justify-content:flex-end;gap:10px;align-items:center;padding:10px 16px 14px">
          <span class="km-dim" style="font-size:12px">每页</span>
          <el-select v-model="sitePageSize" size="small" style="width:84px"
                     @change="() => { const max = Math.max(1, Math.ceil(filteredSites.length / sitePageSize)); if (sitePage > max) sitePage = max }">
            <el-option v-for="n in [10, 20, 50, 100]" :key="n" :label="n + ' 条'" :value="n" />
          </el-select>
          <el-pagination layout="prev, pager, next" small background :total="filteredSites.length"
                         :page-size="sitePageSize" :current-page="sitePage"
                         @current-change="p => sitePage = p" />
        </div>
      </el-card>
    </div>

    <!-- JSON 模式 -->
    <el-card v-else shadow="never">
      <div class="km-title">配置 JSON（直接编辑，发布前仍会服务端校验）</div>
      <el-input v-model="jsonText" type="textarea" :rows="20" class="km-mono" spellcheck="false" />
    </el-card>

    <el-card shadow="never" style="margin-top:16px">
      <div class="km-title">版本历史</div>
      <el-table :data="pagedRevs" size="small">
        <el-table-column prop="id" label="版本" width="70" />
        <el-table-column label="时间（本地）" width="180">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="author" label="作者" width="110" />
        <el-table-column prop="note" label="备注" show-overflow-tooltip />
        <el-table-column width="140">
          <template #default="{ row }">
            <el-button v-if="can('operator')" link type="primary" @click="rollbackTo(row.id)">回滚到此版本</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="revs.length > revPageSize" style="display:flex;justify-content:flex-end;gap:10px;align-items:center;padding:10px 12px">
        <span class="km-dim" style="font-size:12px">每页</span>
        <el-select v-model="revPageSize" size="small" style="width:84px"
                   @change="() => { const max = Math.max(1, Math.ceil(revs.length / revPageSize)); if (revPage > max) revPage = max }">
          <el-option v-for="n in [10, 20, 50, 100]" :key="n" :label="n + ' 条'" :value="n" />
        </el-select>
        <el-pagination layout="prev, pager, next" small background :total="revs.length"
                       :page-size="revPageSize" :current-page="revPage"
                       @current-change="p => revPage = p" />
      </div>
    </el-card>

    <!-- 站点编辑抽屉 -->
    <el-drawer v-model="drawer" :title="editIndex < 0 ? '新增站点' : '编辑站点'" size="780px" destroy-on-close>
      <el-form label-width="120px" label-position="left">
        <div class="km-title">基础</div>
        <el-form-item label="协议">
          <el-radio-group v-model="edit.protocol">
            <el-radio-button value="http">HTTP</el-radio-button>
            <el-radio-button value="https">HTTPS</el-radio-button>
          </el-radio-group>
          <span class="km-dim" style="margin-left:10px;font-size:12px">HTTPS 在下方选择证书来源（ACME 自动 / PEM / 已上传）</span>
        </el-form-item>
        <el-form-item label="站点名称">
          <el-input v-model="edit.name" placeholder="可选，便于识别的自定义名称" maxlength="100" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="edit.comment" type="textarea" :rows="2" maxlength="500" show-word-limit placeholder="可选，记录用途、负责人等" />
        </el-form-item>
        <el-form-item label="域名">
          <div style="width:100%">
            <div v-for="(d, di) in edit.domainRows" :key="di" style="display:flex;gap:8px;margin-bottom:6px">
              <input v-model="edit.domainRows[di]" placeholder="example.com" class="km-native-input km-mono" />
              <el-button link type="danger" @click="edit.domainRows.splice(di, 1)"><el-icon><Delete /></el-icon></el-button>
            </div>
            <el-button size="small" @click="edit.domainRows.push('')"><el-icon><Plus /></el-icon>&nbsp;新增域名</el-button>
            <div class="km-dim" style="font-size:12px;margin-top:4px">支持逗号（中/英文）分隔批量录入，自动拆分去重</div>
          </div>
        </el-form-item>
        <el-form-item label="上游服务器">
          <div style="width:100%">
            <div v-for="(u, ui) in edit.upstreamRows" :key="ui" style="display:flex;gap:8px;margin-bottom:6px;align-items:center">
              <el-select v-model="u.proto" style="width:96px" size="small" @change="onUpstreamProtoChange(u)">
                <el-option label="HTTP" value="http" />
                <el-option label="HTTPS" value="https" />
              </el-select>
              <input v-model="u.ip" placeholder="IP 或主机名" class="km-native-input km-mono" style="flex:1" />
              <el-input-number v-model="u.port" :min="1" :max="65535" :controls="false" placeholder="端口" size="small" style="width:84px" />
              <el-input-number v-model="u.weight" :min="1" :max="100" size="small" style="width:88px" />
              <span class="km-dim" style="font-size:12px">权重</span>
              <el-button link type="danger" @click="edit.upstreamRows.splice(ui, 1)"><el-icon><Delete /></el-icon></el-button>
            </div>
            <el-button size="small" @click="edit.upstreamRows.push({ proto: 'http', ip: '', port: 80, weight: 1 })"><el-icon><Plus /></el-icon>&nbsp;新增上游</el-button>
          </div>
        </el-form-item>
        <el-form-item label="负载算法">
          <el-radio-group v-model="edit.algorithm">
            <el-radio-button value="wrr">加权轮询</el-radio-button>
            <el-radio-button value="least_conn">最少连接</el-radio-button>
            <el-radio-button value="source_ip">源 IP 会话保持</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="监听端口">
          <span class="km-dim" style="font-size:12px">站点不再单独配置端口：统一使用系统设置页「数据面监听」的监听地址（默认 HTTP 80 / HTTPS 443），按域名自动路由</span>
        </el-form-item>
        <el-form-item label="防护状态">
          <el-radio-group v-model="edit.modeOrDisabled">
            <el-radio-button value="intercept">拦截</el-radio-button>
            <el-radio-button value="monitor">观察（只记录）</el-radio-button>
            <el-radio-button value="disabled">禁用（不路由）</el-radio-button>
          </el-radio-group>
          <div class="km-dim" style="font-size:12px;margin-top:4px;width:100%">禁用等价于站点列表的启停开关：数据面不再路由该站点</div>
        </el-form-item>
        <template v-if="edit.protocol === 'https'">
          <el-form-item label="HTTPS 跳转">
            <el-switch v-model="edit.redirect_to_https" :disabled="edit.tlsSource === 'none'" />
            <span class="km-dim" style="margin-left:10px;font-size:12px">HTTP 访问 308 跳转 HTTPS（需 TLS/ACME）</span>
          </el-form-item>
          <el-form-item label="HTTP/2">
            <el-switch v-model="edit.http2Enabled" />
            <span class="km-dim" style="margin-left:10px;font-size:12px">默认开启；关闭后该站点 TLS 协商仅提供 HTTP/1.1</span>
          </el-form-item>
          <el-form-item label="SNI 转发">
            <el-switch v-model="edit.sniForward" />
            <span class="km-dim" style="margin-left:10px;font-size:12px">上游为 HTTPS 时，把客户端原始 SNI 转发给后端（后端证书需匹配该域名）；与固定回源 SNI 互斥</span>
          </el-form-item>
          <el-form-item v-if="upstreamHasHTTPS" label="固定回源 SNI">
            <el-input v-model="edit.sniHost" placeholder="backend.example.com" style="width:320px" clearable />
            <div class="km-dim" style="font-size:12px;margin-top:4px;width:100%">回源 TLS 握手固定使用该域名作 SNI（连接复用场景安全）；与 SNI 转发互斥，二者同设保存会被拒绝</div>
            <div v-if="edit.sniHost && edit.sniForward" style="font-size:12px;margin-top:4px;width:100%;color:#e6a23c">已同时开启 SNI 转发：请关闭其一，否则无法保存</div>
          </el-form-item>

          <div class="km-title" style="margin-top:18px">TLS / 证书</div>
        <el-form-item label="证书来源">
          <el-radio-group v-model="edit.tlsSource" @change="onTlsSource">
            <el-radio-button value="none">无</el-radio-button>
            <el-radio-button value="file">PEM 文件</el-radio-button>
            <el-radio-button value="acme">ACME 自动</el-radio-button>
            <el-radio-button value="uploaded">已上传证书</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <template v-if="edit.tlsSource === 'file'">
          <el-form-item label="证书路径"><el-input v-model="edit.tls_cert" placeholder="/etc/kingmoat/certs/x.pem" /></el-form-item>
          <el-form-item label="私钥路径"><el-input v-model="edit.tls_key" placeholder="/etc/kingmoat/certs/x.key" /></el-form-item>
        </template>
        <el-form-item v-if="edit.tlsSource === 'uploaded'" label="选择证书">
          <el-select v-model="edit.uploadedName" style="width:100%">
            <el-option v-for="u in uploads" :key="u.name" :value="u.name"
                       :label="u.name + '（' + (u.subject || '?') + '，至 ' + fmtShort(u.not_after) + '）'" />
          </el-select>
          <div class="km-dim" style="font-size:12px;margin-top:4px">证书在「证书管理」页上传</div>
        </el-form-item>
        <el-form-item v-if="edit.tlsSource === 'acme'" label="ACME 说明">
          <span class="km-dim" style="font-size:12px">开启后该域名自动申请 Let's Encrypt 证书并续签；站点未单独填邮箱时使用顶部工具栏的 ACME 联系邮箱，状态见证书管理页</span>
        </el-form-item>

        <el-form-item label="加密套件组">
          <el-select v-model="edit.tls_profile" style="width:320px">
            <el-option label="中等（默认：AEAD + 前向安全兼容套件）" value="moderate" />
            <el-option label="强加密（仅 AEAD 套件）" value="strong" />
            <el-option label="高兼容性（放宽至旧版套件）" value="compatible" />
          </el-select>
          <div class="km-dim" style="font-size:12px;margin-top:4px">HTTPS 站点统一 TLS 1.2 起步，TLS 1.3 始终可用；三档差异见配置文档</div>
        </el-form-item>
        </template>

        <div class="km-title" style="margin-top:18px">检测与防护</div>
        <el-form-item label="WAF (CRS)"><el-switch v-model="edit.wafEnabled" /></el-form-item>
        <el-form-item label="检测分类">
          <el-switch v-model="edit.catFollowGlobal" style="margin-right:8px" />
          <span class="km-dim" style="font-size:12px">跟随全局默认（关闭后按下方勾选覆盖）</span>
          <div v-if="!edit.catFollowGlobal" class="cat-grid" style="width:100%;margin-top:8px">
            <div v-for="c in CRS_CATEGORIES" :key="c.id" class="cat-item">
              <span class="cat-label">{{ c.label }}</span>
              <el-switch v-model="edit.catStates[c.id]" size="small" :disabled="!can('operator')" />
            </div>
          </div>
        </el-form-item>
        <el-form-item label="请求体上限">
          <div style="width:100%">
            <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
              <span class="km-dim" style="font-size:12px">缓冲上限</span>
              <el-input-number v-model="edit.bodyLimitMB" :min="1" :max="10240" size="small" style="width:118px" placeholder="默认 8" />
              <span class="km-dim" style="font-size:12px">MB</span>
              <span class="km-dim" style="font-size:12px;margin-left:10px">检测窗口</span>
              <el-input-number v-model="edit.bodyInspectKB" :min="16" :max="10485760" size="small" style="width:130px" placeholder="默认 256" />
              <span class="km-dim" style="font-size:12px">KB</span>
              <el-select v-model="edit.bodyOverLimit" size="small" style="width:140px;margin-left:10px">
                <el-option label="拒绝（413）" value="reject" />
                <el-option label="深检前缀" value="stream" />
                <el-option label="流式透传" value="bypass" />
              </el-select>
            </div>
            <div class="km-dim" style="font-size:12px;margin-top:8px">深检前缀路径（上传接口）：命中路径超限时不拒绝，只深检窗口后放行；未列出路径仍按超限动作处理</div>
            <div style="display:flex;gap:8px;align-items:center;margin-top:6px">
              <el-input v-model="edit.newStreamPath" size="small" placeholder="/v1/patrol/install/rulefile/upload"
                        style="max-width:380px" class="km-mono" :disabled="!can('operator')" @keyup.enter="addEditStreamPath" />
              <el-button size="small" :disabled="!can('operator')" @click="addEditStreamPath">添加</el-button>
            </div>
            <div v-if="(edit.bodyStreamPaths || []).length" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:6px">
              <el-tag v-for="p in edit.bodyStreamPaths" :key="p" closable class="km-mono"
                      @close="edit.bodyStreamPaths = edit.bodyStreamPaths.filter(x => x !== p)">{{ p }}</el-tag>
            </div>
          </div>
        </el-form-item>
        <el-form-item label="语义检测"><el-switch v-model="edit.semanticEnabled" /></el-form-item>
        <el-form-item label="滑块验证码"><el-switch v-model="edit.captchaEnabled" />
          <el-input v-if="edit.captchaEnabled" v-model="edit.captchaSecret" placeholder="HMAC 密钥（可选）" style="width:220px;margin-left:10px" size="small" />
        </el-form-item>
        <el-form-item label="CC 限流">
          <el-switch v-model="edit.rlEnabled" />
          <template v-if="edit.rlEnabled">
            <el-input-number v-model="edit.rlRequests" :min="1" size="small" style="margin-left:10px;width:110px" />
            <span class="km-dim" style="margin:0 6px;font-size:12px">次 /</span>
            <el-input-number v-model="edit.rlWindow" :min="1" size="small" style="width:110px" />
            <span class="km-dim" style="margin-left:6px;font-size:12px">秒</span>
            <el-select v-model="edit.rlAction" size="small" style="width:90px;margin-left:10px">
              <el-option label="429 限速" value="throttle" /><el-option label="403 拒绝" value="deny" />
            </el-select>
          </template>
        </el-form-item>
        <el-form-item label="GeoIP 封禁">
          <el-switch v-model="edit.geoEnabled" style="margin-left:10px" />
          <template v-if="edit.geoEnabled">
            <el-radio-group v-model="edit.geoMode" size="small" style="margin-left:12px">
              <el-radio-button value="blacklist">封禁所选地区</el-radio-button>
              <el-radio-button value="whitelist">仅允许所选地区</el-radio-button>
            </el-radio-group>
            <el-select v-model="edit.geoCountries" multiple filterable collapse-tags collapse-tags-tooltip reserve-keyword
                       placeholder="选择国家/地区（可多选，输入码或中文名筛选）" size="small" style="width:100%;margin-top:8px">
              <el-option v-for="c in geoAllOptions" :key="c.value" :label="c.label" :value="c.value" />
            </el-select>
            <el-checkbox v-if="edit.geoMode === 'whitelist'" v-model="edit.geoTrusted" style="margin-top:4px">
              白名单命中跳过后续全部检测（trusted）
            </el-checkbox>
          </template>
        </el-form-item>
        <el-form-item label="站点认证">
          <el-switch v-model="edit.authEnabled" />
          <template v-if="edit.authEnabled">
            <el-input v-model="edit.authUser" placeholder="用户名" size="small" style="width:130px;margin-left:10px" />
            <el-input v-model="edit.authPass" placeholder="密码(≥8位，留空保持原有密码)" size="small" style="width:220px;margin-left:10px" show-password />
          </template>
        </el-form-item>
        <el-form-item label="响应脱敏">
          <el-switch v-model="edit.respEnabled" />
          <el-select v-if="edit.respEnabled" v-model="edit.respPresets" multiple size="small" style="width:280px;margin-left:10px">
            <el-option label="手机号" value="phone" /><el-option label="身份证" value="idcard" /><el-option label="密钥" value="secret" />
          </el-select>
        </el-form-item>
        <el-form-item label="动态防护">
          <el-switch v-model="edit.dynamicEnabled" />
          <span class="km-dim" style="margin-left:10px;font-size:12px">HTML 逐请求加密（需 HTTPS）</span>
        </el-form-item>

        <div class="km-title" style="margin-top:18px">访问控制 / 可用性</div>
        <el-form-item label="IP 黑名单">
          <el-select v-model="edit.aclBlack" multiple filterable allow-create default-first-option
                     placeholder="IP/CIDR/group:名称" style="width:100%" />
        </el-form-item>
        <el-form-item label="IP 白名单">
          <el-select v-model="edit.aclWhite" multiple filterable allow-create default-first-option
                     placeholder="IP/CIDR/group:名称" style="width:100%" />
        </el-form-item>
        <el-form-item label="健康检查">
          <el-switch v-model="edit.healthEnabled" />
          <el-input v-if="edit.healthEnabled" v-model="edit.healthPath" placeholder="探测路径 /" size="small" style="width:150px;margin-left:10px" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="drawer = false">取消</el-button>
        <el-button type="primary" @click="applyEdit">保存到配置（待发布）</el-button>
        <el-button type="success" :loading="publishingSite" :disabled="!can('operator')" @click="saveAndPublishSite">保存并发布此站点</el-button>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, applyNotice, can, post } from '../api'
import { fmtTime } from '../timefmt'
import { parseListenAddr } from '../listen'
import { GEO_NAMES, geoCountryName } from '../geoNames'

const route = useRoute()

const uploads = ref([])
async function loadUploads() { try { uploads.value = await api('/api/certificates/uploads') } catch (e) { uploads.value = [] } }
function fmtShort(ts) { return (ts || '').slice(0, 10) }

// GeoIP 国家/地区选项：统一取自共享映射 geoNames.js（唯一来源，全量 ISO 3166-1 alpha-2
// + 常见遗留/特殊码），不再维护页面内手写子集表；显示名与 geoNames.js 完全一致（如「沙特阿拉伯」）。
// 交互用 el-select 既有 filterable 搜索过滤（输入码或中文名均可命中），全量约 260 项静态渲染
// 规模可接受，不引入虚拟滚动组件；未被映射收录的手工配置码追加为兜底选项，保证回显可反选不丢值。
const geoOptions = Object.entries(GEO_NAMES).map(([code, name]) => ({ label: code + ' · ' + name, value: code }))
const geoAllOptions = computed(() => {
  const known = new Set(geoOptions.map(o => o.value))
  const extra = (Array.isArray(edit.geoCountries) ? edit.geoCountries : [])
    .filter(cc => !known.has(String(cc ?? '').trim().toUpperCase()))
    .map(cc => ({ label: String(cc) + ' · ' + geoCountryName(cc), value: cc }))
  return extra.concat(geoOptions)
})

// 防护概览卡片的 GeoIP 描述：方向 + 国家/地区摘要（码值转中文，未识别码保留括号原码）。
function geoDesc(s) {
  const geo = s.security?.geo
  if (!geo?.enabled) return '按国家/地区黑白名单控制来源 · 使用内置 DB-IP 库，无需自备 mmdb'
  const list = geo.blacklist?.length ? geo.blacklist : geo.whitelist || []
  const dir = geo.blacklist?.length ? '黑名单' : '白名单'
  const head = list.slice(0, 6).map(cc => geoCountryName(cc)).join(' / ')
  return `${dir}模式：${head}${list.length > 6 ? ` 等 ${list.length} 个国家/地区` : (list.length ? '' : '（未选择地区）')}`
}

const rev = ref(0)
const revs = ref([])
const mode = ref('form')
const publishing = ref(false)
const publishingSite = ref(false)
const drawer = ref(false)
const editIndex = ref(-1)
const jsonText = ref('')
const sel = ref(0)
const dirty = ref(false)
function markDirty() { dirty.value = true }

// 上游协议切换时端口跟随默认值：HTTP→80、HTTPS→443；
// 用户已填非默认端口（如 8443）时保留不覆盖
function onUpstreamProtoChange(u) {
  const d = u.proto === 'https' ? 443 : 80
  if (!u.port || u.port === 80 || u.port === 443) u.port = d
}

// 表单模型 = 整份配置（sites 数组 + 顶层）。
// listen_http / listen_https 已迁至系统设置页「数据面监听」，此处仅作发布透传：
// load() 时从配置初始化，publishForm 发布前再用最新配置覆写，避免发布时把监听清空；
// acme_email 保留在本页工具栏编辑，随「发布配置」一并生效
const form = reactive({ listen_http: '', listen_https: '', acme_email: '', audit_log_dir: 'logs', sites: [], _raw: null })

// 发布整份配置前的前置校验（与后端 config.Validate 对齐）：
// 启用 ACME 或 HTTPS 跳转的站点必须先有全局 HTTPS 监听。
// 监听地址格式/端口范围校验已随「全局监听设置」迁至系统设置页，本页不再编辑监听、只做站点级前置拦截。
function validatePublishConfig(cfg) {
  const ls = parseListenAddr(cfg?.listen_https)
  const sites = Array.isArray(cfg?.sites) ? cfg.sites : []
  for (let i = 0; i < sites.length; i++) {
    const s = sites[i] || {}
    const label = (s.domains && s.domains[0]) || '#' + i
    if (s.acme && (!ls.ok || ls.empty)) return '站点「' + label + '」启用 ACME 自动证书：请先在系统设置页「数据面监听」填写 HTTPS 监听地址（如 0.0.0.0:443）'
    if (s.redirect_to_https && (!ls.ok || ls.empty)) return '站点「' + label + '」启用了 HTTPS 跳转：请先在系统设置页「数据面监听」填写 HTTPS 监听地址（如 0.0.0.0:443）'
  }
  return ''
}

const selSite = computed(() => (form.sites.length ? form.sites[Math.min(sel.value, form.sites.length - 1)] : null))

// ---- CRS 检测分类（签名检测子面板）----
// 固定顺序与中英文标签，与 Policy 页全局默认卡、后端 CRS 规则类别保持一致
const CRS_CATEGORIES = [
  { id: 'sqli', label: 'SQL 注入' },
  { id: 'xss', label: 'XSS 跨站' },
  { id: 'rce', label: '远程代码执行' },
  { id: 'lfi', label: '本地文件包含' },
  { id: 'rfi', label: '远程文件包含' },
  { id: 'php', label: 'PHP 攻击' },
  { id: 'generic', label: '通用攻击' },
  { id: 'session', label: '会话固定' },
  { id: 'java', label: 'Java 攻击' },
  { id: 'scanner', label: '扫描器' },
]
const crsCatsOpen = ref(false)
const catStates = reactive({})
const bodyLimitOpen = ref(false)

// 请求体上限（站点级 waf.body_limit_bytes / body_over_limit）：面板按 MB 编解码，
// 未设置 = 默认 8 MiB；「拒绝（413）」为默认动作，选回默认即删除字段保持配置精简
const bodyLimitMB = computed({
  get: () => {
    const b = selSite.value?.waf?.body_limit_bytes
    return b > 0 ? Math.round((b / 1048576) * 10) / 10 : undefined
  },
  set: v => {
    const s = selSite.value
    if (!s) return
    if (!s.waf) s.waf = { enabled: true }
    if (v && v > 0) s.waf.body_limit_bytes = Math.round(v * 1048576)
    else delete s.waf.body_limit_bytes
    markDirty()
  },
})
const bodyOverLimit = computed({
  get: () => selSite.value?.waf?.body_over_limit || 'reject',
  set: v => {
    const s = selSite.value
    if (!s) return
    if (!s.waf) s.waf = { enabled: true }
    if (v === 'reject') delete s.waf.body_over_limit
    else s.waf.body_over_limit = v
    markDirty()
  },
})
// 引擎检测窗口（站点级 waf.body_inspect_bytes）：面板按 KB 编解码，
// 未设置 = 默认 256 KB；窗口外内容不检测并记 body_skip=prefix
const bodyInspectKB = computed({
  get: () => {
    const b = selSite.value?.waf?.body_inspect_bytes
    return b > 0 ? Math.round(b / 1024) : undefined
  },
  set: v => {
    const s = selSite.value
    if (!s) return
    if (!s.waf) s.waf = { enabled: true }
    if (v && v > 0) s.waf.body_inspect_bytes = Math.round(v * 1024)
    else delete s.waf.body_inspect_bytes
    markDirty()
  },
})
const bodyLimitDesc = computed(() => {
  const b = selSite.value?.waf?.body_limit_bytes
  const mb = b > 0 ? `${b / 1048576} MiB` : '默认 8 MiB'
  const w = selSite.value?.waf?.body_inspect_bytes
  const win = w > 0 ? `检测窗口 ${Math.round(w / 1024)} KB` : '检测窗口 256 KB'
  const act = selSite.value?.waf?.body_over_limit
  const actText = act === 'bypass' ? '超限流式透传（仅头部检测）' : act === 'stream' ? '超限深检前缀后放行' : '超限拒绝（413）'
  const paths = selSite.value?.waf?.body_stream_paths
  const extra = Array.isArray(paths) && paths.length ? ` · 深检前缀 ${paths.length} 条` : ''
  return `${mb} · ${win} · ${actText}${extra}`
})

// 深检前缀路径（站点级 waf.body_stream_paths）：列表中任一前缀命中的请求超限时
// 不拒绝，而是只深检「检测窗口」后流式放行；未命中回退站点级超限动作。
// 放宽只认服务端声明的前缀（不认客户端头），因此在此显式维护
const newStreamPath = ref('')
function addStreamPath() {
  const s = selSite.value
  const p = (newStreamPath.value || '').trim()
  if (!s || !p) return
  if (!p.startsWith('/') || p === '/') { ElMessage.warning('路径前缀需以 / 开头（如 /v1/upload）'); return }
  if (p.includes('?') || /\s/.test(p)) { ElMessage.warning('路径前缀不能包含空白或 ?'); return }
  if (!s.waf) s.waf = { enabled: true }
  const list = Array.isArray(s.waf.body_stream_paths) ? s.waf.body_stream_paths : []
  if (list.includes(p)) { ElMessage.warning('已存在相同前缀'); return }
  if (list.length >= 64) { ElMessage.warning('最多 64 条深检前缀路径'); return }
  s.waf.body_stream_paths = [...list, p]
  newStreamPath.value = ''
  markDirty()
}
function removeStreamPath(p) {
  const s = selSite.value
  if (!s || !s.waf) return
  s.waf.body_stream_paths = (s.waf.body_stream_paths || []).filter(x => x !== p)
  if (!s.waf.body_stream_paths.length) delete s.waf.body_stream_paths
  markDirty()
}

// 全局默认装载集：config.policy.waf_categories，省略/nil = 全部启用
function globalCatDefaults() {
  const list = form.policy?.waf_categories
  return Array.isArray(list) ? CRS_CATEGORIES.map(c => c.id).filter(id => list.includes(id)) : CRS_CATEGORIES.map(c => c.id)
}

// 进入站点/展开面板时初始化开关：站点显式 categories 优先，否则预填全局默认
function initCatStates() {
  const explicit = selSite.value?.waf?.categories
  const eff = Array.isArray(explicit) ? CRS_CATEGORIES.map(c => c.id).filter(id => explicit.includes(id)) : globalCatDefaults()
  for (const c of CRS_CATEGORIES) catStates[c.id] = eff.includes(c.id)
}

watch(selSite, s => {
  // 防御：waf 字段缺失时补默认结构，避免签名检测行 el-switch 的 v-model 读到 undefined
  if (s && !s.waf) s.waf = { enabled: true }
  initCatStates()
}, { immediate: true })

function toggleCatsPanel() {
  crsCatsOpen.value = !crsCatsOpen.value
  if (crsCatsOpen.value) initCatStates()
}

// 切开关即写入草稿（随「发布配置」整体发布）：启用集合与全局默认一致时回到跟随语义
function onCatToggle() {
  const s = selSite.value
  if (!s) return
  if (!s.waf) s.waf = { enabled: true }
  const enabled = CRS_CATEGORIES.map(c => c.id).filter(id => catStates[id])
  const def = globalCatDefaults()
  if (def.length === enabled.length && def.every(id => enabled.includes(id))) delete s.waf.categories
  else s.waf.categories = enabled
  markDirty()
}

// 恢复全局默认：重置开关为默认状态并移除站点级覆盖
function resetCatsToDefault() {
  const s = selSite.value
  if (!s) return
  if (!s.waf) s.waf = { enabled: true }
  delete s.waf.categories
  initCatStates()
  markDirty()
}

// 站点列表分页：默认每页 10 条，可选 10/20/50/100
const sitePage = ref(1)
const sitePageSize = ref(10)

// 站点筛选：不区分大小写子串匹配 名称/备注/域名/源站地址，空词返回全部。
// 保留 form.sites 原始索引 i，选中与编辑仍指向原始站点。
const siteFilter = ref('')
// 顶部筛选：文本检索 + 源站健康状态 + 站点防护状态
const healthFilter = ref('')
const modeFilter = ref('')

// 站点防护状态：disabled（禁用）优先于 mode
function modeKeyOf(s) {
  if (s?.disabled) return 'disabled'
  return s?.mode === 'monitor' ? 'monitor' : 'intercept'
}
function modeTag(s) {
  const k = modeKeyOf(s)
  if (k === 'disabled') return { text: '禁用', type: 'info' }
  if (k === 'monitor') return { text: '观察', type: 'warning' }
  return { text: '拦截', type: 'success' }
}
// 源站健康状态键（无健康快照时为 none）
function healthKeyOf(s) {
  const st = siteStats.value[s?.domains?.[0]]
  const h = st?.health
  if (h && h.total > 0) return h.status
  return 'none'
}

// 排序（点击表头）：custom 排序作用于完整筛选结果，而非当前页
const sortKey = ref('')
const sortOrder = ref('')
function onSiteSortChange({ prop, order }) {
  sortKey.value = order ? prop : ''
  sortOrder.value = order || ''
  sitePage.value = 1
}

const filteredSites = computed(() => {
  const q = siteFilter.value.trim().toLowerCase()
  let rows = form.sites.map((s, i) => ({ s, i, st: statOf(s) }))
  if (q) {
    rows = rows.filter(({ s }) => {
      const fields = [s.name, s.comment, ...(s.domains || []), ...((s.upstream?.nodes || []).map(n => n?.address))]
      return fields.some(v => String(v || '').toLowerCase().includes(q))
    })
  }
  if (healthFilter.value) rows = rows.filter(r => healthKeyOf(r.s) === healthFilter.value)
  if (modeFilter.value) rows = rows.filter(r => modeKeyOf(r.s) === modeFilter.value)
  if (sortKey.value && sortOrder.value) {
    const dir = sortOrder.value === 'ascending' ? 1 : -1
    const val = r => {
      switch (sortKey.value) {
        case 'name': return String(r.s.name || r.s.domains?.[0] || '')
        case 'domain': return String(r.s.domains?.[0] || '')
        case 'health': { const o = { healthy: 0, degraded: 1, down: 2, none: 3 }; return o[healthKeyOf(r.s)] ?? 9 }
        case 'mode': { const o = { intercept: 0, monitor: 1, disabled: 2 }; return o[modeKeyOf(r.s)] ?? 9 }
        case 'requests': return r.st?.requests || 0
        case 'attacks': return r.st?.attacks || 0
        default: return ''
      }
    }
    rows = [...rows].sort((a, b) => {
      const va = val(a); const vb = val(b)
      if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir
      return String(va).localeCompare(String(vb), 'zh-Hans-CN') * dir
    })
  }
  return rows
})
watch([siteFilter, healthFilter, modeFilter], () => { sitePage.value = 1 })

const pagedSites = computed(() => {
  const list = filteredSites.value
  const start = (sitePage.value - 1) * sitePageSize.value
  return list.slice(start, start + sitePageSize.value)
})

// 版本历史分页：默认每页 10 行，可选 10/20/50/100
const revPage = ref(1)
const revPageSize = ref(10)
const pagedRevs = computed(() => {
  const start = (revPage.value - 1) * revPageSize.value
  return revs.value.slice(start, start + revPageSize.value)
})
watch(revPageSize, () => { const max = Math.max(1, Math.ceil(revs.value.length / revPageSize.value)); if (revPage.value > max) revPage.value = max })
watch(revs, () => { const max = Math.max(1, Math.ceil(revs.value.length / revPageSize.value)); if (revPage.value > max) revPage.value = max })

function sec(s) { if (!s.security) s.security = {}; return s.security }
function wafOn(s) { return !s.waf || s.waf.enabled !== false }

// 行内开关辅助:开启时以 extra 作为初始对象
function toggleSec(s, key, v, extra) {
  if (v) sec(s)[key] = { enabled: true, ...extra }
  else delete sec(s)[key]
  markDirty()
}
function toggleRatelimit(v) {
  const s = selSite.value
  if (!s) return
  if (v) sec(s).ratelimit = { requests: s.security?.ratelimit?.requests || 120, window_sec: s.security?.ratelimit?.window_sec || 10, action: s.security?.ratelimit?.action || 'deny' }
  else delete sec(s).ratelimit
  markDirty()
}
function toggleAcl(v) {
  const s = selSite.value
  if (!s) return
  if (v) sec(s).acl = { blacklist: s.security?.acl?.blacklist || [], whitelist: s.security?.acl?.whitelist || [] }
  else delete sec(s).acl
  markDirty()
}

// 单站点快速禁用/启用:改 disabled 字段后立即走单站点发布(热生效)
const toggling = ref(-1)
async function toggleSite(i) {
  if (!can('operator') || toggling.value >= 0) return
  const s = form.sites[i]
  if (!s) return
  toggling.value = i
  try {
    const next = { ...JSON.parse(JSON.stringify(s)), disabled: !s.disabled }
    const d = await post('/api/config/site/publish', {
      domain: (next.domains && next.domains[0]) || '',
      note: (next.disabled ? 'site disabled: ' : 'site enabled: ') + ((next.domains && next.domains[0]) || ''),
      site: next,
      comment: next.comment || '',
    })
    applyNotice(d, (next.disabled ? '站点已禁用' : '站点已启用') + '，热生效（版本 ' + d.revision + '）')
    await load()
    sel.value = i
  } catch (e) {
    ElMessage.error('切换失败：' + e.message)
  } finally {
    toggling.value = -1
  }
}

// ---- 站点列表统计徽标（GET /api/stats/per-site：今日 0 点至今）----
const siteStats = ref({}) // domain -> { requests, attacks }，键为站点 domains[0]
async function loadSiteStats() {
  try {
    const d = await api('/api/stats/per-site')
    const m = {}
    for (const it of (d?.sites || [])) if (it && it.site) m[it.site] = it
    siteStats.value = m
  } catch (e) {
    siteStats.value = {} // 统计失败静默降级为空，不阻塞配置加载
  }
}

// 统计匹配键 = 站点 domains[0]（与后端 firstDomain 对齐），未命中显示 0
function statOf(s) {
  const st = siteStats.value[s?.domains?.[0]]
  return { requests: st?.requests || 0, attacks: st?.attacks || 0, health: st?.health || null }
}

// 健康状态（表格列）：优先用后端上报的上游健康快照（本地数据面探测，
// /api/stats/per-site 的 health 字段）；无健康数据时退回「今日是否有流量」判定
function healthOf(row) {
  const s = row?.s || {}
  if (s.disabled) return { text: '已禁用', type: 'info' }
  const h = row?.st?.health
  if (h && h.total > 0) {
    if (h.status === 'healthy') return { text: `正常 ${h.healthy}/${h.total}`, type: 'success' }
    if (h.status === 'degraded') return { text: `降级 ${h.healthy}/${h.total}`, type: 'warning' }
    return { text: `故障 0/${h.total}`, type: 'danger' }
  }
  if ((row?.st?.requests || 0) > 0) return { text: '正常', type: 'success' }
  return { text: '无数据', type: 'info' }
}
function healthTip(row) {
  const s = row?.s || {}
  if (s.disabled) return '站点已禁用，数据面不路由该站点'
  const h = row?.st?.health
  if (h && h.total > 0) {
    const lines = []
    const parts = (h.nodes || []).map(n => `${n.address} ${n.healthy ? '健康' : '不可用'}`)
    lines.push('上游：' + (parts.join('，') || '-'))
    lines.push(`汇总：${h.healthy}/${h.total} 个上游健康`)
    return lines.join('\n')
  }
  if ((row?.st?.requests || 0) > 0) return '暂无上游健康数据（未开启健康检查或探测尚未上报），按今日流量判定为正常'
  if (s.health?.enabled) return '已开启上游健康检查，但暂无上报数据（探测尚在进行）'
  return '暂无健康数据：未开启上游健康检查且今日无流量'
}

// 抽屉内维护深检前缀路径（上传接口）
function addEditStreamPath() {
  const p = String(edit.newStreamPath || '').trim()
  if (!p) return
  if (!p.startsWith('/') || p === '/') { ElMessage.warning('路径前缀需以 / 开头'); return }
  if (p.includes('?') || /\s/.test(p)) { ElMessage.warning('路径前缀不能包含空白或 ?'); return }
  if ((edit.bodyStreamPaths || []).includes(p)) { ElMessage.warning('已存在相同前缀'); return }
  if ((edit.bodyStreamPaths || []).length >= 64) { ElMessage.warning('最多 64 条深检前缀路径'); return }
  edit.bodyStreamPaths = [...(edit.bodyStreamPaths || []), p]
  edit.newStreamPath = ''
}

async function load() {
  loadSiteStats()
  const d = await api('/api/config')
  rev.value = d.revision
  jsonText.value = JSON.stringify(d.config, null, 2)
  Object.assign(form, JSON.parse(JSON.stringify(d.config)))
  const rs = await api('/api/revisions')
  revs.value = rs
  dirty.value = false
  if (sel.value >= form.sites.length) sel.value = Math.max(0, form.sites.length - 1)
}

async function publishForm() {
  let cfg
  if (mode.value === 'json') {
    try { cfg = JSON.parse(jsonText.value) } catch (e) { return ElMessage.error('JSON 解析失败：' + e.message) }
    if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) {
      return ElMessage.error('JSON 根节点应为配置对象，如 {"listen_http": "..."}')
    }
  } else {
    cfg = JSON.parse(JSON.stringify(form))
    delete cfg._raw
  }
  // 防覆盖（图形化/JSON 两分支同源）：监听两字段已迁至系统设置页，发布前用最新
  // 活跃配置覆写，避免本页 stale/缺失值把其他管理员刚更新的监听设置覆盖回去
  // （拉取失败时退回各自分支的初始化值）；acme_email 属本页工具栏编辑项，
  // 保留草稿值随本次发布生效（JSON 模式下同样合入，不再被静默丢弃）
  try {
    const d = await api('/api/config')
    const latest = d.config || {}
    cfg.listen_http = latest.listen_http || ''
    // ACME 邮箱的编辑入口已迁至证书管理页：图形化模式按最新活跃配置透传，
    // 避免本页旧表单值把证书页刚保存的邮箱覆盖回去；JSON 模式保留显式编辑值
    if (mode.value === 'form' && 'acme_email' in latest) cfg.acme_email = latest.acme_email
    cfg.listen_https = latest.listen_https || ''
  } catch (e) { /* 拉取失败沿用当前分支的初始化值 */ }
  cfg.acme_email = form.acme_email || ''
  const preErr = validatePublishConfig(cfg)
  if (preErr) return ElMessage.error(preErr)
  publishing.value = true
  try {
    const d = await post('/api/config/publish', { note: 'console publish', config: cfg })
    applyNotice(d, '发布成功，版本 ' + d.revision + '，已热生效')
    await load()
  } catch (e) {
    if (e && e.code === 'no_changes') {
      ElMessage.info('配置无变更，未创建新版本')
      await load()
    } else {
      ElMessage.error('发布失败：' + e.message)
    }
  } finally {
    publishing.value = false
  }
}

async function rollbackPrev() {
  if (revs.value.length < 2) return ElMessage.warning('没有可回滚的历史版本')
  const d = await post(`/api/revisions/${revs.value[1].id}/rollback`)
  applyNotice(d, '已回滚至版本 ' + revs.value[1].id + '，发布为 v' + d.revision)
  await load()
}
async function rollbackTo(id) {
  const d = await post(`/api/revisions/${id}/rollback`)
  applyNotice(d, '已回滚至版本 ' + id + '，发布为 v' + d.revision)
  await load()
}

// ---- 编辑抽屉:config site ↔ 表单模型 ----
const edit = reactive({})
// 固定回源 SNI 仅对 HTTPS 上游有意义：任一上游行选了 https 协议才显示
const upstreamHasHTTPS = computed(() => (edit.upstreamRows || []).some(u => u.proto === 'https'))
function onTlsSource(v) {
  if (v === 'none') edit.redirect_to_https = false
}
// 协议切换：HTTP 时清空 TLS 相关选择；HTTPS 且无证书来源时默认 ACME 自动
function onProtoChange(v) {
  if (v === 'http') {
    edit.tlsSource = 'none'
    edit.redirect_to_https = false
  } else if (edit.tlsSource === 'none') {
    edit.tlsSource = 'acme'
  }
}
function openEdit(i) {
  editIndex.value = i
  if (i < 0) sel.value = Math.max(0, form.sites.length - 1)
  const s = i >= 0 ? JSON.parse(JSON.stringify(form.sites[i])) : {}
  edit.domainRows = (s.domains || []).map(d => d)
  edit.name = s.name || ''
  edit.comment = s.comment || ''
  if (!edit.domainRows.length) edit.domainRows.push('')
  edit.upstreamRows = (s.upstream?.nodes || []).map(n => {
    let proto = 'http', rest = n.address || '', ip = rest, port = 80
    const m = String(n.address || '').match(/^(https?):\/\/(.+)$/)
    if (m) { proto = m[1]; rest = m[2] }
    const hi = rest.lastIndexOf(':')
    if (hi > 0) { ip = rest.slice(0, hi); const p = parseInt(rest.slice(hi + 1), 10); if (p > 0) port = p }
    return { proto, ip, port, weight: n.weight || 1 }
  })
  if (!edit.upstreamRows.length) edit.upstreamRows.push({ proto: 'http', ip: '', port: 80, weight: 1 })
  edit.algorithm = s.upstream?.algorithm || 'wrr'
  edit.sniForward = !!s.upstream?.sni_forward
  edit.sniHost = s.upstream?.sni_host || ''
  edit.verifyTls = !!s.upstream?.verify_tls
  edit.mode = s.mode || 'intercept'
  edit.modeOrDisabled = s.disabled ? 'disabled' : (s.mode === 'monitor' ? 'monitor' : 'intercept')
  edit.redirect_to_https = i >= 0 ? !!s.redirect_to_https : true
  edit.protocol = i >= 0 && !s.tls_cert && !s.acme && !s.redirect_to_https ? 'http' : 'https'
  edit.http2Enabled = s.http2_enabled === undefined ? true : !!s.http2_enabled
  // 证书来源识别:acme / 已上传(路径命中证书库) / PEM / 无;新站点默认 ACME
  edit.tlsSource = i >= 0 ? (s.acme ? 'acme' : (s.tls_cert ? (uploads.value.some(u => u.cert_path === s.tls_cert) ? 'uploaded' : 'file') : 'none')) : 'acme'
  edit.uploadedName = i >= 0 ? (uploads.value.find(u => u.cert_path === s.tls_cert)?.name || '') : ''
  edit.tls_cert = s.tls_cert || ''
  edit.tls_key = s.tls_key || ''
  edit.tls_profile = s.tls_profile || 'moderate'
  loadUploads()
  edit.wafEnabled = wafOn(s)
  const sec0 = s.security || {}
  // 新建站点默认开启语义检测；编辑已有站点保持其现值
  edit.semanticEnabled = i < 0 ? true : !!sec0.semantic?.enabled
  edit.captchaEnabled = !!sec0.captcha?.enabled
  edit.captchaSecret = sec0.captcha?.secret || ''
  edit.rlEnabled = !!sec0.ratelimit
  edit.rlRequests = sec0.ratelimit?.requests || 100
  edit.rlWindow = sec0.ratelimit?.window_sec || 60
  edit.rlAction = sec0.ratelimit?.action || 'throttle'
  edit.geoEnabled = !!sec0.geo?.enabled
  edit.geoMode = (sec0.geo?.whitelist?.length ? 'whitelist' : 'blacklist')
  edit.geoCountries = sec0.geo?.whitelist?.length ? (sec0.geo.whitelist || []) : (sec0.geo?.blacklist || [])
  edit.geoTrusted = !!sec0.geo?.whitelist_trusted
  edit.authEnabled = !!sec0.auth
  edit.authUser = sec0.auth?.users?.[0]?.username || ''
  edit.authPass = ''
  edit.respEnabled = !!sec0.resp_filter?.enabled
  edit.respPresets = sec0.resp_filter?.presets || ['phone', 'idcard', 'secret']
  edit.dynamicEnabled = !!sec0.dynamic?.enabled
  edit.aclBlack = sec0.acl?.blacklist || []
  edit.aclWhite = sec0.acl?.whitelist || []
  edit.healthEnabled = !!s.health?.enabled
  edit.healthPath = s.health?.path || '/'
  // 防护参数（检测分类 / 请求体策略）在抽屉内维护
  const w0 = s.waf || {}
  edit.catFollowGlobal = !Array.isArray(w0.categories)
  edit.catStates = {}
  const wafcats = Array.isArray(w0.categories) ? w0.categories : (form.policy?.waf_categories || CRS_CATEGORIES.map(c => c.id))
  for (const c of CRS_CATEGORIES) edit.catStates[c.id] = wafcats.includes(c.id)
  edit.bodyLimitMB = w0.body_limit_bytes > 0 ? Math.round((w0.body_limit_bytes / 1048576) * 10) / 10 : undefined
  edit.bodyInspectKB = w0.body_inspect_bytes > 0 ? Math.round(w0.body_inspect_bytes / 1024) : undefined
  edit.bodyOverLimit = w0.body_over_limit || 'reject'
  edit.bodyStreamPaths = Array.isArray(w0.body_stream_paths) ? [...w0.body_stream_paths] : []
  edit.newStreamPath = ''
  drawer.value = true
}

async function applyEdit() {
  // 域名行支持中/英文逗号分隔的批量录入：拆分、去空白、去重，杜绝
  // "a.com,b.com" 被存成单一字面域名导致的数据面 no_site 403。
  const seen = new Set()
  const domains = []
  for (const row of edit.domainRows) {
    for (const piece of String(row || '').split(/[,，]/)) {
      const d = piece.trim()
      if (!d) continue
      if (seen.has(d)) continue
      seen.add(d)
      domains.push(d)
    }
  }
  const nodes = []
  for (const u of edit.upstreamRows) {
    const ip = String(u.ip || '').trim()
    const port = Number(u.port) || 0
    if (!ip || port < 1 || port > 65535) continue
    nodes.push({ address: `${u.proto || 'http'}://${ip}:${port}`, weight: u.weight || 1 })
  }
  if (domains.length === 0) { ElMessage.error('至少需要一个域名'); return null }
  if (nodes.length === 0) { ElMessage.error('至少需要一个完整的上游服务器（协议/IP/端口）'); return null }
  // ACME / HTTPS 跳转的前置条件：全局 HTTPS 监听必须先配置（与后端 config.Validate 对齐，
  // 提前拦截并引导到系统设置页，避免发布时才被服务端拒绝；监听设置已在系统设置页维护，
  // 这里实时拉取最新活跃配置判断，拉取失败退回 form 初始化值）
  if (edit.protocol === 'https' && (edit.tlsSource === 'acme' || edit.redirect_to_https)) {
    let lhp = parseListenAddr(form.listen_https)
    try {
      const d = await api('/api/config')
      lhp = parseListenAddr(d.config?.listen_https)
    } catch (e) { /* 拉取失败沿用 form 初始化值 */ }
    if (!lhp.ok || lhp.empty) {
      ElMessage.error(edit.tlsSource === 'acme'
        ? '启用 ACME 自动证书需先配置全局 HTTPS 监听：请到系统设置页「数据面监听」填写（如 0.0.0.0:443）'
        : '启用 HTTPS 跳转需先配置全局 HTTPS 监听：请到系统设置页「数据面监听」填写（如 0.0.0.0:443）')
      return null
    }
  }
  const prevMode = editIndex.value >= 0 ? (form.sites[editIndex.value]?.mode || 'intercept') : 'intercept'
  const mode = edit.modeOrDisabled === 'monitor' ? 'monitor'
    : edit.modeOrDisabled === 'intercept' ? 'intercept'
    : prevMode
  const s = {
    name: (edit.name || '').trim(),
    domains,
    mode,
    upstream: { nodes, algorithm: edit.algorithm || 'wrr' }
  }
  if (edit.modeOrDisabled === 'disabled') s.disabled = true
  const sniHost = (edit.sniHost || '').trim()
  if (sniHost && edit.sniForward) {
    ElMessage.error('固定回源 SNI 与 SNI 转发互斥，请关闭其一')
    return null
  }
  if (edit.sniForward) s.upstream.sni_forward = true
  if (edit.verifyTls) s.upstream.verify_tls = true
  if (sniHost) s.upstream.sni_host = sniHost
  else delete s.upstream.sni_host
  if ((edit.comment || '').trim()) s.comment = edit.comment.trim()
  if (edit.protocol === 'https') {
    if (edit.redirect_to_https) s.redirect_to_https = true
    if (!edit.http2Enabled) s.http2_enabled = false
    if (edit.tlsSource === 'file') { s.tls_cert = edit.tls_cert; s.tls_key = edit.tls_key }
    s.tls_profile = edit.tls_profile || 'moderate'
    if (edit.tlsSource === 'uploaded') {
      if (!edit.uploadedName) {
        ElMessage.error('请选择已上传证书')
        return null
      }
      const found = uploads.value.find(u => u.name === edit.uploadedName)
      if (!found) {
        ElMessage.error('证书不存在，请先在证书管理上传')
        return null
      }
      s.tls_cert = found.cert_path
      s.tls_key = found.key_path
    }
    if (edit.tlsSource === 'acme') {
      // 空邮箱 = 使用系统设置中的 ACME 全局邮箱（服务端兜底）
      s.acme = {}
    }
  }
  s.waf = { enabled: !!edit.wafEnabled }
  // 站点级检测分类：跟随全局默认时不写 categories；否则写显式清单
  if (!edit.catFollowGlobal) {
    s.waf.categories = CRS_CATEGORIES.map(c => c.id).filter(id => !!edit.catStates?.[id])
  }
  // 请求体策略：仅写非默认值（默认 8 MiB / 256 KB / 拒绝）
  const blMB = Number(edit.bodyLimitMB)
  if (blMB > 0) s.waf.body_limit_bytes = Math.round(blMB * 1048576)
  const biKB = Number(edit.bodyInspectKB)
  if (biKB > 0) s.waf.body_inspect_bytes = Math.round(biKB * 1024)
  if (edit.bodyOverLimit === 'stream' || edit.bodyOverLimit === 'bypass') s.waf.body_over_limit = edit.bodyOverLimit
  const editStreamPaths = (edit.bodyStreamPaths || []).filter(Boolean)
  if (editStreamPaths.length) s.waf.body_stream_paths = [...editStreamPaths]
  const sec0 = {}
  if (edit.semanticEnabled) sec0.semantic = { enabled: true }
  if (edit.captchaEnabled) {
    sec0.captcha = { enabled: true }
    if (edit.captchaSecret) sec0.captcha.secret = edit.captchaSecret
  }
  if (edit.rlEnabled) sec0.ratelimit = { requests: edit.rlRequests, window_sec: edit.rlWindow, action: edit.rlAction }
  if (edit.geoEnabled) {
    sec0.geo = { enabled: true }
    if (edit.geoMode === 'whitelist') {
      sec0.geo.whitelist = [...edit.geoCountries]
      if (edit.geoTrusted) sec0.geo.whitelist_trusted = true
    } else {
      sec0.geo.blacklist = [...edit.geoCountries]
    }
  }
  if (edit.authEnabled) {
    const username = (edit.authUser || '').trim()
    if (!username) { ElMessage.error('启用站点认证需填写用户名'); return null }
    if (edit.authPass) {
      if (edit.authPass.length < 8) { ElMessage.error('站点认证密码至少 8 位'); return null }
      sec0.auth = { users: [{ username, password: edit.authPass }] }
    } else {
      const prev = editIndex.value >= 0 ? form.sites[editIndex.value] : null
      const prevAuth = prev && prev.security && prev.security.auth
      if (!prevAuth || !prevAuth.users || !prevAuth.users.length) {
        ElMessage.error('启用站点认证需填写密码（至少 8 位）'); return null
      }
      sec0.auth = prevAuth
    }
  }
  if (edit.respEnabled) sec0.resp_filter = { enabled: true, presets: edit.respPresets }
  if (edit.dynamicEnabled) sec0.dynamic = { enabled: true }
  if (edit.aclBlack.length || edit.aclWhite.length) sec0.acl = { blacklist: edit.aclBlack, whitelist: edit.aclWhite }
  if (Object.keys(sec0).length) s.security = sec0
  if (edit.healthEnabled) s.health = { enabled: true, path: edit.healthPath || '/' }

  if (editIndex.value >= 0) form.sites[editIndex.value] = s
  else {
    form.sites.push(s)
    sel.value = form.sites.length - 1
  }
  dirty.value = true
  drawer.value = false
  jsonText.value = JSON.stringify(formSitesConfig(), null, 2)
  return s
}

async function saveAndPublishSite() {
  // applyEdit shows the validation ElMessage errors itself; capture the
  // resulting site by re-running the draft update it performs.
  const before = JSON.stringify(form.sites)
  const s = await applyEdit()
  if (!s) return
  publishingSite.value = true
  try {
    const d = await post('/api/config/site/publish', {
      domain: (s.domains && s.domains[0]) || '',
      note: 'console site publish: ' + ((s.domains && s.domains[0]) || ''),
      site: s,
      comment: s.comment || '',
    })
    applyNotice(d, '站点已发布，版本 ' + d.revision + '，已热生效')
  } catch (e) {
    // Roll the draft back so the stale entry is not mistaken for live config.
    form.sites = JSON.parse(before)
    ElMessage.error('站点发布失败：' + e.message)
    return
  } finally {
    publishingSite.value = false
  }
  await load()
}

function formSitesConfig() {
  const c = JSON.parse(JSON.stringify(form))
  delete c._raw
  return c
}

function removeSite(i) {
  ElMessageBox.confirm('删除站点 ' + (form.sites[i].domains.join(', ')) + '？删除后需点击「发布配置」才会生效。', '确认', { type: 'warning' })
    .then(() => { form.sites.splice(i, 1); dirty.value = true })
    .catch(() => {})
}

// 证书页「引用站点」tag 跳转携带 /sites?site=<domain>：初始化与后续变化
// 均同步到站点筛选框（复用现有筛选，无新增 UI）。
function applySiteQuery() {
  const v = route.query.site
  siteFilter.value = typeof v === 'string' ? v : ''
}
watch(() => route.query.site, applySiteQuery)

let statsTimer = null
onMounted(() => { applySiteQuery(); load(); statsTimer = setInterval(loadSiteStats, 30000) })
onUnmounted(() => { if (statsTimer) { clearInterval(statsTimer); statsTimer = null } })
</script>

<style scoped>
.km-site-list .site-item { padding: 11px 14px; border-bottom: 1px solid var(--km-line-soft); cursor: pointer; }
.km-site-list .site-item:last-child { border-bottom: none; }
.km-site-list .site-item:hover { background: var(--km-panel-2); }
.km-site-list .site-item.sel { background: var(--km-nav-grad); }
.km-site-list .domain { font-size: 13.5px; font-weight: 600; color: var(--km-txt); display: flex; align-items: center; gap: 8px; }
.km-site-list .domains { margin-top: 3px; font-size: 11.5px; line-height: 1.5; color: var(--km-txt-3); word-break: break-all; }
.km-site-list .meta { font-size: 11px; color: var(--km-txt-3); margin-top: 3px; display: flex; gap: 8px; flex-wrap: wrap; }
.km-site-list .domain + .meta { margin-top: 5px; }
.km-site-list .stat-line { margin-top: 5px; font-size: 11px; color: var(--km-txt-2); }
.km-site-list .stat-line .atk { color: var(--km-red); font-weight: 700; }
.km-crs-sub { padding: 10px 16px 14px 64px; background: var(--km-panel-2); border-bottom: 1px solid var(--km-line-soft); }
.km-crs-sub .sub-head { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.km-crs-sub .sub-head .hint { flex: 1; font-size: 11.5px; color: var(--km-txt-3); line-height: 1.5; }
.km-crs-sub .cat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 12px; }
.km-crs-sub .cat-item { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 6px 10px; border-radius: 8px; background: var(--km-panel); border: 1px solid var(--km-line); }
.km-crs-sub .cat-item .cat-label { font-size: 12px; color: var(--km-txt-2); }
.cats-toggle { padding: 4px; }
.cats-toggle :deep(.el-icon) { transition: transform 0.2s; }
.cats-toggle.open :deep(.el-icon) { transform: rotate(180deg); }
</style>
