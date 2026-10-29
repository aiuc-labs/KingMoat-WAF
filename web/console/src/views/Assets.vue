<template>
  <div>
    <div class="km-title">API 安全（被动学习）</div>
    <el-alert v-if="!enabled" type="info" :closable="false" show-icon
              title="API 资产学习未启用" description="在配置中设置 api_assets.enabled=true 并发布后开始学习流量。" style="margin:12px 0" />

    <template v-if="enabled">
      <!-- 统计条 -->
      <div class="km-ast-stats">
        <div class="stat"><div class="n">{{ siteNames.length }}</div><div class="l">站点</div></div>
        <div class="stat"><div class="n">{{ assets.length }}</div><div class="l">端点</div></div>
        <div class="stat warn"><div class="n">{{ flagged.length }}</div><div class="l">需关注</div></div>
        <div class="stat"><div class="n">{{ fmtTotalHits }}</div><div class="l">累计命中</div></div>
        <div class="stat" :class="openRisks.length ? 'danger' : ''" style="cursor:pointer" @click="tab = 'risks'">
          <div class="n">{{ openRisks.length }}</div><div class="l">待处理风险</div>
        </div>
      </div>

      <el-tabs v-model="tab" class="km-sec-tabs">
        <!-- ============ 风险事件 Tab ============ -->
        <el-tab-pane name="risks">
          <template #label>风险事件<el-badge v-if="openRisks.length" :value="openRisks.length" class="tab-badge" /></template>

          <div class="km-toolbar">
            <el-alert type="info" :closable="false" show-icon style="flex:1"
                      title="风险中心：对 API 资产与流量的专项风险评估（observe-only，仅记录不阻断，建议人工复核）"
                      description="覆盖敏感数据暴露 / 未授权访问 / 登录爆破 / 影子 API / 僵尸 API / 管理面暴露 / 明文敏感参数。" />
            <el-button v-if="can('operator')" type="primary" @click="scan" :loading="scanning">立即扫描</el-button>
          </div>

          <div class="risk-grid" style="margin-bottom:16px">
            <el-card v-for="c in riskCards" :key="c.name" shadow="never" class="km-risk-card"
                     :body-style="{ padding: '14px 16px' }">
              <div class="rid" :style="{ color: c.color }">{{ c.label }}</div>
              <div class="rcount" :style="{ color: c.count ? c.color : 'var(--km-txt-3)' }">{{ c.count }}</div>
              <div class="rdesc">{{ c.desc }}</div>
            </el-card>
          </div>

          <el-card shadow="never" :body-style="{ padding: 0 }">
            <div class="km-card-head"><span class="km-card-title">风险事件明细</span></div>
            <el-table :data="risks" size="small" highlight-current-row @row-click="openRiskDetail" style="cursor:pointer">
              <el-table-column prop="kind" label="风险项" width="180">
                <template #default="{ row }">{{ kindLabel(row.kind) }}</template>
              </el-table-column>
              <el-table-column prop="site" label="站点" width="170" show-overflow-tooltip>
                <template #default="{ row }"><span class="km-mono" style="color:var(--km-soft-blue)">{{ row.site || '-' }}</span></template>
              </el-table-column>
              <el-table-column prop="level" label="级别" width="90">
                <template #default="{ row }">
                  <el-tag size="small" :type="row.level === 'high' ? 'danger' : row.level === 'medium' ? 'warning' : 'info'" effect="dark" class="km-tag">
                    {{ levelLabel(row.level) }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="count" label="次数" width="70">
                <template #default="{ row }"><span class="km-mono">{{ row.count ? row.count.toLocaleString() : '-' }}</span></template>
              </el-table-column>
              <el-table-column prop="status" label="状态" width="100">
                <template #default="{ row }">
                  <el-tag size="small" :type="row.status === 'open' ? 'warning' : 'success'" effect="dark" class="km-tag">{{ statusLabel(row.status) }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="message" label="证据" show-overflow-tooltip />
              <el-table-column width="240">
                <template #default="{ row }">
                  <el-button link type="primary" size="small" @click.stop="openRiskDetail(row)">详情</el-button>
                  <template v-if="can('operator') && row.status === 'open'">
                    <el-button link type="success" size="small" @click.stop="setStatus(row, 'resolved')">标记已处理</el-button>
                    <el-button link size="small" @click.stop="setStatus(row, 'ignored')">忽略</el-button>
                  </template>
                </template>
              </el-table-column>
            </el-table>
            <el-empty v-if="!risks.length" description="暂无风险事件" :image-size="80" />
          </el-card>
        </el-tab-pane>

        <!-- ============ 资产清单 Tab ============ -->
        <el-tab-pane name="assets">
          <template #label>资产清单</template>

          <div class="km-toolbar">
            <el-select v-model="fSite" size="small" style="width:200px" clearable placeholder="站点">
              <el-option v-for="s in siteNames" :key="s" :label="s" :value="s" />
            </el-select>
            <el-select v-model="fTag" size="small" style="width:150px" clearable placeholder="标记">
              <el-option label="认证入口 auth" value="auth" />
              <el-option label="管理后台 admin" value="admin" />
              <el-option label="数据导出 export" value="export" />
              <el-option label="文件操作 file" value="file" />
            </el-select>
            <el-select v-model="fMethod" size="small" style="width:110px" clearable placeholder="方法">
              <el-option v-for="m in methodNames" :key="m" :label="m" :value="m" />
            </el-select>
            <el-input v-model="fText" size="small" style="width:240px" placeholder="路径 / 参数关键字" clearable @keyup.enter="() => {}" />
            <div class="grow"></div>
            <span class="km-muted" style="font-size:12px">筛选出 {{ filtered.length }} / {{ assets.length }} 个端点</span>
          </div>

          <el-collapse v-model="expanded" class="km-ast-groups">
            <el-collapse-item v-for="g in grouped" :key="g.site" :name="g.site">
              <template #title>
                <div class="grp-head">
                  <span class="grp-site km-mono">{{ g.site }}</span>
                  <span class="grp-meta">{{ g.items.length }} 端点</span>
                  <el-tag v-if="g.flagged" size="small" type="warning" effect="plain" class="km-tag">{{ g.flagged }} 需关注</el-tag>
                  <span class="grp-hits km-dim">{{ g.hits }} 命中</span>
                </div>
              </template>
              <el-table :data="g.items" size="small">
                <el-table-column prop="method" label="方法" width="80">
                  <template #default="{ row }">
                    <el-tag size="small" effect="plain" :type="methodType(row.method)" class="km-tag">{{ row.method }}</el-tag>
                  </template>
                </el-table-column>
                <el-table-column prop="norm_path" label="路径（归一化）" class-name="km-mono" show-overflow-tooltip />
                <el-table-column label="标记" width="170">
                  <template #default="{ row }">
                    <template v-if="(row.tags || []).length">
                      <el-tag v-for="t in (row.tags || []).slice(0, 2)" :key="t" size="small" effect="dark" class="km-tag" style="margin-right:4px">{{ tagLabel(t) }}</el-tag>
                      <el-tooltip v-if="(row.tags || []).length > 2" :content="(row.tags || []).slice(2).map(tagLabel).join('、')" placement="top">
                        <el-tag size="small" effect="plain" class="km-tag">+{{ row.tags.length - 2 }}</el-tag>
                      </el-tooltip>
                    </template>
                    <span v-else class="km-dim">-</span>
                  </template>
                </el-table-column>
                <el-table-column prop="hits" label="命中" width="80" sortable />
                <el-table-column label="状态分布" width="150">
                  <template #default="{ row }">
                    <span v-if="row.status_dist" class="km-mono" style="font-size:12px">
                      <span v-if="row.status_dist['2xx']" style="color:var(--km-success,#67c23a)">{{ row.status_dist['2xx'] }}×2xx</span>
                      <span v-if="row.status_dist['4xx']" style="color:var(--km-warning,#e6a23c);margin-left:4px">{{ row.status_dist['4xx'] }}×4xx</span>
                      <span v-if="row.status_dist['5xx']" style="color:var(--km-danger,#f56c6c);margin-left:4px">{{ row.status_dist['5xx'] }}×5xx</span>
                    </span>
                    <span v-else class="km-dim">-</span>
                  </template>
                </el-table-column>
                <el-table-column label="信号" width="110">
                  <template #default="{ row }">
                    <el-tooltip v-if="(row.anon_ok || 0) > 0" content="匿名请求可成功访问（anon_ok>0），关注是否应要求认证" placement="top">
                      <el-tag size="small" type="warning" effect="plain" class="km-tag">匿名可用</el-tag>
                    </el-tooltip>
                    <span v-else-if="(row.authed_ratio || 0) > 0" class="km-dim" style="font-size:12px">认证 {{ Math.round(row.authed_ratio * 100) }}%</span>
                    <span v-else class="km-dim">-</span>
                  </template>
                </el-table-column>
                <el-table-column label="最后可见" width="160">
                  <template #default="{ row }">{{ fmtTime(row.last_seen) }}</template>
                </el-table-column>
                <el-table-column width="80">
                  <template #default="{ row }">
                    <el-button v-if="can('operator')" link type="warning" @click.stop="ignore(row)">忽略</el-button>
                  </template>
                </el-table-column>
              </el-table>
            </el-collapse-item>
          </el-collapse>
          <el-empty v-if="!grouped.length" description="没有匹配的端点" :image-size="80" />
        </el-tab-pane>
      </el-tabs>
    </template>

    <!-- 风险详情抽屉 -->
    <el-drawer v-model="detailDlg" :title="detail ? kindLabel(detail.kind) : '风险详情'" size="480px">
      <template v-if="detail">
        <el-descriptions :column="1" border size="small" style="margin-bottom:14px">
          <el-descriptions-item label="风险项">{{ kindLabel(detail.kind) }}</el-descriptions-item>
          <el-descriptions-item label="级别">
            <el-tag size="small" :type="detail.level === 'high' ? 'danger' : detail.level === 'medium' ? 'warning' : 'info'" effect="dark" class="km-tag">{{ levelLabel(detail.level) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag size="small" :type="detail.status === 'open' ? 'warning' : 'success'" effect="dark" class="km-tag">{{ statusLabel(detail.status) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="站点">
            <span class="km-mono">{{ detail.site || '-' }}</span>
          </el-descriptions-item>
          <el-descriptions-item v-if="detail.asset_ref" label="关联资产">
            <span class="km-mono">{{ detail.asset_ref }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="发生次数">{{ detail.count ? detail.count.toLocaleString() : '-' }}</el-descriptions-item>
          <el-descriptions-item label="首次发现">{{ fmtTime(detail.created_at) }}</el-descriptions-item>
          <el-descriptions-item label="最近更新">{{ fmtTime(detail.updated_at) }}</el-descriptions-item>
        </el-descriptions>

        <div class="km-title" style="margin-bottom:6px">证据说明</div>
        <div class="km-dim" style="font-size:12.5px;line-height:1.7;white-space:pre-wrap;word-break:break-all;margin-bottom:14px">{{ detail.message }}</div>

        <template v-if="evidenceRows.length">
          <div class="km-title" style="margin-bottom:6px">证据明细</div>
          <el-descriptions :column="1" border size="small" style="margin-bottom:14px">
            <el-descriptions-item v-for="r in evidenceRows" :key="r.k" :label="r.k">
              <span class="km-mono" style="font-size:12px;word-break:break-all">{{ r.v }}</span>
            </el-descriptions-item>
          </el-descriptions>
        </template>

        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <el-button v-if="detail.site" size="small" type="primary" plain @click="goAssetSite(detail.site)">查看该站点资产</el-button>
          <template v-if="can('operator') && detail.status === 'open'">
            <el-button size="small" type="success" @click="setStatus(detail, 'resolved'); detail.status = 'resolved'">标记已处理</el-button>
            <el-button size="small" @click="setStatus(detail, 'ignored'); detail.status = 'ignored'">忽略</el-button>
          </template>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api, can, post } from '../api'
import { useRoute, useRouter } from 'vue-router'
import { fmtTime } from '../timefmt'

const route = useRoute()
const router = useRouter()

const tab = ref(route.query.tab === 'assets' ? 'assets' : 'risks')
watch(tab, (v) => {
  const q = { ...route.query }
  if (v === 'assets') q.tab = 'assets'; else delete q.tab
  router.replace({ query: q })
})

// ============ 资产清单（原 /assets） ============
const assets = ref([])
const enabled = ref(true)
const fSite = ref('')
const fTag = ref('')
const fMethod = ref('')
const fText = ref('')
const expanded = ref([])

const tagLabels = { auth: '认证', admin: '管理', export: '导出', file: '文件' }
function tagLabel(t) { return tagLabels[t] || t }
function methodType(m) {
  return { POST: 'success', GET: 'primary', PUT: 'warning', DELETE: 'danger', PATCH: 'warning' }[m] || 'info'
}

const siteNames = computed(() => [...new Set(assets.value.map(a => a.site || '-'))].sort())
const methodNames = computed(() => [...new Set(assets.value.map(a => a.method))].sort())
const flagged = computed(() => assets.value.filter(a => (a.tags || []).length))
const fmtTotalHits = computed(() => assets.value.reduce((s, a) => s + (a.hits || 0), 0).toLocaleString())

const filtered = computed(() => assets.value.filter(a =>
  (!fSite.value || (a.site || '-') === fSite.value) &&
  (!fTag.value || (a.tags || []).includes(fTag.value)) &&
  (!fMethod.value || a.method === fMethod.value) &&
  (!fText.value || (a.norm_path || '').toLowerCase().includes(fText.value.toLowerCase()))))

// 分组排序：需关注多的站点在前，其余按站点名
const grouped = computed(() => {
  const map = new Map()
  for (const a of filtered.value) {
    const site = a.site || '-'
    if (!map.has(site)) map.set(site, { site, items: [], flagged: 0, hits: 0 })
    const g = map.get(site)
    g.items.push(a)
    if ((a.tags || []).length) g.flagged++
    g.hits += a.hits || 0
  }
  return [...map.values()].sort((x, y) => (y.flagged - x.flagged) || x.site.localeCompare(y.site))
})

async function loadAssets() {
  try {
    const d = await api('/api/assets/apis')
    const prev = assets.value
    assets.value = d.assets || d || []
    enabled.value = d.enabled !== false
    if (prev.length === 0 && assets.value.length && !expanded.value.length) {
      expanded.value = [grouped.value[0]?.site]
    }
  } catch (e) { if (e.status !== 401) enabled.value = false }
}
async function ignore(row) {
  await post(`/api/assets/apis/${row.id}/ignore`)
  ElMessage.success('已忽略')
  loadAssets()
}

// ============ 风险事件（原 /risks） ============
// 后端 Risk.kind 常量见 internal/apiasset/risk.go（R1–R7）
const RISK_DEFS = [
  { key: 'sensitive_exposure', label: '敏感信息暴露', desc: '响应中检测到手机号 / 密钥等敏感信息未脱敏', color: 'var(--km-soft-red)' },
  { key: 'unauthorized', label: '未授权访问', desc: '接口未携带凭证即可返回数据，疑似缺失鉴权', color: 'var(--km-soft-amber)' },
  { key: 'bruteforce', label: '登录爆破', desc: '/login 出现高频失败尝试，来源集中', color: 'var(--km-soft-amber)' },
  { key: 'shadow_api', label: '影子API', desc: '未纳入清单的内部接口存在外部访问', color: 'var(--km-soft-violet)' },
  { key: 'zombie_api', label: '僵尸API', desc: '长期无调用的遗留接口，建议下线', color: 'var(--km-txt-2)' },
  { key: 'admin_exposure', label: '管理面暴露', desc: '管理接口可从公网访问', color: 'var(--km-soft-red)' },
  { key: 'plaintext_secret', label: '明文敏感参数', desc: 'URL 查询串中发现明文 token / 密码参数', color: 'var(--km-soft-amber)' },
]

const risks = ref([])
const scanning = ref(false)
const detailDlg = ref(false)
const detail = ref(null)

const riskCards = computed(() => {
  const open = risks.value.filter(r => r.status === 'open')
  return RISK_DEFS.map(def => ({
    name: def.key,
    label: def.label,
    desc: def.desc,
    color: def.color,
    count: open.filter(r => r.kind === def.key).length,
  }))
})
const openRisks = computed(() => risks.value.filter(r => r.status === 'open'))

const evidenceRows = computed(() => {
  const ev = detail.value?.evidence
  if (!ev || typeof ev !== 'object') return []
  return Object.entries(ev).map(([k, v]) => ({
    k,
    v: typeof v === 'object' ? JSON.stringify(v) : String(v),
  }))
})

function kindLabel(k) { return RISK_DEFS.find(d => d.key === k)?.label || k || '-' }
function levelLabel(s) { return { high: '高危', medium: '中危', low: '低危' }[s] || s }
function statusLabel(s) { return { open: '待处理', resolved: '已处理', ignored: '已忽略' }[s] || s }

function openRiskDetail(row) {
  detail.value = row
  detailDlg.value = true
}

function goAssetSite(site) {
  detailDlg.value = false
  tab.value = 'assets'
  fSite.value = site
  expanded.value = [site]
}

async function loadRisks() {
  try { const d = await api('/api/risks'); risks.value = d.risks || d || [] } catch (e) { /* module off */ }
}
async function scan() {
  scanning.value = true
  try { await post('/api/risks/scan'); ElMessage.success('扫描完成'); loadRisks() }
  catch (e) { ElMessage.error(e.message) }
  finally { scanning.value = false }
}
async function setStatus(row, status) {
  await post(`/api/risks/${row.id}/status`, { status })
  loadRisks()
}

// ============ 轮询 ============
let timer = null
onMounted(() => { loadAssets(); loadRisks(); timer = setInterval(() => { loadAssets(); loadRisks() }, 20000) })
onBeforeUnmount(() => clearInterval(timer))
</script>

<style scoped>
.km-ast-stats { display: flex; gap: 12px; margin-bottom: 12px; }
.km-ast-stats .stat { flex: 1; border: 1px solid var(--km-border, #dcdfe6); border-radius: 8px; padding: 10px 14px; }
.km-ast-stats .stat .n { font-size: 20px; font-weight: 600; font-family: ui-monospace, monospace; }
.km-ast-stats .stat .l { font-size: 12px; color: var(--km-text-secondary, #909399); }
.km-ast-stats .stat.warn .n { color: var(--km-warning, #e6a23c); }
.km-ast-stats .stat.danger .n { color: var(--km-danger, #f56c6c); }
.grp-head { display: flex; align-items: center; gap: 10px; width: 100%; padding-right: 8px; }
.grp-site { font-weight: 600; }
.grp-meta { font-size: 12px; color: var(--km-text-secondary, #909399); }
.grp-hits { font-size: 12px; margin-left: auto; }
.risk-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; }
.km-risk-card .rid { font-size: 11px; font-weight: 700; letter-spacing: 0.4px; }
.km-risk-card .rcount { font-size: 26px; font-weight: 700; margin: 2px 0; }
.km-risk-card .rdesc { font-size: 11.5px; color: var(--km-txt-3); line-height: 1.5; }
.tab-badge { margin-left: 6px; }
.tab-badge :deep(.el-badge__content) { position: static; transform: none; }
</style>
