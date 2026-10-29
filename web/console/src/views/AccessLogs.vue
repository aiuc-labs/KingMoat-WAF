<template>
  <div>
    <!-- 本地记录状态行：数据来自 /api/access_logs 响应的 record 对象（与内存尾同源轮询刷新）。
         三种形态：开启（含留存条数/最早记录/淘汰/丢弃明细）· 关闭但本地仍有残留（明示数据未清空并给清理入口）·
         未开启且空库。「立即清空」仅 admin 可见（can('admin')，与 Settings/Certs 等页面同机制）。 -->
    <div class="km-al-recbar">
      <span class="km-dot" :class="record.enabled ? 'ok' : 'off'"></span>
      <template v-if="record.enabled">
        <span class="km-dim" style="font-size:12px;line-height:1.8">
          本地记录已开启 · {{ recordModeLabel }} · 保留 {{ record.retention_days }} 天 · 容量上限 {{ (Number(record.max_disk_mb) || 0).toLocaleString() }} MB · 当前占用 {{ sizeLabel }} · 留存 {{ (Number(record.rows) || 0).toLocaleString() }} 条 · 最早记录 {{ oldestLabel }}<template v-if="record.evicted > 0"> · <span style="color:var(--km-orange,#e6a23c)">已按容量淘汰 {{ Number(record.evicted).toLocaleString() }} 条（最早记录可能短于保留天数）</span></template><template v-if="record.dropped > 0"> · <span class="km-al-dropped">已丢弃 {{ Number(record.dropped).toLocaleString() }} 条：高负载下写入队列已满，有访问日志未入库</span></template>
        </span>
      </template>
      <template v-else-if="record.rows > 0">
        <span class="km-dim" style="font-size:12px;line-height:1.8">
          已停止记录：本地仍保留 {{ (Number(record.rows) || 0).toLocaleString() }} 条<template v-if="record.oldest_ts">（最早 {{ fmtTime(record.oldest_ts) }}）</template>——停止记录后已留存数据不会自动按期清除（重新开启记录后恢复按期清理），这些残留数据仍可在下方「本地历史」视图只读检索<template v-if="can('admin')">；如需立即清空并回收磁盘空间请点击右侧「立即清空」（不可恢复）</template><template v-else>；如需立即清空请联系管理员</template>
        </span>
      </template>
      <template v-else>
        <span class="km-dim" style="font-size:12px;line-height:1.8">
          本地记录未开启（默认关闭）：在「系统设置 → 通用设置 → 访问日志配置」开启后，访问日志将在本机留存并可在此查历史（独立于日志外发，未配置外发也会留存）
        </span>
      </template>
      <el-button v-if="can('admin') && (record.enabled || record.rows > 0)" size="small" type="danger" plain
                 :loading="purging" style="margin-left:auto;flex:none" @click="confirmPurge">立即清空</el-button>
    </div>

    <el-alert v-if="!enabled" type="info" :closable="false" show-icon style="margin-bottom:12px"
    title="实时访问日志未启用"
    description="在「系统设置 → 日志外发 → 全量访问日志」开启后，可在此实时查看内存尾（约 5000 条、重启即清）；如需长期留存，可在「系统设置 → 通用设置 → 访问日志配置」开启本地记录（独立于外发，开启后可在「本地历史」视图查询）。" />
    <el-alert v-if="enabled && hint" type="warning" :closable="false" show-icon style="margin-bottom:12px" :title="hint" />
    <el-alert v-if="hError" type="error" :closable="false" show-icon style="margin-bottom:12px" :title="'历史查询失败'" :description="hError" />
    <!-- 记录已停止但本地有残留：后端对已关记录回落磁盘只读查询，本地历史仍可用，给明确只读提示 -->
    <el-alert v-if="viewMode === 'history' && !record.enabled && record.rows > 0" type="info" :closable="false" show-icon style="margin-bottom:12px"
              title="记录已停止：以下为本地残留的历史数据（只读），停止记录期间不自动按期清理（重新开启记录后恢复按期清理）" />

    <!-- 视图切换 + 筛选工具栏：实时尾（内存）/ 本地历史（access_log_record 落库数据） -->
    <div class="km-toolbar" v-if="enabled || record.enabled || record.rows > 0">
      <el-radio-group v-model="viewMode" size="small">
        <el-radio-button value="live">实时尾（内存）</el-radio-button>
        <el-radio-button value="history" :disabled="!record.enabled && !(record.rows > 0)">本地历史</el-radio-button>
      </el-radio-group>

      <template v-if="viewMode === 'live'">
        <el-select v-model="fOutcome" size="small" style="width:150px" clearable placeholder="结果">
          <el-option label="转发 forwarded" value="forwarded" />
          <el-option label="拦截 blocked" value="blocked" />
          <el-option label="挑战 challenged" value="challenged" />
          <el-option label="观察放行 monitor_forwarded" value="monitor_forwarded" />
          <el-option label="跳转 redirected" value="redirected" />
        </el-select>
        <el-input v-model="fSite" size="small" style="width:170px" placeholder="站点过滤" clearable />
        <el-input v-model="fTrace" size="small" style="width:170px" placeholder="Trace ID" clearable class="km-mono" />
        <el-input v-model="fText" size="small" style="width:240px" placeholder="过滤 IP / 路径 / UA / 规则…" clearable />
        <div class="grow"></div>
        <span class="km-muted" style="font-size:12px">内存尾 {{ count.toLocaleString() }} 条 · 5s 自动刷新</span>
      </template>

      <template v-else>
        <el-input v-model="hSite" size="small" style="width:160px" placeholder="站点（包含匹配）" clearable />
        <el-select v-model="hOutcome" size="small" style="width:150px" clearable placeholder="结果">
          <el-option label="转发 forwarded" value="forwarded" />
          <el-option label="拦截 blocked" value="blocked" />
          <el-option label="挑战 challenged" value="challenged" />
          <el-option label="观察放行 monitor_forwarded" value="monitor_forwarded" />
          <el-option label="跳转 redirected" value="redirected" />
        </el-select>
        <el-input v-model="hIp" size="small" style="width:150px" placeholder="来源 IP（前缀）" clearable class="km-mono" />
        <el-input v-model="hText" size="small" style="width:220px" placeholder="路径 / UA / 规则 / Trace…" clearable />
        <el-date-picker v-model="hRange" type="datetimerange" size="small" style="width:330px"
                        start-placeholder="开始时间" end-placeholder="结束时间" />
        <el-button size="small" type="primary" plain :loading="hLoading" @click="hPage = 1; loadHistory()">查询</el-button>
        <div class="grow"></div>
        <span class="km-muted" style="font-size:12px">共 {{ hTotal.toLocaleString() }} 条 · 本地留存库</span>
      </template>
    </div>

    <!-- 实时尾视图（既有能力保留）：内存环形缓冲，结果集内过滤 -->
    <el-card shadow="never" :body-style="{ padding: 0 }" v-if="viewMode === 'live'">
      <el-table :data="viewItems" size="small" style="cursor:pointer" @row-click="openDetail">
        <el-table-column label="时间" width="165">
          <template #default="{ row }">{{ fmtTime(row.ts) }}</template>
        </el-table-column>
        <el-table-column prop="site" label="站点" width="150" show-overflow-tooltip />
        <el-table-column prop="client_ip" label="来源" width="130">
          <template #default="{ row }"><span class="km-mono" style="color:var(--km-soft-blue)">{{ row.client_ip }}</span></template>
        </el-table-column>
        <el-table-column prop="method" label="方法" width="66" class-name="km-mono" />
        <el-table-column label="路径" show-overflow-tooltip class-name="km-mono">
          <template #default="{ row }">{{ row.path }}<template v-if="row.query">?{{ row.query }}</template></template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="74">
          <template #default="{ row }">
            <el-tag size="small" :type="row.status >= 400 ? 'danger' : row.status >= 300 ? 'warning' : 'success'" effect="plain" class="km-tag">{{ row.status || '-' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="时延" width="84">
          <template #default="{ row }"><span class="km-mono km-dim">{{ row.latency_ms ?? '-' }} ms</span></template>
        </el-table-column>
        <el-table-column label="结果" width="140">
          <template #default="{ row }">
            <el-tag size="small" effect="dark" :type="outcomeType(row.outcome)" class="km-tag">{{ outcomeLabel(row.outcome) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="rule" label="命中规则" width="150" show-overflow-tooltip class-name="km-mono" />
        <template #empty><span class="km-muted" style="font-size:12px">实时管道未启用或暂无请求记录</span></template>
      </el-table>
    </el-card>

    <!-- 本地历史视图：/api/access_logs/history 分页检索（服务端过滤 + 分页） -->
    <el-card shadow="never" :body-style="{ padding: 0 }" v-else>
      <el-table v-loading="hLoading" :data="hItems" size="small" style="cursor:pointer" @row-click="openDetail">
        <el-table-column label="时间" width="165">
          <template #default="{ row }">{{ fmtTime(row.ts) }}</template>
        </el-table-column>
        <el-table-column prop="site" label="站点" width="150" show-overflow-tooltip />
        <el-table-column prop="client_ip" label="来源" width="130">
          <template #default="{ row }"><span class="km-mono" style="color:var(--km-soft-blue)">{{ row.client_ip }}</span></template>
        </el-table-column>
        <el-table-column prop="method" label="方法" width="66" class-name="km-mono" />
        <el-table-column label="路径" show-overflow-tooltip class-name="km-mono">
          <template #default="{ row }">{{ row.path }}<template v-if="row.query">?{{ row.query }}</template></template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="74">
          <template #default="{ row }">
            <el-tag size="small" :type="row.status >= 400 ? 'danger' : row.status >= 300 ? 'warning' : 'success'" effect="plain" class="km-tag">{{ row.status || '-' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="时延" width="84">
          <template #default="{ row }"><span class="km-mono km-dim">{{ row.latency_ms ?? '-' }} ms</span></template>
        </el-table-column>
        <el-table-column label="结果" width="140">
          <template #default="{ row }">
            <el-tag size="small" effect="dark" :type="outcomeType(row.outcome)" class="km-tag">{{ outcomeLabel(row.outcome) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="rule" label="命中规则" width="150" show-overflow-tooltip class-name="km-mono" />
        <template #empty><span class="km-muted" style="font-size:12px">无匹配的历史记录：可调整筛选条件或时间范围；确认本地记录已开启且站点在记录范围内</span></template>
      </el-table>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:12px 16px">
        <span class="km-muted" style="font-size:12px">显示 {{ hItems.length }} 条 / 共 {{ hTotal.toLocaleString() }} 条</span>
        <el-pagination layout="prev, pager, next, sizes" :total="hTotal" :page-size="hPageSize" :current-page="hPage"
                       :page-sizes="[20, 50, 100, 200]" @current-change="p => { hPage = p; loadHistory() }"
                       @size-change="s => { hPageSize = s; hPage = 1; loadHistory() }" />
      </div>
    </el-card>

    <el-drawer v-model="detail" size="42%" :title="detailRec ? `${detailRec.method} ${detailRec.path}` : '请求详情'">
      <div v-if="detailRec" style="display:flex;flex-direction:column;gap:12px">
        <el-descriptions :column="2" size="small" border>
          <el-descriptions-item label="时间">{{ fmtTime(detailRec.ts) }}</el-descriptions-item>
          <el-descriptions-item label="结果">
            <el-tag size="small" effect="dark" :type="outcomeType(detailRec.outcome)" class="km-tag">{{ outcomeLabel(detailRec.outcome) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="站点">{{ detailRec.site || '-' }}</el-descriptions-item>
          <el-descriptions-item label="来源 IP"><span class="km-mono">{{ detailRec.client_ip || '-' }}</span></el-descriptions-item>
          <el-descriptions-item label="请求"><span class="km-mono">{{ detailRec.method }} {{ detailRec.path }}</span></el-descriptions-item>
          <el-descriptions-item label="Query"><span class="km-mono" style="word-break:break-all">{{ detailRec.query || '-' }}</span></el-descriptions-item>
          <el-descriptions-item label="响应状态">
            <el-tag size="small" :type="detailRec.status >= 400 ? 'danger' : detailRec.status >= 300 ? 'warning' : 'success'" effect="plain" class="km-tag">{{ detailRec.status || '-' }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="耗时"><span class="km-mono">{{ detailRec.latency_ms ?? '-' }} ms</span></el-descriptions-item>
          <el-descriptions-item label="响应字节"><span class="km-mono">{{ detailRec.bytes ?? '-' }}</span></el-descriptions-item>
          <el-descriptions-item label="Trace ID"><span class="km-mono">{{ detailRec.trace_id || '-' }}</span></el-descriptions-item>
          <el-descriptions-item label="命中规则" v-if="detailRec.rule"><span class="km-mono">{{ detailRec.rule }}</span></el-descriptions-item>
          <el-descriptions-item label="攻击类型" v-if="detailRec.attack_type">
            <el-tag size="small" type="danger" effect="dark" class="km-tag">{{ detailRec.attack_type }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="请求体检测" v-if="detailRec.body_skip">
            <el-tag size="small" type="warning" effect="plain" class="km-tag">{{ detailRec.body_skip === 'prefix' ? '仅前缀（超限深检前缀后放行）' : '跳过（超限流式透传，仅头部阶段检测）' }}</el-tag>
          </el-descriptions-item>
        </el-descriptions>
        <div v-if="detailRec.user_agent">
          <div class="km-muted" style="font-size:12px;margin-bottom:6px">User-Agent</div>
          <pre class="km-al-pre">{{ detailRec.user_agent }}</pre>
        </div>
        <el-collapse>
          <el-collapse-item title="原始 JSON" name="raw">
            <pre class="km-al-pre">{{ JSON.stringify(detailRec, null, 2) }}</pre>
          </el-collapse-item>
        </el-collapse>
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, can, post } from '../api'
import { fmtRFC3339, fmtTime } from '../timefmt'

// 本地记录状态（access_log_record）：来自 /api/access_logs 与 /api/access_logs/history
// 响应的 record 对象；老后端无该字段时保持默认值，页面行为不回归
const record = ref({ enabled: false, mode: 'off', retention_days: 7, max_disk_mb: 1024, size_bytes: 0, evicted: 0, rows: 0, oldest_ts: '', dropped: 0 })
const enabled = ref(false)
const count = ref(0)
const hint = ref('')
const items = ref([])
const fOutcome = ref('')
const fSite = ref('')
const fText = ref('')
const fTrace = ref('')
let timer = null
let reloadTimer = null

// ---- 视图切换：实时尾 / 本地历史 ----
const viewMode = ref('live')
watch([enabled, () => record.value.enabled], ([en, recOn]) => {
  // 记录已停止但本地仍有残留（rows>0）时历史视图保持可用（后端回落磁盘只读查询）
  if (!recOn && !(record.value.rows > 0)) { if (viewMode.value === 'history') viewMode.value = 'live'; return }
  if (!en && viewMode.value === 'live') viewMode.value = 'history'
}, { immediate: true })
watch(viewMode, v => { if (v === 'history') loadHistory() })

const recordModeLabel = computed(() =>
  ({ off: '关闭', all: '全部站点', sites: '指定站点' }[record.value.mode] || record.value.mode))
const sizeLabel = computed(() => {
  const b = Number(record.value.size_bytes) || 0
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB'
  if (b >= 1024) return (b / 1024).toFixed(0) + ' KB'
  return b + ' B'
})
// 最早记录展示：空库（rows=0）时后端省略 oldest_ts 键
const oldestLabel = computed(() => (record.value.oldest_ts ? fmtTime(record.value.oldest_ts) : '暂无'))

// 站点/全文为当前结果集内过滤(内存尾本身有限)
const viewItems = computed(() => items.value.filter(e =>
  (!fSite.value || (e.site || '').includes(fSite.value)) &&
  (!fOutcome.value || e.outcome === fOutcome.value) &&
  (!fTrace.value || (e.trace_id || '').toLowerCase().includes(fTrace.value.toLowerCase())) &&
  (!fText.value || [e.path, e.user_agent, e.client_ip, e.rule].some(v => (v || '').toLowerCase().includes(fText.value.toLowerCase())))))

function outcomeType(o) {
  return { blocked: 'danger', challenged: 'warning', redirected: 'primary' }[o] || 'info'
}
function outcomeLabel(o) {
  return { forwarded: '转发', blocked: '拦截', challenged: '挑战', monitor_forwarded: '观察放行', redirected: '跳转' }[o] || o || '-'
}

const detail = ref(false)
const detailRec = ref(null)
function openDetail(row) {
  detailRec.value = row
  detail.value = true
}

// ---- 内存尾（既有能力保留）：5s 轮询，响应同时刷新 record 状态 ----
async function load() {
  try {
    const p = new URLSearchParams()
    p.set('limit', '500')
    if (fOutcome.value) p.set('outcome', fOutcome.value)
    const d = await api('/api/access_logs?' + p.toString())
    enabled.value = !!d.enabled
    count.value = d.count || 0
    hint.value = d.hint || ''
    items.value = d.items || []
    if (d.record && typeof d.record === 'object') record.value = { ...record.value, ...d.record }
  } catch (e) { /* 401 handled in api() */ }
}

watch([fOutcome], () => load())
watch([fSite, fText], () => { clearTimeout(reloadTimer); reloadTimer = setTimeout(load, 300) })

// ---- 本地历史（access_log_record）：/api/access_logs/history，服务端过滤 + 分页 ----
const hItems = ref([])
const hTotal = ref(0)
const hPage = ref(1)
const hPageSize = ref(50)
const hSite = ref('')
const hOutcome = ref('')
const hIp = ref('')
const hText = ref('')
const hRange = ref(null)
const hLoading = ref(false)
const hError = ref('')
let hReloadTimer = null

async function loadHistory() {
  // 已停止记录但仍有残留（rows>0）时同样允许查询：后端回落磁盘只读，参数与响应形态一致
  if (!record.value.enabled && !(record.value.rows > 0)) return
  hLoading.value = true
  hError.value = ''
  try {
    const p = new URLSearchParams()
    p.set('page', String(hPage.value))
    p.set('page_size', String(hPageSize.value))
    if (hSite.value) p.set('site', hSite.value)
    if (hOutcome.value) p.set('outcome', hOutcome.value)
    if (hIp.value) p.set('ip', hIp.value)
    if (hText.value) p.set('q', hText.value)
    if (hRange.value && hRange.value[0] && hRange.value[1]) {
      p.set('since', fmtRFC3339(new Date(hRange.value[0])))
      p.set('until', fmtRFC3339(new Date(hRange.value[1])))
    }
    const d = await api('/api/access_logs/history?' + p.toString())
    hItems.value = d.items || []
    hTotal.value = d.total || 0
    if (d.record && typeof d.record === 'object') record.value = { ...record.value, ...d.record }
  } catch (e) {
    hError.value = e.message || '查询失败，请稍后重试'
  } finally {
    hLoading.value = false
  }
}

watch(hOutcome, () => { hPage.value = 1; if (viewMode.value === 'history') loadHistory() })
watch(hRange, () => { hPage.value = 1; if (viewMode.value === 'history') loadHistory() })
watch([hSite, hIp, hText], () => {
  clearTimeout(hReloadTimer)
  hReloadTimer = setTimeout(() => { hPage.value = 1; if (viewMode.value === 'history') loadHistory() }, 300)
})

// ---- 立即清空（admin 专属）：POST /api/access_logs/purge，破坏性操作需二次确认 ----
// 成功后用响应里的 record 立即刷新状态行；purged>0 但 VACUUM 失败时后端附 warning，需如实提示。
const purging = ref(false)
async function confirmPurge() {
  try {
    await ElMessageBox.confirm(
      '将删除本地留存的全部访问日志（当前 ' + (Number(record.value.rows) || 0).toLocaleString() + ' 条），不可恢复，且会回收磁盘空间。确定继续？',
      '立即清空本地访问日志',
      { type: 'warning', confirmButtonText: '清空', cancelButtonText: '取消' }
    )
  } catch { return }
  purging.value = true
  try {
    const d = await post('/api/access_logs/purge')
    if (d.record && typeof d.record === 'object') record.value = { ...record.value, ...d.record }
    const n = (Number(d.purged) || 0).toLocaleString()
    if (d.warning) ElMessage.warning('已清空 ' + n + ' 条本地访问日志，但磁盘空间回收失败：' + d.warning)
    else ElMessage.success('已清空 ' + n + ' 条本地访问日志')
    if (viewMode.value === 'history') loadHistory()
  } catch (e) {
    ElMessage.error('清空失败：' + (e.message || '未知错误'))
  } finally {
    purging.value = false
  }
}

onMounted(() => { load(); timer = setInterval(load, 5000) })
onBeforeUnmount(() => { clearInterval(timer); clearTimeout(reloadTimer); clearTimeout(hReloadTimer) })
</script>

<style scoped>
.km-al-pre { margin: 0; padding: 8px 10px; font-size: 12px; white-space: pre-wrap; word-break: break-word; border: 1px solid var(--km-border, #dcdfe6); border-radius: 6px; font-family: ui-monospace, monospace; background: var(--km-fill, #f5f7fa); }
.km-al-recbar { display: flex; align-items: center; gap: 8px; padding: 8px 12px; margin-bottom: 12px; border: 1px solid var(--km-border, #dcdfe6); border-radius: 6px; background: var(--km-fill, #f5f7fa); }
.km-dot { width: 8px; height: 8px; border-radius: 50%; flex: none; }
.km-dot.ok { background: var(--km-green, #67c23a); box-shadow: 0 0 0 3px rgba(103, 194, 58, .15); }
.km-dot.off { background: var(--km-txt-3, #909399); opacity: .5; }
.km-al-dropped { color: var(--km-red, #f56c6c); font-weight: 600; }
</style>
