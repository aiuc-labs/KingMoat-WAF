<template>
  <div>
    <el-alert v-if="!enabled" type="info" :closable="false" show-icon style="margin-bottom:12px"
      title="AI 会话审计未启用"
      description="未启用 AI 会话审计。在「系统设置 → AI 会话审计」开启捕获后，经过本机的 LLM API 调用（OpenAI / Anthropic / Gemini 及国产协议）会被识别并记录会话全文，此处即可检索与查看。" />

    <div class="km-toolbar" v-if="enabled">
      <el-select v-model="fProvider" size="small" style="width:150px" clearable placeholder="协议">
        <el-option label="OpenAI" value="openai" />
        <el-option label="Anthropic" value="anthropic" />
        <el-option label="Gemini" value="gemini" />
        <el-option label="未知" value="unknown" />
      </el-select>
      <el-input v-model="fSite" size="small" style="width:170px" placeholder="站点域名" clearable />
      <el-input v-model="fText" size="small" style="width:260px" placeholder="IP / 路径 / 模型 / 内容关键字" clearable @keyup.enter="load" @clear="load" />
      <div class="grow"></div>
      <span class="km-muted" style="font-size:12px">共 {{ total.toLocaleString() }} 条会话</span>
      <el-button size="small" @click="load" :loading="loading">刷新</el-button>
    </div>

    <el-card shadow="never" :body-style="{ padding: 0 }">
      <el-table :data="items" size="small" @row-click="openDetail" style="cursor:pointer" v-loading="loading">
        <el-table-column label="时间" width="165">
          <template #default="{ row }">{{ fmtTime(row.ts) }}</template>
        </el-table-column>
        <el-table-column prop="site" label="站点" width="150" show-overflow-tooltip />
        <el-table-column prop="client_ip" label="来源" width="130">
          <template #default="{ row }"><span class="km-mono" style="color:var(--km-soft-blue)">{{ row.client_ip }}</span></template>
        </el-table-column>
        <el-table-column label="协议" width="100">
          <template #default="{ row }">
            <el-tag size="small" effect="plain" class="km-tag" :type="providerType(row.provider)">{{ providerLabel(row.provider) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="operation" label="操作" width="110" show-overflow-tooltip class-name="km-mono" />
        <el-table-column prop="model" label="模型" width="150" show-overflow-tooltip class-name="km-mono" />
        <el-table-column prop="path" label="路径" show-overflow-tooltip class-name="km-mono" />
        <el-table-column prop="status" label="状态" width="74">
          <template #default="{ row }">
            <el-tag size="small" :type="row.status >= 400 ? 'danger' : row.status >= 300 ? 'warning' : 'success'" effect="plain" class="km-tag">{{ row.status || '-' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="耗时" width="84">
          <template #default="{ row }"><span class="km-mono km-dim">{{ row.duration_ms ?? '-' }} ms</span></template>
        </el-table-column>
        <el-table-column label="标记" width="120">
          <template #default="{ row }">
            <el-tag v-if="row.interrupted" size="small" type="warning" effect="plain" class="km-tag">中断</el-tag>
            <el-tag v-if="row.trunc_in || row.trunc_out" size="small" type="info" effect="plain" class="km-tag">截断</el-tag>
          </template>
        </el-table-column>
      </el-table>
      <div style="display:flex;justify-content:flex-end;padding:10px 12px">
        <el-pagination small background layout="prev, pager, next, total" :total="total"
          :page-size="pageSize" :current-page="page" @current-change="p => { page = p; load() }" />
      </div>
    </el-card>

    <el-drawer v-model="detail" size="46%" :title="detailRec ? `${providerLabel(detailRec.provider)} · ${detailRec.model || '(未识别模型)'}` : ''">
      <div v-if="detailRec" style="display:flex;flex-direction:column;gap:12px">
        <el-descriptions :column="2" size="small" border>
          <el-descriptions-item label="时间">{{ fmtTime(detailRec.ts) }}</el-descriptions-item>
          <el-descriptions-item label="耗时">{{ detailRec.duration_ms ?? '-' }} ms</el-descriptions-item>
          <el-descriptions-item label="站点">{{ detailRec.site || '-' }}</el-descriptions-item>
          <el-descriptions-item label="来源 IP">{{ detailRec.client_ip || '-' }}</el-descriptions-item>
          <el-descriptions-item label="节点">{{ detailRec.node_id || '-' }}</el-descriptions-item>
          <el-descriptions-item label="Trace">
            <span class="km-mono">{{ detailRec.trace_id || '-' }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="路径"><span class="km-mono">{{ detailRec.method }} {{ detailRec.path }}</span></el-descriptions-item>
          <el-descriptions-item label="状态">{{ detailRec.status || '-' }}</el-descriptions-item>
          <el-descriptions-item label="Tokens" v-if="detailRec.usage">
            prompt {{ detailRec.usage.prompt_tokens }} / completion {{ detailRec.usage.completion_tokens }} / total {{ detailRec.usage.total_tokens }}
          </el-descriptions-item>
          <el-descriptions-item label="请求/响应字节">
            {{ detailRec.req_bytes ?? 0 }} / {{ detailRec.resp_bytes ?? 0 }}
          </el-descriptions-item>
        </el-descriptions>

        <el-alert v-if="detailRec.err" type="error" :closable="false" show-icon :title="detailRec.err" />
        <el-alert v-if="detailRec.interrupted" type="warning" :closable="false" show-icon title="该会话未正常结束（客户端中断或流挂起超时）" />
        <el-alert v-if="detailRec.trunc_in || detailRec.trunc_out" type="info" :closable="false" show-icon
          title="内容超出捕获上限被截断（trunc 标记）" />

        <div>
          <div class="km-muted" style="font-size:12px;margin-bottom:6px">请求报文</div>
          <div v-if="detailRec.request && detailRec.request.system" class="km-audit-block">
            <div class="km-audit-role">system</div>
            <pre class="km-audit-pre">{{ detailRec.request.system }}</pre>
          </div>
          <div v-for="(m, i) in requestMessages" :key="i" class="km-audit-block">
            <div class="km-audit-role">{{ m.role || 'message' }}</div>
            <pre class="km-audit-pre">{{ m.content || '(空 / 非文本内容)' }}</pre>
          </div>
          <div v-if="detailRec.request && detailRec.request.raw" class="km-audit-block">
            <div class="km-audit-role">raw</div>
            <pre class="km-audit-pre">{{ detailRec.request.raw }}</pre>
          </div>
          <div v-if="!requestMessages.length && !(detailRec.request && (detailRec.request.system || detailRec.request.raw))" class="km-muted" style="font-size:12px">
            （请求内容未捕获：body 未缓冲或命中采样丢弃）
          </div>
        </div>

        <div>
          <div class="km-muted" style="font-size:12px;margin-bottom:6px">模型输出</div>
          <pre v-if="detailRec.response && detailRec.response.text" class="km-audit-pre km-audit-out">{{ detailRec.response.text }}</pre>
          <div v-else class="km-muted" style="font-size:12px">（无输出文本：错误响应 / 非文本输出 / 未捕获）</div>
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api } from '../api'
import { fmtTime } from '../timefmt'

const enabled = ref(false)
const total = ref(0)
const items = ref([])
const loading = ref(false)
const fProvider = ref('')
const fSite = ref('')
const fText = ref('')
const page = ref(1)
const pageSize = 50
const detail = ref(false)
const detailRec = ref(null)
let reloadTimer = null

// search triggers: provider dropdown reloads immediately; site/keyword
// debounce 300ms and reset to page 1 (offset would go stale otherwise)
watch([fProvider], () => { page.value = 1; load() })
watch([fSite, fText], () => {
	clearTimeout(reloadTimer)
	reloadTimer = setTimeout(() => { page.value = 1; load() }, 300)
})
onBeforeUnmount(() => clearTimeout(reloadTimer))

const requestMessages = computed(() => {
  const rq = detailRec.value && detailRec.value.request
  if (!rq) return []
  if (Array.isArray(rq.messages)) return rq.messages
  try {
    const m = typeof rq.messages === 'string' ? JSON.parse(rq.messages) : null
    return Array.isArray(m) ? m : []
  } catch { return [] }
})

function providerLabel(p) {
  return { openai: 'OpenAI', anthropic: 'Anthropic', gemini: 'Gemini', unknown: '未知' }[p] || p || '-'
}
function providerType(p) {
  return { openai: 'success', anthropic: 'warning', gemini: 'primary', unknown: 'info' }[p] || 'info'
}

async function load() {
  loading.value = true
  try {
    const params = new URLSearchParams()
    if (fProvider.value) params.set('provider', fProvider.value)
    if (fSite.value) params.set('site', fSite.value)
    if (fText.value) params.set('q', fText.value)
    params.set('limit', String(pageSize))
    params.set('offset', String((page.value - 1) * pageSize))
    const data = await api(`/api/ai_sessions?${params.toString()}`)
    enabled.value = !!data.enabled
    items.value = data.items || []
    total.value = data.total || 0
  } finally {
    loading.value = false
  }
}

function openDetail(row) {
  detailRec.value = row
  detail.value = true
}

onMounted(load)
</script>

<style scoped>
.km-audit-block { margin-bottom: 8px; border: 1px solid var(--km-border, #dcdfe6); border-radius: 6px; overflow: hidden; }
.km-audit-role { font-size: 11px; font-weight: 600; padding: 3px 8px; background: var(--km-fill, #f5f7fa); color: var(--km-text-secondary, #606266); }
.km-audit-pre { margin: 0; padding: 8px 10px; font-size: 12px; white-space: pre-wrap; word-break: break-word; max-height: 260px; overflow-y: auto; font-family: ui-monospace, monospace; }
.km-audit-out { border: 1px solid var(--km-border, #dcdfe6); border-radius: 6px; }
</style>
