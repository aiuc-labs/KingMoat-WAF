<template>
  <el-card shadow="never" style="margin-bottom:16px">
    <div class="km-title">自定义规则专家</div>
    <div class="km-dim" style="font-size:12px;margin:-6px 0 12px">
      粘贴漏洞通告或报告，由 AI 生成可追加在 CRS 之后的拦截规则；仅生成文本，不会自动写入下方编辑器、也不会自动发布。
    </div>

    <el-radio-group v-model="source" size="small" :disabled="!can('operator') || parsing || loading" style="margin-bottom:12px">
      <el-radio-button value="text">粘贴文本</el-radio-button>
      <el-radio-button value="file">上传文件</el-radio-button>
      <el-radio-button value="url">链接</el-radio-button>
      <el-radio-button value="table">表格</el-radio-button>
    </el-radio-group>

    <!-- ① 粘贴文本 -->
    <div v-if="source === 'text'">
      <el-input v-model="text" type="textarea" :rows="6" class="km-mono" spellcheck="false"
                placeholder="粘贴漏洞通告 / CVE 描述 / 安全报告正文…"
                :disabled="!can('operator') || loading" />
      <div class="km-muted" style="font-size:12px;margin-top:6px">已输入 {{ text.length }} 字</div>
    </div>

    <!-- ② 上传文件 -->
    <div v-else-if="source === 'file'">
      <input ref="fileInput" type="file" accept=".txt,.md,.html,.htm,.json,.pdf,.docx,.csv,.xlsx,.png,.jpg,.jpeg,.webp" style="display:none" @change="onPickFile" />
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <el-button size="small" :disabled="!can('operator') || parsing || loading" @click="fileInput && fileInput.click()">选择文件</el-button>
        <span v-if="file" class="km-dim" style="font-size:12px">{{ file.name }} · {{ sizeText(file.size) }}</span>
        <el-button v-if="file" link type="primary" size="small" :disabled="parsing || loading" @click="file = null">清除</el-button>
        <span v-else class="km-muted" style="font-size:12px">支持 .txt / .md / .html / .htm / .json / .pdf / .docx / .csv / .xlsx，单文件 ≤8MB</span>
      </div>
    </div>

    <!-- ③ 链接 -->
    <div v-else-if="source === 'url'">
      <el-input v-model="url" placeholder="https://vendor.example.com/advisory/CVE-2026-0001" class="km-mono"
                :disabled="!can('operator') || loading" />
      <div style="display:flex;align-items:center;gap:10px;margin-top:10px">
        <span class="km-dim" style="font-size:12.5px">允许访问内网地址</span>
        <el-switch v-model="requiresExternal" :disabled="!can('operator') || loading" />
      </div>
      <div class="km-muted" style="font-size:12px;margin-top:4px">
        默认只允许公网地址。开启后允许抓取内网/本机地址，存在 SSRF 风险，仅在确认该地址可信时开启。
      </div>
    </div>

    <!-- ④ 表格 -->
    <div v-else>
      <div class="km-dim" style="font-size:12px;margin-bottom:6px">
        从 Excel 直接复制粘贴（制表符分隔）或粘贴 CSV（逗号分隔，支持引号）；也可上传 .csv / .xlsx 由服务端解析
      </div>
      <el-input v-model="tableRaw" type="textarea" :rows="5" class="km-mono" spellcheck="false"
                placeholder="从 Excel 复制的多行数据，或 CSV 文本…"
                :disabled="!can('operator') || loading" />
      <div style="display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap">
        <input ref="tableFileInput" type="file" accept=".csv,.xlsx" style="display:none" @change="onPickTableFile" />
        <el-button size="small" :disabled="!can('operator') || parsing || loading" @click="tableFileInput && tableFileInput.click()">上传 .csv / .xlsx</el-button>
        <span v-if="tableFile" class="km-dim" style="font-size:12px">{{ tableFile.name }} · {{ sizeText(tableFile.size) }}</span>
        <el-button v-if="tableFile" link type="primary" size="small" :disabled="parsing || loading" @click="tableFile = null">清除</el-button>
        <span v-if="rows.length" class="km-muted" style="font-size:12px;margin-left:auto">共 {{ rows.length }} 行</span>
      </div>
      <el-alert v-if="tableTruncated" type="warning" :closable="false" style="margin-top:8px"
                title="表格超过 500 行，已截断至前 500 行" />
      <div v-if="rows.length" style="margin-top:10px;border:1px solid var(--km-line-soft);border-radius:6px;overflow:hidden">
        <el-table :data="rows" size="small" max-height="300">
          <el-table-column label="漏洞名称" min-width="140">
            <template #default="{ row }"><el-input v-model="row.name" size="small" :disabled="!can('operator') || loading" /></template>
          </el-table-column>
          <el-table-column label="编号" min-width="110">
            <template #default="{ row }"><el-input v-model="row.id" size="small" :disabled="!can('operator') || loading" /></template>
          </el-table-column>
          <el-table-column label="影响产品版本" min-width="140">
            <template #default="{ row }"><el-input v-model="row.product" size="small" :disabled="!can('operator') || loading" /></template>
          </el-table-column>
          <el-table-column label="描述" min-width="170">
            <template #default="{ row }"><el-input v-model="row.desc" size="small" :disabled="!can('operator') || loading" /></template>
          </el-table-column>
          <el-table-column label="修复建议" min-width="160">
            <template #default="{ row }"><el-input v-model="row.fix" size="small" :disabled="!can('operator') || loading" /></template>
          </el-table-column>
          <el-table-column label="操作" width="66">
            <template #default="{ $index }">
              <el-button link type="danger" size="small" :disabled="!can('operator') || loading" @click="rows.splice($index, 1)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <div style="padding:8px 10px;border-top:1px solid var(--km-line-soft)">
          <el-button size="small" :disabled="!can('operator') || loading" @click="addRow">添加一行</el-button>
          <span class="km-muted" style="font-size:12px;margin-left:8px">修改表格后请再次点击「解析并预览」刷新预览文本</span>
        </div>
      </div>
    </div>

    <div style="display:flex;align-items:center;gap:10px;margin-top:14px">
      <el-button :loading="parsing" :disabled="!can('operator') || loading || !canExtract" @click="extractNow">解析并预览</el-button>
      <el-button type="primary" :loading="loading" :disabled="!can('operator') || parsing || !previewText.trim()" @click="generate">
        生成拦截规则
      </el-button>
      <span v-if="!can('operator')" class="km-muted" style="font-size:12px">当前角色只读</span>
      <span v-else-if="!previewText.trim()" class="km-muted" style="font-size:12px">请先点击「解析并预览」，确认文本后再生成</span>
    </div>

    <!-- 待生成文本预览（可编辑） -->
    <div v-if="previewText" style="margin-top:16px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
        <div class="km-title" style="margin:0;font-size:13.5px">待生成文本预览（可编辑）</div>
        <span class="km-muted" style="font-size:12px;margin-left:auto">
          来源：{{ previewSource || '-' }}<template v-if="previewName"> · {{ previewName }}</template> · {{ previewText.length }} 字
        </span>
      </div>
      <el-input v-model="previewText" type="textarea" :rows="8" class="km-mono" spellcheck="false"
                :disabled="!can('operator') || loading" />
      <el-alert v-if="previewTruncated" type="warning" :closable="false" style="margin-top:8px"
                title="内容过长已截断，可手动补充关键信息" />
      <el-alert v-for="(w, i) in previewWarnings" :key="'w' + i" type="warning" :closable="false"
                :title="w" style="margin-top:8px" />
      <div class="km-muted" style="font-size:12px;margin-top:6px">生成时固定使用上方预览文本，审阅确认后再点击「生成拦截规则」</div>
    </div>

    <!-- 生成中/失败：常驻内联提示，避免只靠一闪而过的 toast -->
    <el-alert v-if="loading" type="info" :closable="false" style="margin-top:16px"
              title="正在生成规则，通常需要 30–90 秒（上游波动时会自动重试，最长约 3 分钟）" />
    <el-alert v-if="genErr" type="error" :closable="false" style="margin-top:16px"
              :title="'生成失败：' + genErr">
      <div style="margin-top:6px">
        <el-button size="small" type="primary" @click="generate">重试</el-button>
        <span class="km-muted" style="font-size:12px;margin-left:8px">若反复失败，多为模型上游不稳定，可稍后再试或改用其它模型</span>
      </div>
    </el-alert>

    <!-- 结果区 -->
    <div v-if="result" ref="resultRef" style="margin-top:16px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
        <div class="km-title" style="margin:0;font-size:13.5px">生成的拦截规则</div>
        <el-button size="small" style="margin-left:auto" @click="copyRule">复制</el-button>
      </div>
      <pre class="km-mono" style="white-space:pre-wrap;word-break:break-all;max-height:420px;overflow:auto;margin:0;padding:12px;border:1px solid var(--km-line-soft);border-radius:6px;background:var(--km-bg-2)">{{ result.rule }}</pre>
      <el-alert v-if="result.notes" type="info" :closable="false" title="生成说明" :description="result.notes" style="margin-top:10px" />
      <el-alert v-for="(w, i) in (result.warnings || [])" :key="'rw' + i" type="warning" :closable="false"
                title="预检提示" :description="w" style="margin-top:8px" />
      <div class="km-dim" style="font-size:12px;margin-top:10px;font-weight:500">
        请确认规则后再复制到下方编辑器；保存发布时服务端仍会做编译校验。
      </div>
      <div v-if="resultMeta" class="km-muted" style="font-size:12px;margin-top:4px">{{ resultMeta }}</div>
    </div>
  </el-card>
</template>

<script setup>
import { computed, nextTick, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { can, clearSession } from '../api'

const SOURCE_LABEL = { text: '粘贴文本', file: '上传文件', url: '链接', table: '表格' }
const FILE_EXTS = ['.txt', '.md', '.html', '.htm', '.json', '.pdf', '.docx', '.csv', '.xlsx', '.png', '.jpg', '.jpeg', '.webp']
const IMG_EXTS = ['.png', '.jpg', '.jpeg', '.webp']
const MAX_FILE = 8 * 1024 * 1024
const EXTRACT_TIMEOUT = 60000
const GENERATE_TIMEOUT = 220000
const MAX_ROWS = 500

const source = ref('text')
const text = ref('')
const file = ref(null)
const url = ref('')
const requiresExternal = ref(false)
const tableRaw = ref('')
const tableFile = ref(null)
const rows = ref([])
const tableTruncated = ref(false)

const previewText = ref('')
const previewSource = ref('')
const previewName = ref('')
const previewTruncated = ref(false)
const previewWarnings = ref([])

const parsing = ref(false)
const loading = ref(false)
const result = ref(null)
const genErr = ref('')
const resultRef = ref(null)

const fileInput = ref(null)
const tableFileInput = ref(null)

const canExtract = computed(() => {
  if (source.value === 'text') return !!text.value.trim()
  if (source.value === 'file') return !!file.value
  if (source.value === 'url') return !!url.value.trim()
  return !!(tableFile.value || tableRaw.value.trim())
})

const resultMeta = computed(() => {
  const r = result.value || {}
  const parts = []
  if (r.model) parts.push('模型：' + r.model)
  const rem = r.remaining || {}
  if (typeof rem.requests_today === 'number') parts.push('今日剩余请求：' + rem.requests_today)
  if (typeof rem.tokens_today === 'number') parts.push('今日剩余 Token：' + rem.tokens_today)
  const ex = r.extracted
  if (ex && ex.source_name) parts.push('来源：' + ex.source_name)
  return parts.join(' · ')
})

function sizeText(n) {
  const v = Number(n || 0)
  if (v >= 1024 * 1024) return (v / 1024 / 1024).toFixed(1) + ' MB'
  if (v >= 1024) return (v / 1024).toFixed(0) + ' KB'
  return v + ' B'
}

function validateFile(f) {
  const name = String(f.name || '')
  const dot = name.lastIndexOf('.')
  const ext = dot >= 0 ? name.slice(dot).toLowerCase() : ''
  if (ext === '.doc') {
    ElMessage.error('暂不支持旧版 .doc，请另存为 .docx')
    return false
  }
  if (!FILE_EXTS.includes(ext)) {
    ElMessage.error('不支持的文件类型：' + (ext || '未知') + '（支持 ' + FILE_EXTS.join(' / ') + '）')
    return false
  }
  if (f.size > MAX_FILE) {
    ElMessage.error('文件超过 8MB')
    return false
  }
  return true
}

function fileExtOf(f) {
  const name = String((f && f.name) || '')
  const dot = name.lastIndexOf('.')
  return dot >= 0 ? name.slice(dot).toLowerCase() : ''
}
const isImageFile = computed(() => source.value === 'file' && !!file.value && IMG_EXTS.includes(fileExtOf(file.value)))

function onPickFile(ev) {
  const f = ev.target.files && ev.target.files[0]
  ev.target.value = ''
  if (!f) return
  if (!validateFile(f)) return
  file.value = f
  result.value = null
  if (IMG_EXTS.includes(fileExtOf(f))) {
    previewText.value = ''
    previewSource.value = '图片（多模态直读）'
    previewName.value = f.name
    previewTruncated.value = false
    previewWarnings.value = []
  }
}

function onPickTableFile(ev) {
  const f = ev.target.files && ev.target.files[0]
  ev.target.value = ''
  if (!f) return
  const name = String(f.name || '').toLowerCase()
  if (!name.endsWith('.csv') && !name.endsWith('.xlsx')) {
    ElMessage.error('表格仅支持 .csv / .xlsx 文件')
    return
  }
  if (f.size > MAX_FILE) {
    ElMessage.error('文件超过 8MB')
    return
  }
  tableFile.value = f
  rows.value = []
  tableTruncated.value = false
}

// 逐行解析 TSV / CSV：制表符优先；CSV 支持双引号包裹与 "" 转义（不支持引号内换行）
function parseDelimited(raw) {
  const all = String(raw || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim()
  if (!all) return []
  const lines = all.split('\n').filter(l => l.trim() !== '')
  if (!lines.length) return []
  const delim = lines[0].includes('\t') ? '\t' : ','
  const out = []
  for (const line of lines) {
    if (delim === '\t') {
      out.push(line.split('\t').map(s => s.trim()))
      continue
    }
    const cells = []
    let cur = ''
    let quoted = false
    for (let i = 0; i < line.length; i++) {
      const ch = line[i]
      if (quoted) {
        if (ch === '"') {
          if (line[i + 1] === '"') { cur += '"'; i++ } else quoted = false
        } else cur += ch
      } else if (ch === '"') {
        quoted = true
      } else if (ch === ',') {
        cells.push(cur.trim())
        cur = ''
      } else cur += ch
    }
    cells.push(cur.trim())
    out.push(cells)
  }
  return out
}

const HEADER_HINTS = ['名称', '漏洞', '编号', 'cve', '产品', '版本', '描述', '修复', 'name', 'id', 'product', 'desc', 'fix']

function toRows(cells) {
  const list = cells.slice()
  if (list.length && list[0].some(c => HEADER_HINTS.includes(String(c || '').toLowerCase().trim()))) list.shift()
  return list.map(c => ({
    name: c[0] || '',
    id: c[1] || '',
    product: c[2] || '',
    desc: c[3] || '',
    fix: c[4] || '',
  }))
}

function addRow() {
  rows.value.push({ name: '', id: '', product: '', desc: '', fix: '' })
}

async function send(path, body, timeoutMs) {
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort(), timeoutMs)
  let r
  try {
    r = await fetch(path, { method: 'POST', credentials: 'same-origin', body, signal: ctl.signal })
  } catch (e) {
    const err = new Error('网络异常或超时，请稍后重试')
    err.network = true
    throw err
  } finally {
    clearTimeout(timer)
  }
  let j = null
  try { j = await r.json() } catch (e) { j = null }
  if (r.status === 401) {
    clearSession()
    location.hash = '#/login'
    throw new Error('未登录或会话已过期')
  }
  if (!r.ok) throw new Error((j && (j.message || j.error)) || ('请求失败（HTTP ' + r.status + '）'))
  return j || {}
}

async function extractNow() {
  if (!can('operator')) return
  if (source.value === 'text') {
    if (!text.value.trim()) return ElMessage.error('请粘贴漏洞通告正文')
    previewText.value = text.value
    previewSource.value = SOURCE_LABEL.text
    previewName.value = ''
    previewTruncated.value = false
    previewWarnings.value = []
    return
  }
  if (source.value === 'file' && isImageFile.value) {
    ElMessage.info('图片无需解析，直接点击「生成规则」由多模态模型识别')
    return
  }
  const fd = new FormData()
  fd.append('source_type', source.value)
  if (source.value === 'file') {
    if (!file.value) return ElMessage.error('请先选择文件')
    fd.append('file', file.value)
  } else if (source.value === 'url') {
    const u = url.value.trim()
    if (!/^https?:\/\//i.test(u)) return ElMessage.error('链接仅支持 http/https')
    if (u.length > 2048) return ElMessage.error('链接长度不能超过 2048')
    fd.append('url', u)
    fd.append('requires_external', requiresExternal.value ? 'true' : 'false')
  } else if (tableFile.value) {
    fd.append('file', tableFile.value)
  } else {
    const parsed = toRows(parseDelimited(tableRaw.value))
    if (!parsed.length) return ElMessage.error('请粘贴表格数据或上传 .csv / .xlsx 文件')
    tableTruncated.value = parsed.length > MAX_ROWS
    rows.value = parsed.slice(0, MAX_ROWS)
    if (tableTruncated.value) ElMessage.warning('表格超过 500 行，已截断至前 500 行')
    fd.append('rows_json', JSON.stringify(rows.value))
  }
  parsing.value = true
  try {
    const r = await send('/api/policy/rule-expert/extract', fd, EXTRACT_TIMEOUT)
    previewText.value = r.text || ''
    previewSource.value = SOURCE_LABEL[r.source_type] || SOURCE_LABEL[source.value]
    previewName.value = r.source_name || (file.value ? file.value.name : (tableFile.value ? tableFile.value.name : ''))
    previewTruncated.value = !!r.truncated
    previewWarnings.value = Array.isArray(r.warnings) ? r.warnings : []
    if (!previewText.value) ElMessage.warning('未解析出正文，请检查输入内容')
  } catch (e) {
    ElMessage.error(e.network ? '解析失败（网络或超时），请稍后重试' : (e.message || '解析失败'))
  } finally {
    parsing.value = false
  }
}

async function generate() {
  if (!can('operator')) return
  const fd = new FormData()
  if (source.value === 'file' && isImageFile.value) {
    fd.append('source_type', 'file')
    fd.append('file', file.value)
  } else {
    const body = previewText.value.trim()
    if (!body) return ElMessage.error('待生成文本为空，请先解析或粘贴内容')
    fd.append('source_type', 'text')
    fd.append('text', body)
  }
  loading.value = true
  genErr.value = ''
  result.value = null
  try {
    result.value = await send('/api/policy/rule-expert', fd, GENERATE_TIMEOUT)
    ElMessage.success('规则已生成，见下方「生成的拦截规则」')
    await nextTick()
    if (resultRef.value && resultRef.value.scrollIntoView) {
      resultRef.value.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  } catch (e) {
    const msg = e.network ? '网络异常或超时（已等待 220 秒），请稍后重试' : (e.message || '生成失败')
    genErr.value = msg
    ElMessage.error('生成失败：' + msg)
  } finally {
    loading.value = false
  }
}

async function copyRule() {
  const v = (result.value && result.value.rule) || ''
  if (!v) return
  try {
    if (!(navigator.clipboard && navigator.clipboard.writeText)) throw new Error('clipboard unavailable')
    await navigator.clipboard.writeText(v)
    ElMessage.success('规则已复制')
    return
  } catch (e) { /* 回退到 execCommand */ }
  try {
    const ta = document.createElement('textarea')
    ta.value = v
    ta.style.position = 'fixed'
    ta.style.top = '0'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    if (!ok) throw new Error('copy failed')
    ElMessage.success('规则已复制')
  } catch (e) {
    ElMessage.error('复制失败，请手动选中复制')
  }
}
</script>