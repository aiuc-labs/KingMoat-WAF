<template>
  <el-container style="height:100vh">
    <el-aside width="224px" class="km-side">
      <div class="brand" @click="$router.push('/')">
        <div>
          <div class="name">King<span>Moat</span> WAF</div>
          <div class="slogan">固若金汤 · 御攻于无形</div>
        </div>
      </div>
      <div class="km-nav">
        <div class="km-menu-group">总览</div>
        <div class="km-nav-item" :class="{ active: $route.path === '/' }" @click="$router.push('/')">
          <el-icon><Odometer /></el-icon>防护总览
        </div>
        <template v-if="can('operator')">
          <div class="km-menu-group">防护</div>
          <div class="km-nav-item" :class="{ active: $route.path === '/sites' }" @click="$router.push('/sites')">
            <el-icon><Umbrella /></el-icon>站点防护
          </div>
          <div class="km-nav-item" :class="{ active: $route.path === '/policy' }" @click="$router.push('/policy')">
            <el-icon><Aim /></el-icon>策略管理
          </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/logs' }" @click="$router.push('/logs')">
          <el-icon><Document /></el-icon>攻击日志
          <span v-if="badge.blocked > 0" class="km-nav-badge">{{ blockedLabel }}</span>
        </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/access-logs' }" @click="$router.push('/access-logs')">
          <el-icon><Notebook /></el-icon>访问日志
        </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/ai-sessions' }" @click="$router.push('/ai-sessions')">
          <el-icon><ChatDotRound /></el-icon>AI 会话审计
        </div>
        </template>
        <div class="km-menu-group">资产与证书</div>
        <div class="km-nav-item" :class="{ active: $route.path === '/certs' }" @click="$router.push('/certs')">
          <el-icon><Postcard /></el-icon>证书管理
        </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/assets' }" @click="$router.push('/assets')">
          <el-icon><Grid /></el-icon>API 安全
          <span v-if="badge.risks > 0" class="km-nav-badge">{{ badge.risks }}</span>
        </div>
        <div class="km-menu-group">系统</div>
        <div v-if="can('operator')" class="km-nav-item" :class="{ active: $route.path === '/settings' }" @click="$router.push('/settings')">
          <el-icon><Tools /></el-icon>系统设置
        </div>
        <div v-if="role() === 'admin'" class="km-nav-item" :class="{ active: $route.path === '/users' }" @click="$router.push('/users')">
          <el-icon><UserFilled /></el-icon>用户管理
        </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/ai' }" @click="$router.push('/ai')">
          <el-icon><ChatDotRound /></el-icon>AI 助手
          <span class="km-nav-badge plain">只读</span>
        </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/docs' }" @click="$router.push('/docs')">
          <el-icon><Tickets /></el-icon>API 文档
        </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/about' }" @click="$router.push('/about')">
          <el-icon><InfoFilled /></el-icon>关于KingMoat WAF
        </div>
      </div>
      <div class="km-side-slogan">Fortress for Every Request</div>
      <div class="km-side-foot">
        <div class="km-foot-row">
          <el-tooltip :content="themeLabel" placement="top">
            <el-button circle text @click="onToggleTheme">
              <el-icon><Sunny v-if="isDark" /><Moon v-else /></el-icon>
            </el-button>
          </el-tooltip>
          <el-tag size="small" effect="dark" class="km-tag" type="info">{{ roleLabel }}</el-tag>
          <div style="flex:1"></div>
          <el-dropdown trigger="click">
            <div class="km-avatar">{{ (user() || '?').slice(0, 1).toUpperCase() }}</div>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item disabled>
                  <span style="font-weight:600">{{ user() }}</span>
                </el-dropdown-item>
                <el-dropdown-item divided @click="account = true"><el-icon><User /></el-icon>我的账号</el-dropdown-item>
                <el-dropdown-item @click="logout"><el-icon><SwitchButton /></el-icon>退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </div>
    </el-aside>
    <el-container>
      <el-header class="km-head" height="56px">
        <div class="page-title">{{ pageTitle }}</div>
        <div class="spacer"></div>
      </el-header>
      <el-main class="km-main">
        <el-alert v-if="revMismatch" class="km-rev-alert" type="error" :closable="false" show-icon>
          <template #title>
            <span>配置已更新但引擎未应用，最新发布结果：{{ applyText }}</span>
            <el-button v-if="can('operator')" size="small" type="danger" plain class="km-rev-alert-btn" @click="$router.push('/sites')">查看发布记录</el-button>
          </template>
        </el-alert>
        <!-- 加载期降级/归一化横幅（A2）：load_notes 非空才展示（后端语义：启动/回滚时对
             存量旧形态外发节做过归一化或降级才记录；成功发布一次后清空，随轮询消失）。
             可手动关闭，同内容不重复弹出；内容变化（新一次启动/回滚记录）重新弹出。 -->
        <el-alert v-if="loadNotes.length && !loadNotesDismissed" class="km-rev-alert" type="warning" show-icon closable
                  @close="loadNotesDismissed = true">
          <template #title>
            <span>服务启动时已自动处理存量外发配置：部分外发节被归一化或自动关闭，请到「系统设置」核对日志外发与 AI 会话外发</span>
          </template>
          <div v-for="(n, i) in loadNotes" :key="i" class="km-load-note">{{ n }}</div>
          <div class="km-load-note-hint">以上为进程启动时的自动处理记录（含原始校验错误）；保存发布一次新配置后本提示自动消失。</div>
        </el-alert>
        <!-- 运行期告警横幅（新契约）：/api/status 的 runtime_alerts 非空才展示。与 load_notes 语义不同：
             load_notes 是配置加载事实（发布成功即清空），runtime_alerts 是运行期异常，不因发布清空，
             条件消失后后端才不再下发。critical 红色醒目；显示后端 message 原文 + since；
             手动关闭仅本会话生效（不持久化），页面刷新后若告警仍存在会再次出现。 -->
        <el-alert v-for="a in visibleRuntimeAlerts" :key="runtimeAlertKey(a)" class="km-rev-alert km-rt-alert"
                  :type="a.level === 'critical' ? 'error' : 'warning'" show-icon closable
                  @close="dismissRuntimeAlert(a)">
          <template #title>
            <span class="km-rt-title">运行期告警{{ a.level === 'critical' ? '（严重）' : '' }}：{{ a.message }}</span>
            <span v-if="a.since" class="km-rt-since">自 {{ fmtTime(a.since) }} 起</span>
          </template>
        </el-alert>
        <router-view />
      </el-main>
    </el-container>
    <MyAccount v-model="account" />

    <!-- AI 悬浮球:悬浮于任意页面,可拖动(位置记忆),点击打开抽屉 -->
    <div class="km-ai-fab-float" :style="{ left: fab.x + 'px', top: fab.y + 'px' }"
         title="AI 安全助手（可拖动）" @mousedown.prevent="fabDown" @click="onFabClick">
      <el-icon><ChatDotRound /></el-icon>
    </div>

    <!-- destroy-on-close: AIChat 每次打开抽屉重新挂载，重新拉取 /api/ai/config，
         避免抽屉复用旧实例导致「未启用/旧模型」陈旧展示（发布新配置后不刷新） -->
    <el-drawer v-model="aiDrawer" title="AI 安全助手" size="440px" :append-to-body="true" destroy-on-close>
      <AIChat inline />
    </el-drawer>
  </el-container>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, can, clearSession, role, user } from '../api'
import { applyTheme, getTheme } from '../theme'
import { fmtTime } from '../timefmt'
import AIChat from '../views/AIChat.vue'
import MyAccount from './MyAccount.vue'

const aiDrawer = ref(false)
const account = ref(false)
const isDark = ref(getTheme() === 'dark')
const badge = reactive({ blocked: 0, risks: 0 })
// 引擎运行 revision vs 配置库最新 revision（T-03）：两者都存在且不一致时
// 全局红色告警条；旧后端无字段/拉取失败时保持 null，告警条静默隐藏
const applyInfo = reactive({ latest: null, running: null, error: '', status: '' })
const revMismatch = computed(() => applyInfo.latest !== null && applyInfo.running !== null && applyInfo.latest !== applyInfo.running)
// status 只存机器值（applied / failed / pending），展示文案统一在
// applyText 映射，状态字段不再混入 UI 文案
const applyText = computed(() => {
  if (applyInfo.error) return applyInfo.error
  if (applyInfo.status === 'pending') return '配置应用中…'
  return applyInfo.status || ''
})
// 加载期降级/归一化横幅（A2）：随 loadBadge 的 /api/status 轮询更新；字段缺失/为空
//（含 static 纯文件形态与旧后端）时静默隐藏，不报错
const loadNotes = ref([])
const loadNotesDismissed = ref(false)
let loadNotesSig = ''
let badgeTimer = null
// 运行期告警（新契约）：字段缺失/非数组/元素非法一律兜底为空列表，不报错。
// 手动关闭仅本会话生效（内存 Set，不持久化）；列表内容变化（告警新增/消失）时重置关闭态，
// 同内容轮询重拉不重弹。不在前端编造原因文案，展示后端 message 原文。
const runtimeAlerts = ref([])
const runtimeAlertDismissed = ref(new Set())
let runtimeAlertsSig = ''
const runtimeAlertKey = a => `${a.code || ''}|${a.since || ''}|${a.message || ''}`
const visibleRuntimeAlerts = computed(() => runtimeAlerts.value.filter(a => !runtimeAlertDismissed.value.has(runtimeAlertKey(a))))
function dismissRuntimeAlert(a) {
  const next = new Set(runtimeAlertDismissed.value)
  next.add(runtimeAlertKey(a))
  runtimeAlertDismissed.value = next
}

const route = useRoute()
const router = useRouter()
const roleLabel = computed(() => ({ admin: '管理员', operator: '运维', auditor: '审计' }[role()] || role()))
const themeLabel = computed(() => (isDark.value ? '切换到浅色 · 量子青' : '切换到深色 · 暗域'))
const blockedLabel = computed(() => (badge.blocked > 999 ? '999+' : String(badge.blocked)))
const pageTitle = computed(() => ({
  '/': '防护总览',
  '/sites': '站点防护',
  '/policy': '策略管理',
  '/logs': '攻击日志',
  '/log': '日志详情',
  '/access-logs': '访问日志',
  '/ai-sessions': 'AI 会话审计',
  '/certs': '证书管理',
  '/assets': 'API 安全',
  '/ai': 'AI 助手',
  '/settings': '系统设置',
  '/users': '用户管理',
  '/docs': 'API 文档',
  '/about': '关于KingMoat WAF',
}[route.path.startsWith('/log/') ? '/log' : route.path] || 'KingMoat Console'))

// AI 悬浮球:拖动(位置记忆)+ 点击与拖拽区分
const fab = reactive({ x: window.innerWidth - 84, y: window.innerHeight - 120, dragging: false, moved: false, dx: 0, dy: 0 })
try {
  const saved = JSON.parse(localStorage.getItem('km-ai-fab') || 'null')
  if (saved && typeof saved.x === 'number' && typeof saved.y === 'number') { fab.x = saved.x; fab.y = saved.y }
} catch (e) { /* default position */ }
function fabDown(ev) {
  fab.dragging = true
  fab.moved = false
  fab.dx = ev.clientX - fab.x
  fab.dy = ev.clientY - fab.y
  document.addEventListener('mousemove', fabMove)
  document.addEventListener('mouseup', fabUp)
}
function fabMove(ev) {
  if (!fab.dragging) return
  const nx = Math.min(Math.max(8, ev.clientX - fab.dx), window.innerWidth - 60)
  const ny = Math.min(Math.max(8, ev.clientY - fab.dy), window.innerHeight - 60)
  if (Math.abs(nx - fab.x) > 2 || Math.abs(ny - fab.y) > 2) fab.moved = true
  fab.x = nx
  fab.y = ny
}
function fabUp() {
  fab.dragging = false
  document.removeEventListener('mousemove', fabMove)
  document.removeEventListener('mouseup', fabUp)
  localStorage.setItem('km-ai-fab', JSON.stringify({ x: fab.x, y: fab.y }))
}
function onFabClick() {
  if (fab.moved) { fab.moved = false; return }
  aiDrawer.value = true
}

async function loadBadge() {
  try {
    const [st, risks, status] = await Promise.all([
      api('/api/stats'),
      api('/api/risks').catch(() => null),
      api('/api/status').catch(() => null),
    ])
    badge.blocked = st.blocked_today || 0
    const risksList = Array.isArray(risks) ? risks : (risks?.risks || [])
    badge.risks = risksList.filter(r => !r.status || r.status === 'open' || r.status === 'pending').length
    // 瞬时失败保留旧值（C5）：status 请求被 catch 成 null 时若按空数组处理，签名变化会
    // 重置 dismissed（已关闭的横幅重弹）；仅成功响应才更新这两组横幅状态
    if (status) {
      const notes = Array.isArray(status.load_notes) ? status.load_notes : []
      const notesSig = JSON.stringify(notes)
      if (notesSig !== loadNotesSig) { loadNotesSig = notesSig; loadNotesDismissed.value = false }
      loadNotes.value = notes
      // runtime_alerts：运行期异常，非空才展示；与 load_notes 互不影响（同口径：仅在成功响应时更新）
      const rts = Array.isArray(status.runtime_alerts)
        ? status.runtime_alerts.filter(a => a && typeof a === 'object')
        : []
      const rtsSig = JSON.stringify(rts)
      if (rtsSig !== runtimeAlertsSig) { runtimeAlertsSig = rtsSig; runtimeAlertDismissed.value = new Set() }
      runtimeAlerts.value = rts
    }
    // apply 携带的是最近一次数据面应用结果（含 revision）：只有它与最新
    // 发布版本一致时才代表当前配置的真实结果；不一致说明发布仍在途
    // （或结果尚未上报），展示中性「应用中」而不是上一次的陈旧结果
    if (status && status.latest_revision != null && status.running_revision != null) {
      applyInfo.latest = status.latest_revision
      applyInfo.running = status.running_revision
      const applyRev = status.apply && status.apply.revision
      if (applyRev != null && applyRev === status.latest_revision) {
        applyInfo.error = (status.apply && status.apply.error) || ''
        applyInfo.status = (status.apply && status.apply.status) || ''
      } else {
        applyInfo.error = ''
        applyInfo.status = 'pending'
      }
    } else {
      applyInfo.latest = null
      applyInfo.running = null
    }
  } catch (e) { /* silent: badge is cosmetic */ }
}
function onToggleTheme() {
  isDark.value = !isDark.value
  applyTheme(isDark.value ? 'dark' : 'light')
  window.dispatchEvent(new CustomEvent('km-theme-changed'))
}

function logout() {
  api('/api/logout', { method: 'POST' }).catch(() => {}).finally(() => {
    clearSession()
    router.push('/login')
  })
}

onMounted(() => {
  loadBadge()
  badgeTimer = setInterval(loadBadge, 30000)
  // 设置页发布成功后立即复查（后端清空 load_notes），横幅随发布消失而不必等下一轮轮询
  window.addEventListener('km-status-refresh', loadBadge)
})
onBeforeUnmount(() => {
  if (badgeTimer) clearInterval(badgeTimer)
  window.removeEventListener('km-status-refresh', loadBadge)
})
</script>

<style scoped>
.km-rev-alert { margin-bottom: 14px; }
.km-rev-alert-btn { margin-left: 12px; }
.km-load-note { font-size: 12px; line-height: 1.8; font-family: ui-monospace, SFMono-Regular, Consolas, 'Courier New', monospace; color: var(--km-txt-2); word-break: break-all; }
.km-load-note-hint { font-size: 12px; line-height: 1.8; color: var(--km-txt-3); margin-top: 2px; }
.km-rt-title { font-weight: 600; }
.km-rt-since { font-size: 12px; font-weight: 400; margin-left: 10px; opacity: .75; }
</style>
