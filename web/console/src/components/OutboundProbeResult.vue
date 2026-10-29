<template>
  <el-alert v-if="result" :type="alertType" :closable="false" show-icon class="km-probe-result">
    <template #title>
      <span>{{ title }}</span>
      <el-link v-if="collapsible" :underline="false" class="km-probe-toggle" @click="open = !open">
        {{ open ? '收起详情' : '查看详情' }}
      </el-link>
    </template>
    <div v-if="reasonText" class="km-probe-line">{{ reasonText }}</div>
    <div v-if="result.state === 'degraded'" class="km-probe-line">
      只读探测仅能验证到此处（如 UDP 投递、跳过证书校验的 TLS 握手均无法确认端到端投递），实际投递能力请以目标端是否收到日志为准
    </div>
    <div v-if="open && checks.length" class="km-probe-checks">
      <div v-for="(c, i) in checks" :key="i" class="km-probe-check">
        <span class="km-probe-dot" :class="c.state" />
        <span class="km-probe-step">{{ STEP_TEXT[c.step] || c.step }}</span>
        <span class="km-probe-step-res">{{ STEP_STATE[c.state] || c.state }}<template v-if="c.reason">（{{ c.reason }}）</template></span>
      </div>
    </div>
    <div v-if="result.error || (open && result.detail)" class="km-mono km-probe-detail">{{ result.detail }}</div>
  </el-alert>
</template>

<script setup>
// 外发渠道测试结果三态展示（POST /api/outbound/test 响应，三张外发卡共用）。
// ok=绿 / degraded=琥珀（有限验证，不得显示为「正常」）/ fail=红。
import { computed, ref, watch } from 'vue'
import { SINK_TYPE_LABELS } from '../sinkTypes'

const props = defineProps({
  // { state:'ok'|'degraded'|'fail', ok, type?, latency_ms, reason?, detail, checks?, error? }
  // error=true 表示请求层失败（网络/401/403/429），detail 直接内联展示；
  // checks 是多步探测的分步结果（[{step,state,reason?}]，如 s3 的 dial→s3）
  result: { type: Object, default: null },
})

const STATE_TEXT = { ok: '连接正常', degraded: '连接可达（有限验证）', fail: '连接失败' }
// 分步检测的步骤名与单步结论（reason 为后端机器码，与响应 reason 枚举一致）
const STEP_TEXT = { dial: 'TCP 拨号', s3: 'S3 桶校验' }
const STEP_STATE = { ok: '通过', degraded: '有限验证', fail: '未通过' }
const REASON_TEXT = {
  unreachable: '目标不可达：地址错误、端口未开放或网络不通',
  auth_failed: '认证失败：用户名/密码或 AccessKey/SecretKey 不正确',
  tls_error: 'TLS 证书校验失败：证书过期、自签未信任或域名不匹配',
  config_incomplete: '配置不完整，请补全必填项后重试',
  // 后端将 ≥5xx、不跟随的 3xx 及其它非 401/403 的 4xx 均归为 server_error，
  // 实际状态码在 detail 中，文案不能锁定为 5xx
  server_error: '对端返回错误状态码（非 2xx，实际码见详情）',
  timeout: '连接超时',
  bucket_missing: 'S3 桶不存在（凭据本身有效）',
  unsupported: '不支持的外发类型',
}

const open = ref(false)
watch(() => props.result, () => { open.value = false })

const alertType = computed(() => ({ ok: 'success', degraded: 'warning', fail: 'error' }[props.result?.state] || 'info'))
const title = computed(() => {
  const r = props.result || {}
  if (r.error) return '测试连接：请求未完成'
  const bits = []
  if (SINK_TYPE_LABELS[r.type]) bits.push(SINK_TYPE_LABELS[r.type])
  if (r.latency_ms !== undefined && r.latency_ms !== null) bits.push(`${r.latency_ms}ms`)
  const meta = bits.length ? `（${bits.join(' · ')}）` : ''
  return `测试连接：${STATE_TEXT[r.state] || r.state || '未知结果'}${meta}`
})
const reasonText = computed(() => REASON_TEXT[props.result?.reason] || '')
const checks = computed(() => props.result?.checks || [])
const collapsible = computed(() => !props.result?.error && (!!props.result?.detail || checks.value.length > 0))
</script>

<style scoped>
.km-probe-toggle { font-size: 12px; margin-left: 10px; vertical-align: middle; }
.km-probe-line { font-size: 12.5px; line-height: 1.8; }
.km-probe-detail { font-size: 12px; line-height: 1.8; white-space: pre-wrap; word-break: break-all; margin-top: 4px; color: var(--km-txt-2); }
.km-probe-checks { margin-top: 6px; padding-top: 6px; border-top: 1px dashed var(--km-line); display: flex; flex-direction: column; gap: 2px; }
.km-probe-check { display: flex; align-items: center; gap: 8px; font-size: 12px; line-height: 1.9; }
.km-probe-dot { width: 7px; height: 7px; border-radius: 50%; flex: none; }
.km-probe-dot.ok { background: var(--km-green); }
.km-probe-dot.degraded { background: var(--km-amber); }
.km-probe-dot.fail { background: var(--km-red); }
.km-probe-step { color: var(--km-txt); }
.km-probe-step-res { color: var(--km-txt-2); }
</style>
