<template>
  <div style="display:flex;gap:16px;align-items:flex-start">
    <el-card shadow="never" class="km-set-nav" :body-style="{ padding: '8px' }">
      <div v-for="t in tabs" :key="t.id" class="item" :class="{ on: tab === t.id }" @click="tab = t.id">
        <span>{{ t.icon }} {{ t.name }}</span>
      </div>
    </el-card>

    <div style="flex:1;min-width:0">
      <el-alert type="info" :closable="false" show-icon style="margin-bottom:14px"
                title="系统设置保存即发布为新配置版本并热生效（与站点配置同一版本库，可回滚）；标注「需重启」的项在服务重启后生效，可使用「服务重启」卡片执行" />

      <!-- ① 通用 -->
      <template v-if="tab === 'general'">
        <!-- 管理界面端口（在线更换：写 console.env + 自动重启，独立于配置发布流程） -->
        <el-card v-if="portInfo" shadow="never" style="margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
            <div class="km-title" style="margin:0">管理界面端口</div>
            <el-tag size="small" effect="plain" class="km-mono">当前 {{ portInfo.port }}</el-tag>
            <div style="flex:1"></div>
            <el-input-number v-model="portForm.port" :min="1" :max="65535" :controls="false" size="small"
                             :disabled="!portInfo.changeable || !can('admin') || upgTaskActive" placeholder="新端口"
                             class="km-mono" style="width:120px" />
            <el-button size="small" type="primary" :disabled="!portInfo.changeable || !can('admin') || upgTaskActive"
                       @click="openPortDlg">更换端口</el-button>
          </div>
          <div class="km-dim" style="font-size:12px;margin-top:8px;line-height:1.8">
            控制台端口由 systemd 单元从数据目录 console.env 读取，更换后服务自动重启生效（约 30 秒），数据面业务监听不受影响；防火墙需同步放行新端口。
          </div>
          <el-alert v-if="portResult" type="success" :closable="false" show-icon style="margin-top:12px"
                    :title="`端口变更已提交，服务重启中（约 ${portResult.seconds} 秒）`"
                    :description="`重启完成后请用新地址访问：${portResult.url} —— 当前标签页将失联；若超时未恢复，请按部署文档「控制台端口更换与失联恢复」手工恢复。`" />
        </el-card>

        <!-- 版本与升级（在线升级：仅 systemd/Linux 形态开放，admin 专属；模块未接线 501 自动降级手动指引） -->
        <el-card shadow="never" style="margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
            <div class="km-title" style="margin:0">版本与升级</div>
            <div style="flex:1"></div>
            <el-button v-if="upgradeModule && !upgTaskActive" size="small" :loading="upgChecking"
                       :disabled="!can('admin')" @click="checkUpgrade">检查更新</el-button>
          </div>
          <div style="display:flex;align-items:flex-end;gap:14px;margin-top:12px;flex-wrap:wrap">
            <div>
              <div class="km-mono" style="font-size:26px;font-weight:700;line-height:1.15">{{ upgVersion || '—' }}</div>
              <div class="km-dim" style="font-size:12px;margin-top:2px">当前运行版本</div>
            </div>
            <el-tag v-if="upgradeModule && upgLatest?.update_available && !upgTaskActive" size="small" type="warning" effect="plain">
              可升级到 {{ upgLatest.version }}
            </el-tag>
          </div>

          <!-- 降级：非 admin（权限不足）或模块未接线（501，如非 systemd 部署形态） -->
          <div v-if="upgradeModule === false" class="km-dim" style="font-size:12.5px;margin-top:12px;line-height:2">
            <template v-if="upgDenied">在线升级仅管理员可用，如需升级请联系管理员处理。</template>
            <template v-else>当前部署形态不支持在线升级（需 systemd/Linux 一键部署形态），可手动下载升级包完成更新。</template>
            <a href="https://gitee.com/aiuc-labs/KingMoat-WAF/releases" target="_blank" style="color:var(--km-cyan)">前往 Release 页手动下载 →</a>
          </div>

          <!-- 版本检查结果 -->
          <el-alert v-if="upgradeModule && upgLatest?.update_available && !upgTaskActive" type="warning" :closable="false" show-icon
                    style="margin-top:12px" :title="`发现新版本 ${upgLatest.version}，建议在维护窗口升级`">
            <div class="km-upg-notes">{{ upgLatest.notes || '（本次更新无说明）' }}</div>
            <div style="margin-top:10px;display:flex;align-items:center;gap:12px">
              <el-button size="small" type="primary" :disabled="!can('admin')" @click="confirmUpgrade">立即升级</el-button>
              <a v-if="upgAssetsUrl" :href="upgAssetsUrl" target="_blank" rel="noopener noreferrer" class="km-dim" style="font-size:12px">手动下载升级包</a>
              <span v-else-if="upgLatest.assets_url" class="km-dim" style="font-size:12px">手动下载升级包（链接来源不可信，请到发布页获取）</span>
            </div>
          </el-alert>
          <div v-else-if="upgradeModule && upgLatest && !upgTaskActive" style="margin-top:12px;display:flex;align-items:center;gap:8px">
            <el-tag size="small" type="success" effect="plain">已是最新</el-tag>
            <span class="km-dim" style="font-size:12.5px">最新版本 <span class="km-mono">{{ upgLatest.version }}</span>，与当前运行版本一致</span>
          </div>
          <div v-else-if="upgradeModule && !upgLatest && upgStatusError && !upgTaskActive" class="km-dim"
               style="font-size:12.5px;margin-top:12px;color:var(--km-red)">
            版本信息获取失败：{{ upgStatusError }}（可点击「检查更新」重试）
          </div>

          <!-- 升级进行中：五阶段进度 + 2s 轮询（重启窗口自动退避重试）；期间禁用本页全部写操作 -->
          <template v-if="upgTaskActive">
            <div class="km-upg-steps" style="margin-top:14px">
              <template v-for="(s, i) in UPG_STEPS" :key="s.key">
                <span v-if="i > 0" class="km-upg-arrow">→</span>
                <span class="km-upg-step" :class="{ done: i < upgStepIdx, on: i === upgStepIdx }">
                  <span class="dot"></span>{{ s.label }}
                </span>
              </template>
            </div>
            <div class="km-dim" style="font-size:12.5px;margin-top:10px;line-height:1.9">
              {{ upgTask.message || '升级进行中，请保持本页打开（升级完成后服务将自动重启）' }}
              <span v-if="upgTask.target_version"> · 目标版本 <span class="km-mono">{{ upgTask.target_version }}</span></span>
            </div>
            <div class="km-muted" style="font-size:12px;margin-top:4px">升级期间本页所有保存 / 提交操作已临时禁用</div>
          </template>

          <!-- 升级结果 -->
          <el-alert v-if="upgTask?.state === 'success'" type="success" :closable="false" show-icon style="margin-top:14px"
                    title="升级完成，服务重启中">
            <div style="font-size:12.5px;line-height:1.9;color:var(--km-txt-2)">约 30 秒后请刷新页面并重新登录（升级后当前会话需重新登录，属预期现象）。</div>
            <div style="margin-top:8px"><el-button size="small" type="primary" @click="reloadPage">刷新页面</el-button></div>
          </el-alert>
          <el-alert v-if="upgTask?.state === 'failed'" type="error" :closable="false" show-icon style="margin-top:14px"
                    title="升级失败"
                    :description="(upgTask.error || upgTask.message || '未知原因') + ' —— 任务失败后有冷却期，请稍后再试；也可前往 Release 页手动下载升级包。'" />
        </el-card>

        <!-- 服务重启（admin）：POST /api/system/restart，能力探测/审计/升级互斥由后端负责 -->
        <el-card shadow="never" style="margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
            <div class="km-title" style="margin:0">服务重启</div>
            <div style="flex:1"></div>
            <el-button size="small" type="warning" plain :loading="restartBusy"
                       :disabled="!can('admin') || upgTaskActive" @click="confirmRestart">重启服务</el-button>
          </div>
          <div class="km-dim" style="font-size:12.5px;margin-top:10px;line-height:1.9">
            适用于「保存后需重启生效」的配置（如审计保留期、登录态有效期、metrics 推送目标等；日志外发与访问日志管道已支持发布即时生效）。重启期间控制台与数据面约 30 秒不可访问，完成后需重新登录；升级任务进行中时后端会拒绝重启（409）。
          </div>
          <el-alert v-if="restartMsg" type="success" :closable="false" show-icon style="margin-top:10px" :title="restartMsg" />
          <el-alert v-if="restartError" type="error" :closable="false" show-icon style="margin-top:10px" :title="'重启失败'" :description="restartError" />
        </el-card>

        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">数据面监听</div>
          <el-form label-width="160px" label-position="left">
            <el-form-item label="HTTP 监听地址">
              <el-input v-model="f.listen_http" class="km-mono" placeholder="0.0.0.0:80" style="width:320px" :disabled="!can('operator')" />
              <div v-if="listenHttpError" style="width:100%;font-size:12px;color:var(--km-red);margin-top:4px">{{ listenHttpError }}</div>
              <div class="km-dim" style="font-size:12px;width:100%">数据面 HTTP 监听，按站点域名自动路由；留空则 HTTP 数据面关闭</div>
            </el-form-item>
            <el-form-item label="HTTPS 监听地址">
              <el-input v-model="f.listen_https" class="km-mono" placeholder="0.0.0.0:443" style="width:320px" :disabled="!can('operator')" />
              <div v-if="listenHttpsError" style="width:100%;font-size:12px;color:var(--km-red);margin-top:4px">{{ listenHttpsError }}</div>
              <div v-else-if="listenPortConflict" style="width:100%;font-size:12px;color:var(--km-red);margin-top:4px">HTTP 与 HTTPS 监听端口不能相同</div>
              <div class="km-dim" style="font-size:12px;width:100%">站点启用 HTTPS / ACME / HTTPS 跳转的前提，留空则 HTTPS 数据面关闭；支持 [::]:443 IPv6 写法</div>
            </el-form-item>
          </el-form>
          <el-alert v-if="listenPairEmpty" type="error" :closable="false" show-icon style="margin-top:6px"
                    title="至少需要配置一个全局监听地址（HTTP / HTTPS 至少一项）" />
        </el-card>

        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">功能开关</div>
          <el-form label-width="200px" label-position="left">
            <el-form-item label="请求快照捕获">
              <el-switch v-model="f.capture_requests" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">审计事件附带脱敏请求头/body 快样（隐私敏感）</span>
            </el-form-item>
            <el-form-item label="API 资产学习">
              <el-switch v-model="f.api_assets_enabled" />
            </el-form-item>
            <el-form-item label="风险引擎">
              <el-switch v-model="f.risks_enabled" />
            </el-form-item>
            <el-form-item label="匿名安装统计">
              <el-switch v-model="f.telemetry_enabled" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">默认关。开启后仅上报随机安装 ID、软件版本、操作系统架构与安装方式；不采集主机名、用户名、内网 IP 或任何业务数据；支持 DO_NOT_TRACK 环境变量一键关闭；连续 3 次无法连接统计服务会自动停止上报。保存并发布后生效。</span>
            </el-form-item>
        <el-form-item label="Prometheus /metrics 端点">
          <el-switch v-model="f.metrics_enabled" />
          <span class="km-dim" style="margin-left:10px;font-size:12px">可选指标端点（文本格式，控制台认证内；默认关，热生效）</span>
          <template v-if="f.metrics_enabled">
            <el-form-item label="外发推送目标">
              <div style="width:100%">
              <el-input v-model="f.metrics_push_url" placeholder="http://pushgateway:9091/metrics/job/kingmoat（留空 = 不推送，仅拉取）" class="km-mono" style="margin-bottom:6px" />
              <div style="display:flex;gap:8px;align-items:center">
                <span class="km-dim" style="font-size:12px">间隔</span>
                <el-input-number v-model="f.metrics_push_interval" :min="5" :max="3600" size="small" style="width:110px" />
                <span class="km-dim" style="font-size:12px">秒 · Bearer Token</span>
                <el-input v-model="f.metrics_push_token" placeholder="可选" class="km-mono" style="width:200px" show-password />
              </div>
              <div class="km-dim" style="font-size:12px;margin-top:4px">开启后按间隔将完整 /metrics 文本 POST 到目标（如 Pushgateway）；推送目标变更需重启服务生效（顶部「服务重启」卡片可执行）</div>
              </div>
            </el-form-item>
          </template>
        </el-form-item>
          </el-form>
        </el-card>
        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">审计日志保留与查询治理</div>
          <el-form label-width="200px" label-position="left">
            <el-form-item label="审计事件保留天数">
              <el-input-number v-model="f.audit_retention_days" :min="1" :max="365" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">本机活动库仅保留 N 天（默认 7；保存后需重启生效——顶部「服务重启」卡片可执行）</span>
            </el-form-item>
            <el-form-item label="归档快照保留天数">
              <el-input-number v-model="f.archive_retention_days" :min="1" :max="3650" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">每日 gzip 快照保留 N 天（默认 30；保存后需重启生效——顶部「服务重启」卡片可执行）</span>
            </el-form-item>
            <el-form-item label="紧急降级（停止日志查询）">
              <el-switch v-model="f.query_degraded" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">开启后控制台历史/趋势查询立即降级，转发不受影响（热生效）</span>
            </el-form-item>
          </el-form>
          <el-alert type="warning" :closable="false" show-icon style="margin-top:6px"
                    title="保留期越长，本机日志库越大、控制台检索越慢，并可能挤占转发资源"
                    description="建议保持较短保留期，长期留存请启用「审计日志外发」。日志查询运行在独立只读通道，受并发上限与超时限制；攻击风暴等紧急情况可打开上方降级开关一键停止查询。" />
        </el-card>

        <!-- 访问日志本地记录（access_log_record）：独立顶层节，与「日志外发」页签的 access_log 外发节相互独立 -->
        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">访问日志配置</div>
          <el-form label-width="200px" label-position="left">
            <el-form-item label="记录模式">
              <div>
                <el-radio-group v-model="f.access_record_mode">
                  <el-radio-button value="off">关闭</el-radio-button>
                  <el-radio-button value="all">全部站点</el-radio-button>
                  <el-radio-button value="sites">指定站点</el-radio-button>
                </el-radio-group>
                <div class="km-dim" style="font-size:12px;margin-top:4px;line-height:1.8;max-width:660px">
                  默认关闭。开启后访问日志在本机留存（保存发布后即时生效，无需重启），可在「访问日志」页查本地历史；与「日志外发」页签的外发配置相互独立，未配置外发也会本地留存。「全部站点」不含未匹配任何站点的直打流量。
                </div>
              </div>
            </el-form-item>
            <el-form-item v-if="f.access_record_mode === 'sites'" label="记录站点">
              <div style="width:100%">
                <el-select v-model="f.access_record_sites" multiple filterable clearable collapse-tags
                           placeholder="选择要记录的站点（按站点首域名）" style="width:100%;max-width:660px">
                  <el-option v-for="s in accessRecordSiteOptions" :key="s" :label="s" :value="s" />
                </el-select>
                <div v-if="!accessRecordSiteOptions.length" class="km-dim" style="font-size:12px;margin-top:4px">
                  当前配置中暂无站点：请先在「站点防护」创建站点，或改用「全部站点」模式
                </div>
              </div>
            </el-form-item>
            <el-form-item label="保留天数">
              <el-input-number v-model="f.access_record_retention_days" :min="1" :max="90" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">本机留存天数（默认 7，范围 1-90）</span>
            </el-form-item>
            <el-form-item label="容量上限（MB）">
              <el-input-number v-model="f.access_record_max_disk_mb" :min="128" :max="10240" :step="128" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">本机库占用上限（默认 1024，范围 128-10240）</span>
            </el-form-item>
          </el-form>
          <el-alert type="info" :closable="false" show-icon style="margin-top:6px"
                    title="容量到顶后按最旧优先淘汰，实际留存时间可能短于保留天数；请求量越大淘汰越快，可在「访问日志」页查看当前占用与已淘汰条数"
                    description="容量估算：每条约 0.5 KB，1024 MB 约可存 200 万条；如日均请求量达百万级，默认容量约一至两天即淘汰一轮，请按业务量调大容量上限或缩短保留天数。" />
        </el-card>

        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">AI 助手</div>
          <el-form label-width="140px" label-position="left">
            <el-form-item label="启用">
              <el-switch v-model="f.ai_enabled" />
            </el-form-item>
            <template v-if="f.ai_enabled">
              <el-form-item label="服务商模板">
                <el-select v-model="f.ai_template" style="width:260px" @change="onTemplate">
                  <el-option v-for="tp in templates" :key="tp.id" :label="tp.name" :value="tp.id" />
                </el-select>
              </el-form-item>
              <el-form-item label="Base URL"><el-input v-model="f.ai_base" placeholder="https://api.openai.com/v1" class="km-mono" style="width:420px" /></el-form-item>
              <el-form-item label="模型"><el-input v-model="f.ai_model" placeholder="gpt-4o-mini" style="width:260px" /></el-form-item>
              <el-form-item label="API Key">
                <div style="display:flex;gap:8px;align-items:center;width:100%;flex-wrap:wrap">
                  <el-input v-model="aiKeyInput" type="password" show-password autocomplete="new-password"
                            placeholder="粘贴 Key 后保存入库，保存后不可再查看" class="km-mono" style="width:300px" />
                  <el-button size="small" type="primary" :disabled="!can('admin') || upgTaskActive" :loading="aiKeySaving" @click="saveAIKey">保存 Key</el-button>
                  <el-button size="small" type="danger" plain :disabled="!can('admin') || aiKeySaving || aiKeySource !== 'stored' || upgTaskActive" @click="clearAIKey">清除</el-button>
                  <el-tag size="small" effect="plain" :type="keySourceTag" class="km-tag">{{ keySourceLabel }}</el-tag>
                </div>
                <span class="km-dim" style="margin-left:10px;font-size:12px">存入数据库（argon2id 哈希 + KEK 加密），保存后不可再查看；优先于环境变量</span>
              </el-form-item>
              <el-form-item label="温度">
                <el-slider v-model="f.ai_temperature" :min="0" :max="2" :step="0.1" show-input style="width:320px" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">默认 0.2；越高越发散</span>
              </el-form-item>
              <el-form-item label="超时（秒）">
                <el-input-number v-model="f.ai_timeout" :min="10" :max="600" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">单次请求超时，默认 120</span>
              </el-form-item>
              <el-form-item label="输出上限">
                <el-input-number v-model="f.ai_max_tokens" :min="256" :max="1000000" :step="1024" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">单次回答的最大 tokens，默认 4096</span>
              </el-form-item>
              <el-form-item label="系统提示词">
                <el-input v-model="f.ai_sysprompt" type="textarea" :rows="4" spellcheck="false"
                          placeholder="留空使用内置只读分析师人设；自定义后覆盖默认人设" />
              </el-form-item>
              <el-form-item label="上下文窗口">
                <el-input-number v-model="f.ai_ctx_tokens" :min="0" :max="10000000" :step="1000" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">tokens，0 = 不限制；超限自动压缩历史</span>
              </el-form-item>
              <el-form-item label="压缩保留轮数">
                <el-input-number v-model="f.ai_keep_turns" :min="1" :max="50" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">压缩时保留最近 N 轮原文</span>
              </el-form-item>
            <el-form-item label="历史保留（天)">
              <el-input-number v-model="f.ai_history_days" :min="0" :max="3650" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">超过 N 天的 AI 会话自动清理（0 = 永久保留）</span>
            </el-form-item>
            <el-form-item label="出站脱敏">
              <el-switch v-model="f.ai_sanitize" />
              <el-tooltip content="发给大模型的攻击上下文/工具结果自动掩码 IP/主机/凭据，控制台展示自动还原" placement="top">
                <el-icon style="margin-left:8px;vertical-align:middle;color:var(--km-txt-3)"><QuestionFilled /></el-icon>
              </el-tooltip>
              <span class="km-dim" style="margin-left:10px;font-size:12px">默认开启，建议保持</span>
            </el-form-item>
            <el-form-item label="AI 日报">
              <el-switch v-model="f.ai_analysis" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">定时生成攻击态势报告并投递（报告留存于 AI 报告列表）</span>
            </el-form-item>
            <template v-if="f.ai_analysis">
              <el-form-item label="执行时间">
                <el-time-picker v-model="f.ai_report_time" value-format="HH:mm" format="HH:mm" placeholder="选择执行时间" style="width:140px" />
              </el-form-item>
              <el-form-item label="重复">
                <el-checkbox-group v-model="f.ai_report_days">
                  <el-checkbox :value="1">周一</el-checkbox>
                  <el-checkbox :value="2">周二</el-checkbox>
                  <el-checkbox :value="3">周三</el-checkbox>
                  <el-checkbox :value="4">周四</el-checkbox>
                  <el-checkbox :value="5">周五</el-checkbox>
                  <el-checkbox :value="6">周六</el-checkbox>
                  <el-checkbox :value="0">周日</el-checkbox>
                </el-checkbox-group>
              </el-form-item>
              <el-form-item label="单日 Token 限额（万）">
                <el-input-number v-model="f.ai_report_tokens_wan" :min="1" :max="1000" :step="1" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">超出当日限额后报告自动暂停，次日恢复</span>
              </el-form-item>
              <el-form-item label="外发渠道">
                <el-radio-group v-model="f.ai_report_channel">
                  <el-radio-button value="webhook">Webhook</el-radio-button>
                  <el-radio-button value="email">邮箱</el-radio-button>
                </el-radio-group>
              </el-form-item>
              <el-form-item v-if="f.ai_report_channel === 'webhook'" label="Webhook URL">
                <el-input v-model="f.ai_report_webhook" placeholder="https://hooks.example.com/kingmoat" class="km-mono" style="width:420px" />
              </el-form-item>
              <template v-else>
                <el-form-item label="收件地址">
                  <el-input v-model="f.ai_report_email" placeholder="ops@corp.com, sec@corp.com" class="km-mono" style="width:420px" />
                  <div class="km-dim" style="font-size:12px;width:100%;margin-top:4px">多个地址用英文逗号分隔；邮箱渠道需先在「告警与通知」配置 SMTP</div>
                </el-form-item>
              </template>
            </template>
            </template>
          </el-form>
        </el-card>
</template>

      <!-- ② 日志外发 -->
      <template v-if="tab === 'logship'">
        <el-alert v-if="loadNotes.length" type="warning" :closable="false" show-icon style="margin-bottom:14px"
                  title="服务启动时已自动处理存量外发配置：部分外发节被归一化或自动关闭，请核对下方配置（保存发布一次后此提示自动消失）">
          <div v-for="(n, i) in loadNotes" :key="i" class="km-load-note">{{ n }}</div>
        </el-alert>
        <el-card shadow="never" style="margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:10px">
            <div class="km-title" style="margin:0">审计日志外发（log_shipper）</div>
            <el-button size="small" style="margin-left:auto" :loading="probeBusy.audit" :disabled="upgTaskActive" @click="runOutboundTest('audit')">
              <el-icon><Promotion /></el-icon>&nbsp;测试连接
            </el-button>
          </div>
          <OutboundProbeResult :result="probeResults.audit" style="margin-top:8px" />
          <el-form label-width="140px" label-position="left" style="margin-top:12px">
            <el-form-item label="启用">
              <el-switch v-model="f.shipper_enabled" />
            </el-form-item>
            <template v-if="f.shipper_enabled">
              <el-form-item label="类型">
                <el-radio-group v-model="f.shipper_type">
                  <el-radio-button value="clickhouse">ClickHouse</el-radio-button>
                  <el-radio-button value="elasticsearch">Elasticsearch</el-radio-button>
                  <el-radio-button value="loki">Loki</el-radio-button>
                  <el-radio-button value="s3">S3 对象存储</el-radio-button>
                  <el-radio-button value="kafka">Kafka</el-radio-button>
                  <el-radio-button value="syslog">Syslog</el-radio-button>
                </el-radio-group>
              </el-form-item>
              <template v-if="!['s3', 'kafka'].includes(f.shipper_type)">
                <el-form-item label="地址">
                  <el-input v-model="f.shipper_url" :placeholder="urlHint" class="km-mono" style="width:420px" />
                </el-form-item>
                <el-form-item label="表 / 索引前缀">
                  <el-input v-model="f.shipper_index" style="width:260px" placeholder="kingmoat" />
                </el-form-item>
                <template v-if="['clickhouse', 'elasticsearch', 'loki'].includes(f.shipper_type)">
                  <el-form-item label="认证用户名">
                    <el-input v-model="f.shipper_user" class="km-mono" style="width:260px" placeholder="无认证则留空" autocomplete="off" />
                  </el-form-item>
                  <el-form-item label="认证密码">
                    <el-input v-model="f.shipper_pass" type="password" show-password class="km-mono" style="width:260px" placeholder="无认证则留空" autocomplete="new-password" />
                  </el-form-item>
                </template>
              </template>
              <template v-if="f.shipper_type === 'syslog'">
                <el-form-item label="消息格式">
                  <el-radio-group v-model="f.shipper_sys_format">
                    <el-radio-button value="rfc5424">RFC 5424</el-radio-button>
                    <el-radio-button value="rfc3164">RFC 3164 (BSD)</el-radio-button>
                  </el-radio-group>
                </el-form-item>
                <el-form-item label="主机名">
                  <el-input v-model="f.shipper_sys_hostname" placeholder="默认本机主机名" style="width:260px" />
                </el-form-item>
              </template>
              <template v-else-if="f.shipper_type === 's3'">
                <el-form-item label="Endpoint"><el-input v-model="f.s3_endpoint" placeholder="minio.internal:9000（不带协议）" class="km-mono" style="width:420px" /></el-form-item>
                <el-form-item label="Bucket"><el-input v-model="f.s3_bucket" placeholder="kingmoat-logs" style="width:260px" /></el-form-item>
                <el-form-item label="对象前缀"><el-input v-model="f.s3_prefix" placeholder="kingmoat" style="width:260px" /></el-form-item>
                <el-form-item label="AccessKey"><el-input v-model="f.s3_ak" class="km-mono" style="width:260px" /></el-form-item>
                <el-form-item label="SecretKey"><el-input v-model="f.s3_sk" type="password" show-password class="km-mono" style="width:260px" /></el-form-item>
                <el-form-item label="使用 HTTPS"><el-switch v-model="f.s3_ssl" /></el-form-item>
              </template>
              <template v-else-if="f.shipper_type === 'kafka'">
                <el-form-item label="Bootstrap 服务器">
                  <el-input v-model="f.shipper_kafka_brokers" type="textarea" :rows="3" class="km-mono"
                            placeholder="每行一个或逗号分隔：&#10;kafka-1.internal:9092&#10;kafka-2.internal:9092" style="width:420px" />
                </el-form-item>
                <el-form-item label="Topic">
                  <el-input v-model="f.shipper_kafka_topic" placeholder="kingmoat-audit" class="km-mono" style="width:260px" />
                </el-form-item>
                <el-form-item label="TLS 加密">
                  <el-switch v-model="f.shipper_kafka_tls" />
                  <span class="km-dim" style="margin-left:10px;font-size:12px">内网自签证书场景默认不校验证书</span>
                </el-form-item>
                <el-form-item v-if="f.shipper_kafka_tls" label="跳过 TLS 证书校验">
                  <el-switch v-model="f.shipper_kafka_tls_skip" />
                  <span class="km-dim" style="margin-left:10px;font-size:12px">内网自签证书保持开启；关闭后将校验 broker 证书</span>
                </el-form-item>
                <el-form-item label="SASL 认证">
                  <el-select v-model="f.shipper_kafka_sasl" style="width:220px">
                    <el-option value="none" label="无认证" />
                    <el-option value="plain" label="PLAIN" />
                    <el-option value="scram-sha256" label="SCRAM-SHA-256" />
                  </el-select>
                </el-form-item>
                <template v-if="f.shipper_kafka_sasl !== 'none'">
                  <el-form-item label="认证用户名">
                    <el-input v-model="f.shipper_user" class="km-mono" style="width:260px" autocomplete="off" />
                  </el-form-item>
                  <el-form-item label="认证密码">
                    <el-input v-model="f.shipper_pass" type="password" show-password class="km-mono" style="width:260px" autocomplete="new-password" />
                  </el-form-item>
                </template>
                <div class="km-dim" style="font-size:12px;padding-left:140px">日志外发配置保存发布后即时生效（无需重启）</div>
              </template>
            </template>
          </el-form>
        </el-card>

        <el-card shadow="never">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <div class="km-title" style="margin:0">全量访问日志管道（access_log）</div>
            <span v-if="f.access_use_audit" class="km-dim" style="font-size:12px">复用已开启：将测试防护日志通道（防护日志外发）与本节身份配置</span>
            <el-button size="small" style="margin-left:auto" :loading="probeBusy.access" :disabled="upgTaskActive" @click="runOutboundTest('access')">
              <el-icon><Promotion /></el-icon>&nbsp;测试连接
            </el-button>
          </div>
          <OutboundProbeResult :result="probeResults.access" style="margin-top:8px" />
          <el-form label-width="140px" label-position="left">
            <div class="km-dim" style="font-size:12px;margin:-6px 0 10px">外发配置保存发布后即时生效（无需重启）；关闭开关仅停外发，控制台实时查看保留</div>
            <el-form-item label="启用">
              <el-switch v-model="f.access_enabled" />
            </el-form-item>
            <template v-if="f.access_enabled">
              <el-form-item label="使用防护日志通道">
                <div>
                  <el-switch v-model="f.access_use_audit" />
                  <div class="km-dim" style="font-size:12px;margin-top:4px;line-height:1.7;max-width:560px">
                    <template v-if="f.access_use_audit">
                      已复用防护日志外发通道，当前实际生效类型：<span class="km-mono">{{ shipperChannelLabel }}</span>；下方置灰的通道字段仅保留备查值（发布时后端忽略），索引前缀、采样率、S3 对象前缀与 syslog APP-NAME 仍由本节独立配置；探测与投递均使用已保存发布的通道配置，表单中未保存的通道改动不参与
                    </template>
                    <template v-else>
                      开启后通道参数（类型/地址/认证等）取自「日志外发」页签的防护日志外发（log_shipper），索引前缀、采样率、S3 对象前缀与 syslog APP-NAME 仍由本节独立配置
                    </template>
                  </div>
                </div>
              </el-form-item>
              <el-alert v-if="f.access_use_audit && !f.shipper_enabled" type="warning" :closable="false" show-icon
                        title="防护日志外发（log_shipper）未启用：请先在「日志外发」页签启用并完成配置，否则无法保存发布" style="margin-bottom:12px" />
              <el-form-item label="类型">
                <el-radio-group v-model="f.access_type" :disabled="f.access_use_audit">
                  <el-radio-button value="clickhouse">ClickHouse</el-radio-button>
                  <el-radio-button value="elasticsearch">Elasticsearch</el-radio-button>
                  <el-radio-button value="loki">Loki</el-radio-button>
                  <el-radio-button value="s3">S3 对象存储</el-radio-button>
                  <el-radio-button value="kafka">Kafka</el-radio-button>
                  <el-radio-button value="syslog">Syslog</el-radio-button>
                </el-radio-group>
              </el-form-item>
              <template v-if="!['s3', 'kafka'].includes(f.access_type)">
                <el-form-item label="地址">
                  <el-input v-model="f.access_url" :placeholder="accessUrlHint" :disabled="f.access_use_audit" class="km-mono" style="width:420px" />
                </el-form-item>
                <el-form-item label="表 / 索引前缀">
                  <el-input v-model="f.access_index" style="width:260px" placeholder="kingmoat_access" />
                </el-form-item>
                <template v-if="['clickhouse', 'elasticsearch', 'loki'].includes(f.access_type)">
                  <el-form-item label="认证用户名">
                    <el-input v-model="f.access_user" :disabled="f.access_use_audit" class="km-mono" style="width:260px" placeholder="无认证则留空" autocomplete="off" />
                  </el-form-item>
                  <el-form-item label="认证密码">
                    <el-input v-model="f.access_pass" type="password" show-password :disabled="f.access_use_audit" class="km-mono" style="width:260px" placeholder="无认证则留空" autocomplete="new-password" />
                  </el-form-item>
                </template>
              </template>
              <template v-if="f.access_type === 'syslog'">
                <el-form-item label="消息格式">
                  <el-radio-group v-model="f.access_sys_format" :disabled="f.access_use_audit">
                    <el-radio-button value="rfc5424">RFC 5424</el-radio-button>
                    <el-radio-button value="rfc3164">RFC 3164 (BSD)</el-radio-button>
                  </el-radio-group>
                </el-form-item>
                <el-form-item label="主机名">
                  <el-input v-model="f.access_sys_hostname" :disabled="f.access_use_audit" placeholder="默认本机主机名" style="width:260px" />
                </el-form-item>
              </template>
              <template v-else-if="f.access_type === 's3'">
                <el-form-item label="Endpoint"><el-input v-model="f.access_s3_endpoint" :disabled="f.access_use_audit" placeholder="minio.internal:9000" class="km-mono" style="width:420px" /></el-form-item>
                <el-form-item label="Bucket"><el-input v-model="f.access_s3_bucket" :disabled="f.access_use_audit" placeholder="kingmoat-logs" style="width:260px" /></el-form-item>
                <el-form-item label="对象前缀"><el-input v-model="f.access_s3_prefix" placeholder="kingmoat" style="width:260px" /></el-form-item>
                <el-form-item label="AccessKey"><el-input v-model="f.access_s3_ak" :disabled="f.access_use_audit" class="km-mono" style="width:260px" /></el-form-item>
                <el-form-item label="SecretKey"><el-input v-model="f.access_s3_sk" type="password" show-password :disabled="f.access_use_audit" class="km-mono" style="width:260px" /></el-form-item>
                <el-form-item label="使用 HTTPS"><el-switch v-model="f.access_s3_ssl" :disabled="f.access_use_audit" /></el-form-item>
              </template>
              <template v-else-if="f.access_type === 'kafka'">
                <el-form-item label="Bootstrap 服务器">
                  <el-input v-model="f.access_kafka_brokers" type="textarea" :rows="3" :disabled="f.access_use_audit" class="km-mono"
                            placeholder="每行一个或逗号分隔：&#10;kafka-1.internal:9092&#10;kafka-2.internal:9092" style="width:420px" />
                </el-form-item>
                <el-form-item label="Topic">
                  <el-input v-model="f.access_kafka_topic" :disabled="f.access_use_audit" placeholder="kingmoat-access" class="km-mono" style="width:260px" />
                </el-form-item>
                <el-form-item label="TLS 加密">
                  <el-switch v-model="f.access_kafka_tls" :disabled="f.access_use_audit" />
                  <span class="km-dim" style="margin-left:10px;font-size:12px">内网自签证书场景默认不校验证书</span>
                </el-form-item>
                <el-form-item v-if="f.access_kafka_tls" label="跳过 TLS 证书校验">
                  <el-switch v-model="f.access_kafka_tls_skip" :disabled="f.access_use_audit" />
                  <span class="km-dim" style="margin-left:10px;font-size:12px">内网自签证书保持开启；关闭后将校验 broker 证书</span>
                </el-form-item>
                <el-form-item label="SASL 认证">
                  <el-select v-model="f.access_kafka_sasl" :disabled="f.access_use_audit" style="width:220px">
                    <el-option value="none" label="无认证" />
                    <el-option value="plain" label="PLAIN" />
                    <el-option value="scram-sha256" label="SCRAM-SHA-256" />
                  </el-select>
                </el-form-item>
                <template v-if="f.access_kafka_sasl !== 'none'">
                  <el-form-item label="认证用户名">
                    <el-input v-model="f.access_user" :disabled="f.access_use_audit" class="km-mono" style="width:260px" autocomplete="off" />
                  </el-form-item>
                  <el-form-item label="认证密码">
                    <el-input v-model="f.access_pass" type="password" show-password :disabled="f.access_use_audit" class="km-mono" style="width:260px" autocomplete="new-password" />
                  </el-form-item>
                </template>
              </template>
              <el-form-item v-if="f.access_use_audit && f.access_type !== 's3'" label="对象前缀">
                <el-input v-model="f.access_s3_prefix" placeholder="kingmoat" style="width:260px" :disabled="accessEffType !== 's3'" />
                <span class="km-dim" style="font-size:12px;margin-left:10px">
                  {{ accessEffType === 's3'
                    ? '复用通道时对象存储连接取自防护日志通道，对象前缀仍由本节独立配置'
                    : '当前生效通道非 S3，对象前缀暂不参与外发；已保存的值在保存发布时保留，生效类型切回 S3 后继续使用' }}
                </span>
              </el-form-item>
              <el-form-item label="采样率 %">
                <el-slider v-model="f.access_sample" :min="1" :max="100" show-input style="width:320px" />
              </el-form-item>
            </template>
          </el-form>
        </el-card>
      </template>


      <!-- AI 会话审计 -->
      <template v-if="tab === 'aiaudit'">
        <el-alert v-if="loadNotes.length" type="warning" :closable="false" show-icon style="margin-bottom:14px"
                  title="服务启动时已自动处理存量外发配置：部分外发节被归一化或自动关闭，请核对下方配置（保存发布一次后此提示自动消失）">
          <div v-for="(n, i) in loadNotes" :key="i" class="km-load-note">{{ n }}</div>
        </el-alert>
        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">AI 会话审计（ai_audit）</div>
          <el-alert type="info" :closable="false" show-icon style="margin:10px 0"
                    title="识别经过 WAF 的 LLM API 调用（OpenAI / Anthropic / Gemini 及国产大模型协议），捕获请求报文与模型输出全文，形成可审计会话记录。仅命中才记录，异步落盘不影响转发时延；多模态图片/音频一律以占位符替代。" />
          <el-form label-width="140px" label-position="left" style="margin-top:12px">
            <el-form-item label="启用">
              <el-switch v-model="f.aiaudit_enabled" />
            </el-form-item>
            <template v-if="f.aiaudit_enabled">
              <el-form-item label="脱敏（推荐开启）">
                <el-switch v-model="f.aiaudit_redact" />
                <span class="km-dim" style="font-size:12px;margin-left:10px">自动掩码密钥 / 口令等高信号敏感串；关闭后对话全文明文入库，请确认业务允许</span>
              </el-form-item>
              <el-form-item label="采样率 %">
                <el-slider v-model="f.aiaudit_sample" :min="1" :max="100" show-input style="width:320px" />
              </el-form-item>
              <el-form-item label="请求截断上限 KB">
                <el-input-number v-model="f.aiaudit_max_req_kb" :min="4" :max="512" size="small" />
                <span class="km-dim" style="font-size:12px;margin-left:10px">超出部分截断并打标记</span>
              </el-form-item>
              <el-form-item label="输出截断上限 KB">
                <el-input-number v-model="f.aiaudit_max_resp_kb" :min="4" :max="512" size="small" />
              </el-form-item>
              <el-form-item label="审计 embeddings">
                <el-switch v-model="f.aiaudit_embed" />
                <span class="km-dim" style="font-size:12px;margin-left:10px">向量接口的响应无审计价值，默认仅记录请求元数据</span>
              </el-form-item>
              <el-form-item label="记录未知协议">
                <el-switch v-model="f.aiaudit_unknown" />
                <span class="km-dim" style="font-size:12px;margin-left:10px">LLM 形态但未识别协议的调用，以 provider=unknown 记录元数据</span>
              </el-form-item>
              <el-form-item label="保留期（天）">
                <el-input-number v-model="f.aiaudit_retention" :min="1" :max="365" size="small" />
                <span class="km-dim" style="font-size:12px;margin-left:10px">会话库保留期，每日自动清理</span>
              </el-form-item>
            </template>
          </el-form>
        </el-card>
        <el-card shadow="never" v-if="f.aiaudit_enabled">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <div class="km-title" style="margin:0">AI 会话外发（可选）</div>
            <span v-if="f.aiaudit_ship_use_audit" class="km-dim" style="font-size:12px">复用已开启：将测试防护日志通道（防护日志外发）与本节身份配置</span>
            <el-button size="small" style="margin-left:auto" :loading="probeBusy.ai" :disabled="upgTaskActive" @click="runOutboundTest('ai')">
              <el-icon><Promotion /></el-icon>&nbsp;测试连接
            </el-button>
          </div>
          <OutboundProbeResult :result="probeResults.ai" style="margin-top:8px" />
          <el-form label-width="140px" label-position="left" style="margin-top:12px">
            <el-form-item label="启用外发">
              <el-switch v-model="f.aiaudit_ship_enabled" />
            </el-form-item>
            <template v-if="f.aiaudit_ship_enabled">
              <el-form-item label="使用防护日志通道">
                <div>
                  <el-switch v-model="f.aiaudit_ship_use_audit" />
                  <div class="km-dim" style="font-size:12px;margin-top:4px;line-height:1.7;max-width:560px">
                    <template v-if="f.aiaudit_ship_use_audit">
                      已复用防护日志外发通道，当前实际生效类型：<span class="km-mono">{{ shipperChannelLabel }}</span>；下方置灰的通道字段仅保留备查值（发布时后端忽略），索引前缀、采样率、S3 对象前缀与 syslog APP-NAME 仍由本节独立配置；探测与投递均使用已保存发布的通道配置，表单中未保存的通道改动不参与
                    </template>
                    <template v-else>
                      开启后通道参数（类型/地址/认证等）取自「日志外发」页签的防护日志外发（log_shipper），索引前缀、采样率、S3 对象前缀与 syslog APP-NAME 仍由本节独立配置
                    </template>
                  </div>
                </div>
              </el-form-item>
              <el-alert v-if="f.aiaudit_ship_use_audit && !f.shipper_enabled" type="warning" :closable="false" show-icon
                        title="防护日志外发（log_shipper）未启用：请先在「日志外发」页签启用并完成配置，否则无法保存发布" style="margin-bottom:12px" />
              <el-form-item label="后端类型">
                <el-select v-model="f.aiaudit_ship_type" :disabled="f.aiaudit_ship_use_audit" style="width:220px">
                  <el-option label="ClickHouse" value="clickhouse" />
                  <el-option label="Elasticsearch" value="elasticsearch" />
                  <el-option label="Loki" value="loki" />
                  <el-option label="S3 对象存储" value="s3" />
                  <el-option label="Kafka" value="kafka" />
                  <el-option label="Syslog" value="syslog" />
                </el-select>
              </el-form-item>
              <template v-if="!['s3', 'kafka'].includes(f.aiaudit_ship_type)">
                <el-form-item label="地址">
                  <el-input v-model="f.aiaudit_ship_url" :placeholder="aiauditShipUrlHint" :disabled="f.aiaudit_ship_use_audit" class="km-mono" style="width:420px" />
                </el-form-item>
                <el-form-item label="索引前缀">
                  <el-input v-model="f.aiaudit_ship_index" placeholder="kingmoat_ai_sessions" class="km-mono" style="width:260px" />
                  <span class="km-dim" style="font-size:12px;margin-left:10px">ES 按此写入 {前缀}-YYYY.MM.DD 日索引；ClickHouse 为表名；Loki 为 app 标签</span>
                </el-form-item>
                <template v-if="['clickhouse', 'elasticsearch', 'loki'].includes(f.aiaudit_ship_type)">
                  <el-form-item label="认证用户名">
                    <el-input v-model="f.aiaudit_ship_user" :disabled="f.aiaudit_ship_use_audit" class="km-mono" style="width:260px" placeholder="无认证则留空" autocomplete="off" />
                  </el-form-item>
                  <el-form-item label="认证密码">
                    <el-input v-model="f.aiaudit_ship_pass" type="password" show-password :disabled="f.aiaudit_ship_use_audit" class="km-mono" style="width:260px" placeholder="无认证则留空" autocomplete="new-password" />
                  </el-form-item>
                </template>
              </template>
              <template v-if="f.aiaudit_ship_type === 'syslog'">
                <el-form-item label="消息格式">
                  <el-radio-group v-model="f.aiaudit_ship_sys_format" :disabled="f.aiaudit_ship_use_audit">
                    <el-radio-button value="rfc5424">RFC 5424</el-radio-button>
                    <el-radio-button value="rfc3164">RFC 3164 (BSD)</el-radio-button>
                  </el-radio-group>
                </el-form-item>
                <el-form-item label="主机名">
                  <el-input v-model="f.aiaudit_ship_sys_hostname" :disabled="f.aiaudit_ship_use_audit" placeholder="默认本机主机名" style="width:260px" />
                </el-form-item>
              </template>
              <template v-else-if="f.aiaudit_ship_type === 's3'">
                <el-form-item label="Endpoint"><el-input v-model="f.aiaudit_ship_s3_endpoint" :disabled="f.aiaudit_ship_use_audit" placeholder="minio.internal:9000（不带协议）" class="km-mono" style="width:420px" /></el-form-item>
                <el-form-item label="Bucket"><el-input v-model="f.aiaudit_ship_s3_bucket" :disabled="f.aiaudit_ship_use_audit" placeholder="kingmoat-logs" style="width:260px" /></el-form-item>
                <el-form-item label="对象前缀"><el-input v-model="f.aiaudit_ship_s3_prefix" placeholder="kingmoat/ai" style="width:260px" /></el-form-item>
                <el-form-item label="AccessKey"><el-input v-model="f.aiaudit_ship_s3_ak" :disabled="f.aiaudit_ship_use_audit" class="km-mono" style="width:260px" /></el-form-item>
                <el-form-item label="SecretKey"><el-input v-model="f.aiaudit_ship_s3_sk" type="password" show-password :disabled="f.aiaudit_ship_use_audit" class="km-mono" style="width:260px" /></el-form-item>
                <el-form-item label="使用 HTTPS"><el-switch v-model="f.aiaudit_ship_s3_ssl" :disabled="f.aiaudit_ship_use_audit" /></el-form-item>
              </template>
              <template v-else-if="f.aiaudit_ship_type === 'kafka'">
                <el-form-item label="Bootstrap 服务器">
                  <el-input v-model="f.aiaudit_ship_kafka_brokers" type="textarea" :rows="3" :disabled="f.aiaudit_ship_use_audit" class="km-mono"
                            placeholder="每行一个或逗号分隔：&#10;kafka-1.internal:9092&#10;kafka-2.internal:9092" style="width:420px" />
                </el-form-item>
                <el-form-item label="Topic">
                  <el-input v-model="f.aiaudit_ship_kafka_topic" :disabled="f.aiaudit_ship_use_audit" placeholder="kingmoat-ai" class="km-mono" style="width:260px" />
                </el-form-item>
                <el-form-item label="TLS 加密">
                  <el-switch v-model="f.aiaudit_ship_kafka_tls" :disabled="f.aiaudit_ship_use_audit" />
                  <span class="km-dim" style="margin-left:10px;font-size:12px">内网自签证书场景默认不校验证书</span>
                </el-form-item>
                <el-form-item v-if="f.aiaudit_ship_kafka_tls" label="跳过 TLS 证书校验">
                  <el-switch v-model="f.aiaudit_ship_kafka_tls_skip" :disabled="f.aiaudit_ship_use_audit" />
                  <span class="km-dim" style="margin-left:10px;font-size:12px">内网自签证书保持开启；关闭后将校验 broker 证书</span>
                </el-form-item>
                <el-form-item label="SASL 认证">
                  <el-select v-model="f.aiaudit_ship_kafka_sasl" :disabled="f.aiaudit_ship_use_audit" style="width:220px">
                    <el-option value="none" label="无认证" />
                    <el-option value="plain" label="PLAIN" />
                    <el-option value="scram-sha256" label="SCRAM-SHA-256" />
                  </el-select>
                </el-form-item>
                <template v-if="f.aiaudit_ship_kafka_sasl !== 'none'">
                  <el-form-item label="认证用户名">
                    <el-input v-model="f.aiaudit_ship_user" :disabled="f.aiaudit_ship_use_audit" class="km-mono" style="width:260px" autocomplete="off" />
                  </el-form-item>
                  <el-form-item label="认证密码">
                    <el-input v-model="f.aiaudit_ship_pass" type="password" show-password :disabled="f.aiaudit_ship_use_audit" class="km-mono" style="width:260px" autocomplete="new-password" />
                  </el-form-item>
                </template>
              </template>
              <el-form-item v-if="f.aiaudit_ship_use_audit && f.aiaudit_ship_type !== 's3'" label="对象前缀">
                <el-input v-model="f.aiaudit_ship_s3_prefix" placeholder="kingmoat/ai" style="width:260px" :disabled="aiauditEffType !== 's3'" />
                <span class="km-dim" style="font-size:12px;margin-left:10px">
                  {{ aiauditEffType === 's3'
                    ? '复用通道时对象存储连接取自防护日志通道，对象前缀仍由本节独立配置'
                    : '当前生效通道非 S3，对象前缀暂不参与外发；已保存的值在保存发布时保留，生效类型切回 S3 后继续使用' }}
                </span>
              </el-form-item>
              <el-form-item label="采样率 %">
                <el-slider v-model="f.aiaudit_ship_sample" :min="1" :max="100" show-input style="width:320px" />
                <span class="km-dim" style="font-size:12px;margin-left:10px">仅对外发投递采样，与上方捕获采样率相互独立；复用防护日志通道时仍属本节配置，保存时随本节提交</span>
              </el-form-item>
            </template>
          </el-form>
          <div class="km-dim" style="font-size:12px;padding-left:140px">AI 会话审计与外发配置保存发布后即时生效（无需重启）。</div>
        </el-card>
      </template>

      <!-- ④ 安全设置（迁回：密码策略 / 会话超时 / 管理面板访问限制） -->
      <template v-if="tab === 'security'">
        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">密码与会话策略</div>
          <el-form label-width="190px" label-position="left">
            <el-form-item label="密码最小长度">
              <el-input-number v-model="f.sec_min_len" :min="6" :max="64" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">创建用户与修改密码时生效（默认 8；已有密码不受影响）</span>
            </el-form-item>
            <el-form-item label="密码复杂度">
              <el-switch v-model="f.sec_complexity" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">需同时包含大写 / 小写 / 数字</span>
            </el-form-item>
            <el-form-item label="密码有效期（天）">
              <el-input-number v-model="f.sec_max_age" :min="0" :max="3650" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">超期登录将被拒绝并提示重置（0 = 不启用）</span>
            </el-form-item>
            <el-form-item label="密码历史次数">
              <el-input-number v-model="f.sec_pw_history" :min="0" :max="24" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">改密时不可与最近 N 次用过的密码相同（0 = 不启用）</span>
            </el-form-item>
            <el-form-item label="会话空闲超时（分钟）">
              <el-input-number v-model="f.sec_session" :min="0" :max="10080" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">登录态有效期，保存后需重启生效（0 = 默认 12 小时；顶部「服务重启」卡片可执行）</span>
            </el-form-item>
            <el-form-item label="登录错误锁定">
              <el-input-number v-model="f.sec_login_max" :min="3" :max="100" style="width:130px" />
              <span class="km-dim" style="margin:0 6px;font-size:12px">次失败后锁定</span>
              <el-input-number v-model="f.sec_lockout_min" :min="1" :max="1440" style="width:120px" />
              <span class="km-dim" style="margin-left:6px;font-size:12px">分钟（同一来源 IP，滑动窗口；默认 10 次 / 15 分钟）</span>
            </el-form-item>
          </el-form>
        </el-card>
        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">管理面板访问限制</div>
          <el-form label-width="140px" label-position="left">
            <el-form-item label="允许的来源 IP">
              <div style="width:100%">
                <div v-for="(ip, i) in f.console_ips" :key="i" style="display:flex;gap:8px;margin-bottom:6px">
                  <el-input v-model="f.console_ips[i]" placeholder="IP/CIDR，如 10.0.0.0/8" class="km-mono" />
                  <el-button link type="danger" @click="f.console_ips.splice(i, 1)"><el-icon><Delete /></el-icon></el-button>
                </div>
                <el-button size="small" @click="f.console_ips.push('')"><el-icon><Plus /></el-icon>&nbsp;新增</el-button>
                
              </div>
            </el-form-item>
          </el-form>
        </el-card>
        <el-card shadow="never">
          <div class="km-title">拦截页面定制（阻断页）</div>
          <el-form label-width="110px" label-position="left">
            <el-form-item label="页面标题">
              <el-input v-model="f.bp_title" placeholder="请求被拦截 · Blocked by KingMoat" style="width:420px" />
            </el-form-item>
            <el-form-item label="说明文字">
              <el-input v-model="f.bp_message" type="textarea" :rows="2" style="width:420px"
                        placeholder="该请求触发了安全防护规则，已被拒绝访问。" />
            </el-form-item>
            <el-form-item label="页脚">
              <el-input v-model="f.bp_footer" placeholder="KingMoat WAF — 固若金汤，御攻于无形" style="width:420px" />
            </el-form-item>
            <el-form-item label="自定义 HTML">
              <div style="width:100%">
                <el-input v-model="f.bp_html" type="textarea" :rows="8" class="km-mono" spellcheck="false"
                          placeholder="留空使用内置拦截页；填写完整 HTML（≤256KB）将整体替换内置页面" />
                <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:6px;align-items:center">
                  <span class="km-dim" style="font-size:12px">可用变量（点击插入）：</span>
                  <div v-for="v in bpVars" :key="v" class="km-chip km-mono" style="padding:2px 8px;font-size:11px" @click="insertBpVar(v)">{{ v }}</div>
                </div>
                <div class="km-dim" style="font-size:12px;margin-top:6px">
                  引擎响应时替换为请求上下文；保存时服务端会拒绝包含 script / 内联事件 / javascript: 的页面（防存储型 XSS）
                </div>
                <div style="margin-top:10px">
                  <div class="km-dim" style="font-size:12px;margin-bottom:6px">实时预览（变量已替换为示例值）</div>
                  <iframe v-if="bpPreview" :srcdoc="bpPreview" sandbox="allow-forms"
                          style="width:100%;height:300px;border:1px solid var(--km-line);border-radius:8px;background:#fff" />
                </div>
              </div>
            </el-form-item>
          </el-form>
        </el-card>
      </template>

      <!-- ⑤ 告警与通知 -->
      <template v-if="tab === 'alerts'">
        <el-card shadow="never" style="margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
            <div class="km-title" style="margin:0">告警引擎</div>
            <el-switch v-model="f.alerts_enabled" style="margin-left:auto" />
          </div>
          <el-form label-width="150px" label-position="left">
            <el-form-item label="评估间隔（秒）">
              <el-input-number v-model="f.alerts_interval" :min="10" :max="3600" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">默认 60；同时是 CPU/内存规则的 1 分钟采样窗</span>
            </el-form-item>
            <el-form-item label="告警冷却（分钟）">
              <el-input-number v-model="f.alerts_cooldown" :min="1" :max="1440" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">同一规则两次通知的最小间隔（默认 10）</span>
            </el-form-item>
            <el-form-item label="Webhook 通知">
              <el-switch v-model="f.alerts_webhook" />
            </el-form-item>
            <el-form-item label="邮件通知">
              <el-switch v-model="f.alerts_email" />
            </el-form-item>
          </el-form>
        </el-card>

        <el-card shadow="never" style="margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
            <div class="km-title" style="margin:0">告警阈值（全部可调）</div>
          </div>
          <div class="km-set-row" v-for="r in alertRuleDefs" :key="r.key">
            <div class="grow">
              <div class="set-name">{{ r.name }}</div>
              <div class="set-desc">{{ r.desc }}</div>
            </div>
            <el-switch v-model="f.alert_rules[r.key].enabled" />
            <el-input-number v-model="f.alert_rules[r.key].threshold" :min="r.min" :max="r.max" size="small" style="width:130px" />
            <span class="km-muted" style="font-size:12px;width:60px">{{ r.unit }}</span>
            <template v-if="r.window">
              <span class="km-muted" style="font-size:12px">持续</span>
              <el-input-number v-model="f.alert_rules[r.key].window_sec" :min="10" :max="3600" size="small" style="width:100px" />
              <span class="km-muted" style="font-size:12px">秒</span>
            </template>
          </div>
        </el-card>

        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">通知渠道 · Webhook</div>
          <el-form label-width="130px" label-position="left">
            <el-form-item label="推送地址">
              <el-input v-model="f.webhook_url" placeholder="https://hooks.example.com/kingmoat" class="km-mono" style="width:100%" />
            </el-form-item>
            <el-form-item label="加签密钥">
              <el-input v-model="f.webhook_secret" placeholder="留空不加签；填写后每条通知带 X-KingMoat-Signature 头（HMAC-SHA256）" class="km-mono" style="width:100%" show-password />
            </el-form-item>
            <el-form-item label="关键词认证">
              <el-input v-model="f.webhook_keyword" placeholder="如 企业微信/钉钉机器人关键词；填写后通知 JSON 携带 keyword 字段" style="width:100%" />
            </el-form-item>
          </el-form>
        </el-card>

        <el-card shadow="never">
          <div class="km-title">通知渠道 · 邮件（SMTP）</div>
          <el-form label-width="130px" label-position="left">
            <el-form-item label="启用邮件通道">
              <el-switch v-model="f.email_enabled" />
            </el-form-item>
            <template v-if="f.email_enabled">
              <el-form-item label="SMTP 服务器">
                <div style="display:flex;gap:8px;align-items:center;width:100%">
                  <el-input v-model="f.email_host" placeholder="smtp.example.com" class="km-mono" style="flex:1" />
                  <el-input-number v-model="f.email_port" :min="1" :max="65535" size="small" style="width:110px" />
                  <el-switch v-model="f.email_ssl" active-text="SSL" />
                </div>
              </el-form-item>
              <el-form-item label="发件人">
                <el-input v-model="f.email_from" placeholder="waf@example.com" class="km-mono" style="width:100%" />
              </el-form-item>
              <el-form-item label="账号 / 密码">
                <div style="display:flex;gap:8px;width:100%">
                  <el-input v-model="f.email_user" placeholder="SMTP 用户名" class="km-mono" style="flex:1" />
                  <el-input v-model="f.email_pass" type="password" show-password placeholder="SMTP 密码" class="km-mono" style="flex:1" />
                </div>
              </el-form-item>
              <el-form-item label="收件人">
                <div style="width:100%">
                  <div v-for="(to, i) in f.email_to" :key="i" style="display:flex;gap:8px;margin-bottom:6px">
                    <el-input v-model="f.email_to[i]" placeholder="ops@example.com" class="km-mono" />
                    <el-button link type="danger" @click="f.email_to.splice(i, 1)"><el-icon><Delete /></el-icon></el-button>
                  </div>
                  <el-button size="small" @click="f.email_to.push('')"><el-icon><Plus /></el-icon>&nbsp;新增收件人</el-button>
                </div>
              </el-form-item>
            </template>
          </el-form>
        </el-card>
      </template>

      <div style="text-align:right">
        <el-button type="primary" size="large" :loading="saving" :disabled="!can('operator') || upgTaskActive" @click="save">
          保存并发布（热生效）
        </el-button>
      </div>
    </div>

    <!-- 管理界面端口更换确认 -->
    <el-dialog v-model="portDlg" title="更换管理界面端口" width="540px" :close-on-click-modal="false">
      <el-alert type="warning" :closable="false" show-icon style="margin-bottom:14px"
                title="保存后服务将自动重启，约 30 秒内控制台不可访问" />
      <el-form label-width="90px" label-position="left">
        <el-form-item label="当前端口"><span class="km-mono">{{ portInfo?.port }}</span></el-form-item>
        <el-form-item label="新端口">
          <el-input-number v-model="portForm.port" :min="1" :max="65535" :controls="false" class="km-mono" style="width:160px" />
        </el-form-item>
      </el-form>
      <div class="km-dim" style="font-size:12px;line-height:1.9">
        重启完成后请用新地址访问：<span class="km-mono">{{ portPreviewUrl }}</span><br />
        当前浏览器标签页将随重启失联；若重启后无法访问，请登录服务器按部署文档「控制台端口更换与失联恢复」小节手工恢复（改回 console.env 后 systemctl restart kingmoatwaf）。
      </div>
      <template #footer>
        <el-button @click="portDlg = false">取消</el-button>
        <el-button type="primary" :loading="portChanging" :disabled="!portForm.port || portForm.port === portInfo?.port" @click="submitPort">确认更换</el-button>
      </template>
    </el-dialog>

    <!-- OpenAPI 清单弹窗 -->
    
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, applyNotice, can, del, outboundTest, post, role } from '../api'
import { parseListenAddr } from '../listen'
import { sinkTypeLabel } from '../sinkTypes'
import OutboundProbeResult from '../components/OutboundProbeResult.vue'

const tabs = [
  { id: 'general', name: '通用设置', icon: '⚙️' },
  { id: 'logship', name: '日志外发', icon: '📤' },
  { id: 'aiaudit', name: 'AI 会话审计', icon: '🤖' },
  { id: 'alerts', name: '告警与通知', icon: '🔔' },
  { id: 'security', name: '安全设置', icon: '🔒' },
]
const tab = ref('general')

const saving = ref(false)
// 外发渠道测试（三卡共用）：audit=防护日志 / access=访问日志 / ai=AI 会话
const probeBusy = reactive({ audit: false, access: false, ai: false })
const probeResults = reactive({ audit: null, access: null, ai: null })

// 告警阈值规则定义(顺序即展示顺序;阈值区间为 UI 约束)
const alertRuleDefs = [
  { key: 'cpu', name: 'CPU 使用率过高', desc: 'CPU 使用率连续超过阈值', unit: '%', min: 1, max: 100, window: true },
  { key: 'mem', name: '内存使用率过高', desc: '内存使用率连续超过阈值', unit: '%', min: 1, max: 100, window: true },
  { key: 'disk', name: '磁盘使用率过高', desc: '数据盘使用率超过阈值(瞬时)', unit: '%', min: 1, max: 100 },
  { key: 'requests', name: '出现大量 Web 请求', desc: '1 分钟内 Web 请求超过阈值', unit: '次/分', min: 10, max: 10000000 },
  { key: 'attacks', name: '出现大量 Web 攻击', desc: '1 分钟内 Web 攻击事件超过阈值', unit: '次/分', min: 10, max: 10000000 },
  { key: 'blocked', name: '请求大量被拦截', desc: '1 分钟内拦截请求超过阈值', unit: '次/分', min: 10, max: 10000000 },
  { key: 'top_ip', name: '攻击 IP 排名告警', desc: '1 小时内单 IP 攻击次数超过阈值', unit: '次/时', min: 10, max: 10000000 },
  { key: 'top_target', name: '攻击目标排名告警', desc: '1 小时内单目标被攻击超过阈值', unit: '次/时', min: 10, max: 10000000 },
]

const f = reactive({
  // 数据面监听（从站点防护页迁入，仅监听地址；随「保存并发布」整份发布）
  listen_http: '', listen_https: '',
  capture_requests: false,
  api_assets_enabled: false,
  risks_enabled: false,
  audit_retention_days: 7,
  archive_retention_days: 30,
  query_degraded: false,
  metrics_enabled: false,
  metrics_push_url: '', metrics_push_interval: 30, metrics_push_token: '',
  // 告警与通知
  alerts_enabled: false, alerts_interval: 60, alerts_cooldown: 10,
  alerts_webhook: false, alerts_email: false,
  webhook_url: '',
  alert_rules: {
    cpu: { enabled: true, threshold: 80, window_sec: 60 }, mem: { enabled: true, threshold: 80, window_sec: 60 },
    disk: { enabled: true, threshold: 80 }, requests: { enabled: true, threshold: 20000 },
    attacks: { enabled: true, threshold: 10000 }, blocked: { enabled: true, threshold: 10000 },
    top_ip: { enabled: true, threshold: 20000 }, top_target: { enabled: true, threshold: 20000 },
  },
  email_enabled: false, email_host: '', email_port: 465, email_from: '',
  email_user: '', email_pass: '', email_ssl: true, email_to: [],
  // 安全设置
  sec_min_len: 8, sec_complexity: false, sec_max_age: 0, sec_session: 0,
  telemetry_enabled: false,
  sec_pw_history: 0, sec_login_max: 10, sec_lockout_min: 15,
  bp_title: '', bp_message: '', bp_footer: '', bp_html: '',
  shipper_enabled: false, shipper_type: 'clickhouse', shipper_url: '', shipper_index: 'kingmoat',
  shipper_sys_format: 'rfc5424', shipper_sys_hostname: '',
  shipper_kafka_brokers: '', shipper_kafka_topic: '', shipper_kafka_tls: false, shipper_kafka_tls_skip: true, shipper_kafka_sasl: 'none',
  access_enabled: false, access_type: 'clickhouse', access_url: '', access_index: 'kingmoat_access', access_sample: 100,
  access_use_audit: false,
  access_sys_format: 'rfc5424', access_sys_hostname: '',
  access_kafka_brokers: '', access_kafka_topic: '', access_kafka_tls: false, access_kafka_tls_skip: true, access_kafka_sasl: 'none',
  // 访问日志本地记录（access_log_record 独立顶层节，与外发 access_log 相互独立）
  access_record_mode: 'off', access_record_sites: [], access_record_retention_days: 7, access_record_max_disk_mb: 1024,
  console_ips: [],
  ai_enabled: false, ai_template: 'openai', ai_base: '', ai_model: '',
  ai_max_tokens: 4096, ai_ctx_tokens: 0, ai_keep_turns: 4, ai_temperature: 0.2, ai_timeout: 120, ai_sysprompt: '',
  ai_history_days: 0,
  ai_sanitize: true,
  ai_analysis: false, ai_report_time: '08:00', ai_report_days: [1, 2, 3, 4, 5, 6, 0],
  ai_report_tokens_wan: 20, ai_report_channel: 'webhook', ai_report_webhook: '', ai_report_email: '',
  s3_endpoint: '', s3_bucket: '', s3_prefix: 'kingmoat', s3_ak: '', s3_sk: '', s3_ssl: false,
  access_s3_endpoint: '', access_s3_bucket: '', access_s3_prefix: 'kingmoat', access_s3_ak: '', access_s3_sk: '', access_s3_ssl: false,
  // AI 会话审计（识别 LLM 流量并捕获请求/输出全文）
  aiaudit_enabled: false, aiaudit_sample: 100,
  aiaudit_max_req_kb: 32, aiaudit_max_resp_kb: 64,
  aiaudit_redact: true, aiaudit_embed: false, aiaudit_unknown: false,
  aiaudit_retention: 30,
  aiaudit_ship_enabled: false, aiaudit_ship_use_audit: false, aiaudit_ship_type: 'elasticsearch', aiaudit_ship_url: '', aiaudit_ship_index: 'kingmoat_ai_sessions',
  aiaudit_ship_sample: 100, // A3：外发采样率（1..100）是本节身份字段，整节替换保存时必须显式提交，否则已存值被静默清零
  aiaudit_ship_user: '', aiaudit_ship_pass: '',
  aiaudit_ship_sys_format: 'rfc5424', aiaudit_ship_sys_hostname: '',
  aiaudit_ship_kafka_brokers: '', aiaudit_ship_kafka_topic: '', aiaudit_ship_kafka_tls: false, aiaudit_ship_kafka_tls_skip: true, aiaudit_ship_kafka_sasl: 'none',
  aiaudit_ship_s3_endpoint: '', aiaudit_ship_s3_bucket: '', aiaudit_ship_s3_prefix: 'kingmoat/ai', aiaudit_ship_s3_ak: '', aiaudit_ship_s3_sk: '', aiaudit_ship_s3_ssl: false
})

// ---- 数据面监听（从站点防护页迁入）：输入即时校验，保存前再拦截 ----
const listenHttpError = computed(() => { const r = parseListenAddr(f.listen_http); return r.ok ? '' : r.msg })
const listenHttpsError = computed(() => { const r = parseListenAddr(f.listen_https); return r.ok ? '' : r.msg })
const listenPortConflict = computed(() => {
  const a = parseListenAddr(f.listen_http)
  const b = parseListenAddr(f.listen_https)
  return a.ok && b.ok && !a.empty && !b.empty && a.port === b.port
})
const listenPairEmpty = computed(() => {
  const a = parseListenAddr(f.listen_http)
  const b = parseListenAddr(f.listen_https)
  return a.empty && b.empty
})

// AI Key 存库：状态徽标 + 保存/清除（仅 admin；密钥只在请求体内，不回显）
const aiKeyInput = ref('')
const aiKeySaving = ref(false)
const aiKeySource = ref('')
const keySourceLabel = computed(() => ({ stored: '已存库', env: '环境变量', none: '未配置' }[aiKeySource.value] || '未启用'))
const keySourceTag = computed(() => ({ stored: 'success', env: 'warning', none: 'info' }[aiKeySource.value] || 'info'))

async function refreshAIKeyStatus() {
  try {
    const d = await api('/api/ai/config')
    aiKeySource.value = d.enabled ? (d.key_source || 'none') : ''
  } catch (e) { aiKeySource.value = '' }
}

async function saveAIKey() {
  const key = (aiKeyInput.value || '').trim()
  if (!key) return ElMessage.warning('请先粘贴 API Key')
  aiKeySaving.value = true
  try {
    await post('/api/ai/key', { key })
    ElMessage.success('API Key 已存库并热生效')
    aiKeyInput.value = ''
    await refreshAIKeyStatus()
  } catch (e) {
    ElMessage.error('保存失败：' + e.message)
  } finally {
    aiKeySaving.value = false
  }
}

async function clearAIKey() {
  try {
    await ElMessageBox.confirm('清除后助手将回退到环境变量取 Key（若无则不可用）。确认清除已存库的 API Key？', '清除 API Key', { type: 'warning', confirmButtonText: '清除', cancelButtonText: '取消' })
  } catch (e) { return }
  aiKeySaving.value = true
  try {
    await del('/api/ai/key')
    ElMessage.success('已清除存库 API Key')
    await refreshAIKeyStatus()
  } catch (e) {
    ElMessage.error('清除失败：' + e.message)
  } finally {
    aiKeySaving.value = false
  }
}

const urlHint = computed(() =>
  ({ clickhouse: 'http://ch:8123', elasticsearch: 'http://es:9200', loki: 'http://loki:3100', syslog: 'udp://siem.internal:514', kafka: 'broker1:9092, broker2:9092' }[f.shipper_type] || ''))
const accessUrlHint = computed(() =>
  ({ clickhouse: 'http://ch:8123', elasticsearch: 'http://es:9200', loki: 'http://loki:3100', syslog: 'udp://siem.internal:514' }[f.access_type] || ''))
const aiauditShipUrlHint = computed(() =>
  ({ clickhouse: 'http://ch:8123', elasticsearch: 'http://es:9200', loki: 'http://loki:3100', syslog: 'udp://siem.internal:514' }[f.aiaudit_ship_type] || ''))

// 外发 sink 类型显示名（复用防护日志通道时提示当前实际生效的类型；映射表见 src/sinkTypes.js 单一来源）
const shipperChannelLabel = computed(() => sinkTypeLabel(f.shipper_type))
// 复用通道时的有效后端类型：开关打开且防护日志外发已启用 → 通道类型；否则本节自身类型
const accessEffType = computed(() => (f.access_use_audit && f.shipper_enabled) ? f.shipper_type : f.access_type)
const aiauditEffType = computed(() => (f.aiaudit_ship_use_audit && f.shipper_enabled) ? f.shipper_type : f.aiaudit_ship_type)

// ===== 管理界面端口（console.env + 自动重启，独立于配置发布流程）=====
const portInfo = ref(null)
const portDlg = ref(false)
const portChanging = ref(false)
const portForm = reactive({ port: null })
const portResult = ref(null)
let portCountdown = null

const portPreviewUrl = computed(() =>
  portForm.port ? `https://${location.hostname}:${portForm.port}` : '-')

async function loadConsolePort() {
  try { portInfo.value = await api('/api/settings/console-port') } catch (e) { portInfo.value = null }
}

function openPortDlg() {
  portForm.port = null
  portDlg.value = true
}

async function submitPort() {
  const p = Number(portForm.port)
  if (!Number.isInteger(p) || p < 1 || p > 65535) return ElMessage.error('端口需在 1-65535 之间')
  if (portInfo.value && p === portInfo.value.port) return ElMessage.error('新端口与当前端口相同')
  portChanging.value = true
  try {
    const r = await post('/api/settings/console-port', { port: p })
    // 提交成功即更新本地展示；服务即将重启，约 30 秒后旧地址失联
    portInfo.value = { ...(portInfo.value || {}), port: p }
    portResult.value = { port: p, url: `https://${location.hostname}:${p}`, seconds: 30 }
    if (portCountdown) clearInterval(portCountdown)
    portCountdown = setInterval(() => {
      if (portResult.value && portResult.value.seconds > 0) portResult.value.seconds--
      else { clearInterval(portCountdown); portCountdown = null }
    }, 1000)
    portDlg.value = false
    ElMessage.success(r.message || '端口变更已提交，服务重启中')
  } catch (e) {
    ElMessage.error('端口变更失败：' + e.message) // 占用/冲突/非法：后端中文错误直接展示
  } finally { portChanging.value = false }
}

// ===== 版本与升级（在线升级，admin；模块未接线 501 → 降级手动下载指引）=====
const UPG_STEPS = [
  { key: 'detecting', label: '环境检测' },
  { key: 'downloading', label: '下载升级包' },
  { key: 'verifying', label: '校验完整性' },
  { key: 'replacing', label: '替换二进制' },
  { key: 'restarting', label: '重启服务' },
]
const UPG_POLL_MS = 2000          // 任务轮询间隔
const UPG_RETRY_MS = 3000         // 服务重启窗口（接口失联）退避间隔
const UPG_RESTART_MAX_MS = 180000 // 失联判定上限（距最后一次成功通信），超时按失败引导人工排查
const upgradeModule = ref(null)   // null=探测中 true=可用 false=未接线/无权限
const upgVersion = ref('')
const upgLatest = ref(null)      // {version, update_available, notes, assets_url}
const upgChecking = ref(false)
const upgTask = ref(null)        // 升级任务对象（轮询态数据源）
const upgStatusError = ref('')
let upgPollTimer = null
let upgPollGen = 0    // 轮询代数：每次进入轮询自增；await 返回后校验，废弃旧代 in-flight 链
let upgLastSeenAt = 0 // 最后一次成功通信时间（task/status 查询成功即刷新），失联超时锚点

const upgDenied = computed(() => !can('admin'))
const upgTaskActive = computed(() => !!upgTask.value && !['success', 'failed'].includes(upgTask.value.state))
// assets_url 来自升级 feed（可被篡改），仅信任本项目官方发布页前缀（收紧到仓库级，
// 防同域任意第三方仓库附件）；其余不渲染链接只提示文本
const upgAssetsUrl = computed(() => {
  const u = upgLatest.value?.assets_url || ''
  return u.startsWith('https://gitee.com/aiuc-labs/KingMoat-WAF/releases') ? u : ''
})
const upgStepIdx = computed(() => UPG_STEPS.findIndex(s => s.key === upgTask.value?.state))

async function loadUpgradeStatus() {
  if (!can('admin')) { upgradeModule.value = false; loadUpgVersion(); return }
  try {
    const d = await api('/api/upgrade/status')
    upgradeModule.value = true
    upgStatusError.value = ''
    if (d.version) upgVersion.value = d.version
    upgLatest.value = d.latest || null
    // running_task 恢复：刷新/重开页面自动接上进行中的升级任务
    if (d.running_task && !upgTask.value) attachUpgradeTask(d.running_task)
  } catch (e) {
    if (e.status === 501) { upgradeModule.value = false; loadUpgVersion() }
    else if (!upgTask.value) upgStatusError.value = e.message
  }
}

// 降级态版本号兜底：/api/status 无角色门禁，501/非 admin 场景仍可展示当前版本
async function loadUpgVersion() {
  if (upgVersion.value) return
  try { upgVersion.value = (await api('/api/status')).version || '' } catch (e) { /* 版本未知时展示 — */ }
}

async function checkUpgrade() {
  upgChecking.value = true
  try {
    const d = await post('/api/upgrade/check', {})
    upgradeModule.value = true
    upgLatest.value = d
    upgStatusError.value = ''
    ElMessage.success(d.update_available ? '发现新版本：' + d.version : '当前已是最新版本')
  } catch (e) {
    if (e.status === 501) { upgradeModule.value = false; loadUpgVersion() }
    else ElMessage.error(e.message) // 502 feed 失败 / 400 当前版本非法：后端文案原文展示
  } finally { upgChecking.value = false }
}

async function confirmUpgrade() {
  const target = upgLatest.value?.version || '最新版本'
  try {
    await ElMessageBox.confirm(
      `将把控制台从 ${upgVersion.value || '当前版本'} 升级到 ${target}。升级过程服务会自动重启，控制台短暂失联，经反向代理的业务流量将中断数秒至数十秒，建议选择维护窗口执行。确认继续？`,
      '确认升级', { type: 'warning', confirmButtonText: '立即升级', cancelButtonText: '取消' }
    )
  } catch (e) { return }
  try {
    const r = await post('/api/upgrade/start', {})
    upgTask.value = {
      id: r.task_id, state: 'detecting',
      current_version: upgVersion.value, target_version: upgLatest.value?.version || '',
      message: '升级任务已启动', started_at: new Date().toISOString(),
    }
    pollUpgradeTask(r.task_id)
  } catch (e) {
    if (e.status === 409) {
      // 已有任务进行中（后端返回现任务）：清本地态后从 status 接上现任务
      ElMessage.warning(e.message)
      upgTask.value = null
      await loadUpgradeStatus()
    } else {
      ElMessage.error(e.message) // 429 冷却（后端含剩余分钟）/ 400 目标或当前版本非法
    }
  }
}

function attachUpgradeTask(t) {
  if (upgTask.value && !['success', 'failed'].includes(upgTask.value.state)) return // 已在跟踪
  upgTask.value = t
  if (!['success', 'failed'].includes(t.state)) pollUpgradeTask(t.id)
}

function pollUpgradeTask(id) {
  stopUpgradePoll()
  const gen = ++upgPollGen
  upgLastSeenAt = Date.now()
  const alive = () => gen === upgPollGen
  const schedule = (ms) => { if (alive()) upgPollTimer = setTimeout(tick, ms) }
  const finish = (t) => {
    if (!alive()) return
    upgTask.value = t
    if (t.state === 'success' && t.target_version) upgVersion.value = t.target_version
  }
  const tick = async () => {
    if (!alive()) return
    upgPollTimer = null
    try {
      const t = await api('/api/upgrade/task?id=' + encodeURIComponent(id))
      if (!alive()) return // 代数已更替（重挂/卸载/新任务）：丢弃本链，避免双轮询并存
      upgLastSeenAt = Date.now() // task 查询成功（无论 state）即刷新失联锚点
      if (t.state === 'success' || t.state === 'failed') { finish(t); return }
      upgTask.value = t
    } catch (e) {
      if (!alive()) return
      // 服务重启窗口接口失联属预期：改走 /status 判定成败；status 也不可达则退避重试
      try {
        const d = await api('/api/upgrade/status')
        if (!alive()) return
        upgLastSeenAt = Date.now() // status 可达同样是成功通信
        if (d.running_task) { upgTask.value = d.running_task; schedule(UPG_RETRY_MS); return }
        upgVersion.value = d.version || upgVersion.value
        const t0 = upgTask.value || {}
        if (t0.target_version && d.version === t0.target_version) {
          finish({ ...t0, state: 'success', finished_at: new Date().toISOString() })
        } else {
          finish({ ...t0, state: 'failed', error: '升级任务中断' + (e.message ? '（' + e.message + '）' : '') })
        }
        return
      } catch (e2) {
        if (!alive()) return
        // 失联窗口锚定最后一次成功通信：任务仍在推进（响应回来）就一直续期，
        // 下载/校验耗时长的正常升级不会被误判；仅连续失联超 3 分钟才判失败
        if (Date.now() - upgLastSeenAt > UPG_RESTART_MAX_MS) {
          finish({ ...(upgTask.value || { id }), state: 'failed', error: '升级服务已连续失联超过 3 分钟，请登录服务器执行 systemctl status kingmoatwaf 排查，必要时用安装目录 kingmoatwaf.bak-* 备份手动恢复' })
          return
        }
        schedule(UPG_RETRY_MS)
        return
      }
    }
    schedule(UPG_POLL_MS)
  }
  tick()
}

function stopUpgradePoll() {
  upgPollGen++ // 废弃旧代 in-flight 回调（卸载/重入轮询均生效）
  if (upgPollTimer) { clearTimeout(upgPollTimer); upgPollTimer = null }
}

function reloadPage() { location.reload() }

// ===== 服务重启（admin；非 systemd 形态后端 501 附手动指引，错误原文展示）=====
const restartBusy = ref(false)
const restartMsg = ref('')
const restartError = ref('')
async function confirmRestart() {
  try {
    await ElMessageBox.confirm(
      '重启期间控制台与数据面约 30 秒不可访问，完成后需重新登录。确认现在重启服务？',
      '重启服务',
      { confirmButtonText: '确认重启', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return
  }
  restartBusy.value = true
  restartMsg.value = ''
  restartError.value = ''
  try {
    await post('/api/system/restart', {})
  } catch (e) {
    restartBusy.value = false
    restartError.value = e.message || String(e) // 409 升级互斥 / 501 非 systemd 手动指引：后端中文原文直接展示
    return
  }
  // 重启提交成功：轮询 /api/status 直到服务恢复（2s 间隔，上限 90s；raw401 防重启窗口 401 跳登录）。
  // 成功判定需要先观察到至少一次失败探测：延迟提交前/取消场景下首次探测可能仍 200，
  // 直接把 200 当恢复会把「后端实际未重启」误报为成功（门禁 B-1②）；
  // 401 表示服务已用新 sessionKey 恢复且旧会话失效，直接判成功（门禁 B-1①）。
  const deadline = Date.now() + 90000
  let sawFailure = false
  const poll = async () => {
    try {
      await api('/api/status', { raw401: true })
      if (!sawFailure) {
        // 尚未见到任何失败探测：后端很可能还没真正重启（延迟窗内被取消或提交失败），继续等
        if (Date.now() < deadline) {
          setTimeout(poll, 2000)
        } else {
          restartBusy.value = false
          restartError.value = '重启提交已受理，但 90 秒内未探测到服务重启——请稍后刷新页面或登录服务器检查（systemctl status kingmoatwaf）'
        }
        return
      }
      restartBusy.value = false
      restartMsg.value = '服务已重启完成，请重新登录（如登录态已失效）'
      return
    } catch (e) {
      sawFailure = true
      if (e && e.status === 401) {
        // 401 = 服务已恢复且旧会话失效（新 sessionKey）——直接判定成功
        restartBusy.value = false
        restartMsg.value = '服务已重启完成，请重新登录（当前会话已失效）'
        return
      }
      // 网络错误/连接拒绝：重启窗口内属预期，继续轮询
    }
    if (Date.now() < deadline) {
      restartPollTimer = setTimeout(poll, 2000)
    } else {
      restartBusy.value = false
      restartError.value = '重启提交已受理，但 90 秒内未探测到服务恢复——请稍后刷新页面或登录服务器检查（systemctl status kingmoatwaf）'
    }
  }
  restartPollTimer = setTimeout(poll, 4000)
}
let restartPollTimer = 0
onBeforeUnmount(() => { if (restartPollTimer) clearTimeout(restartPollTimer) })

// 拦截页定制：可用变量 + 实时预览（示例值替换 + iframe sandbox）
const bpVars = ['{{request_id}}', '{{rule_id}}', '{{reason}}', '{{client_ip}}', '{{method}}', '{{host}}', '{{url}}', '{{ua}}', '{{timestamp}}']
const bpPreview = computed(() => {
  if (!f.bp_html) return ''
  const sample = {
    request_id: 'tr-4f8a2c1b', rule_id: 'crs/942100', reason: 'SQL 注入特征',
    client_ip: '203.0.113.7', method: 'GET', host: 'portal.example.cn',
    url: '/api/user?id=1', ua: 'Mozilla/5.0 (X11; Linux x86_64)', timestamp: new Date().toLocaleString(),
  }
  return f.bp_html.replace(/\{\{\s*([a-z_]+)\s*\}\}/g, (m, k) => (sample[k] !== undefined ? sample[k] : ''))
})

function insertBpVar(v) {
  f.bp_html = (f.bp_html || '') + v
}

const rbac = [
  { perm: '查看仪表盘 / 日志 / 报表', admin: true, operator: true, auditor: true },
  { perm: '站点防护配置（保存并发布）', admin: true, operator: true, auditor: false },
  { perm: '策略管理（规则 / 名单 / SecLang）', admin: true, operator: true, auditor: false },
  { perm: '攻击日志一键加白', admin: true, operator: true, auditor: false },
  { perm: '证书上传 / 站点证书管理', admin: true, operator: true, auditor: false },
  { perm: '系统设置 / 用户管理', admin: true, operator: false, auditor: false },
  { perm: 'AI 助手（只读分析）', admin: true, operator: true, auditor: true, opNote: '只读', audNote: '只读' },
]

// 加载期降级/归一化提示（A2）：/api/status 的 load_notes 仅在非空时出现（后端语义：
// 启动/回滚时对存量旧形态外发节做过归一化或降级才记录；成功发布一次后清空）。
// static 纯文件形态无此字段：为空/缺失时静默，不报错。
const loadNotes = ref([])
async function refreshLoadNotes() {
  try {
    const st = await api('/api/status')
    loadNotes.value = Array.isArray(st?.load_notes) ? st.load_notes : []
  } catch (e) { loadNotes.value = [] }
}

async function load() {
  const d = await api('/api/config')
  const c = d.config
  // 数据面监听（从站点防护页迁入，仅监听地址）
  f.listen_http = c.listen_http || ''
  f.listen_https = c.listen_https || ''
  f.capture_requests = !!c.capture_requests
  f.telemetry_enabled = !!(c.telemetry && c.telemetry.enabled)
  f.api_assets_enabled = !!c.api_assets?.enabled
  f.risks_enabled = !!c.risks?.enabled
  f.audit_retention_days = c.audit_retention_days > 0 ? c.audit_retention_days : 7
  f.archive_retention_days = c.audit_archive?.retention_days > 0 ? c.audit_archive.retention_days : 30
  f.query_degraded = !!c.audit_query?.degraded
  f.metrics_enabled = !!c.metrics?.enabled
  f.metrics_push_url = c.metrics?.push?.url || ''
  f.metrics_push_interval = c.metrics?.push?.interval_sec || 30
  f.metrics_push_token = c.metrics?.push?.bearer_token || ''
  f.shipper_enabled = !!c.log_shipper
  f.shipper_type = c.log_shipper?.type || 'clickhouse'
  f.shipper_url = c.log_shipper?.url || ''
  f.shipper_index = c.log_shipper?.index || 'kingmoat'
  f.shipper_sys_format = c.log_shipper?.syslog?.format || 'rfc5424'
  f.shipper_sys_hostname = c.log_shipper?.syslog?.hostname || ''
  // S3 字段为 ShipperSettings 顶层（endpoint/bucket/access_key/...）
  f.s3_endpoint = c.log_shipper?.endpoint || ''
  f.s3_bucket = c.log_shipper?.bucket || ''
  f.s3_prefix = c.log_shipper?.prefix || 'kingmoat'
  f.s3_ak = c.log_shipper?.access_key || ''
  f.s3_sk = c.log_shipper?.secret_key || ''
  f.s3_ssl = !!c.log_shipper?.use_ssl
  f.shipper_kafka_brokers = (c.log_shipper?.brokers || []).join('\n')
  f.shipper_kafka_topic = c.log_shipper?.topic || ''
  f.shipper_kafka_tls = !!c.log_shipper?.use_tls
  f.shipper_kafka_tls_skip = c.log_shipper?.tls_skip_verify !== false
  f.shipper_kafka_sasl = c.log_shipper?.sasl || 'none'
  f.shipper_user = c.log_shipper?.username || ''
  f.shipper_pass = c.log_shipper?.password || ''
  f.access_enabled = !!c.access_log?.enabled
  f.access_use_audit = !!c.access_log?.use_audit_channel
  f.access_type = c.access_log?.type || 'clickhouse'
  f.access_url = c.access_log?.url || ''
  f.access_index = c.access_log?.index || 'kingmoat_access'
  f.access_sys_format = c.access_log?.syslog?.format || 'rfc5424'
  f.access_sys_hostname = c.access_log?.syslog?.hostname || ''
  f.access_sample = c.access_log?.sample_pct || 100
  // S3 字段为嵌套 s3 对象（S3Settings）——旧版控制台曾平铺提交，被后端静默丢弃，无遗留数据可迁移
  f.access_s3_endpoint = c.access_log?.s3?.endpoint || ''
  f.access_s3_bucket = c.access_log?.s3?.bucket || ''
  f.access_s3_prefix = c.access_log?.s3?.prefix || 'kingmoat'
  f.access_s3_ak = c.access_log?.s3?.access_key || ''
  f.access_s3_sk = c.access_log?.s3?.secret_key || ''
  f.access_s3_ssl = !!c.access_log?.s3?.use_ssl
  f.access_kafka_brokers = (c.access_log?.brokers || []).join('\n')
  f.access_kafka_topic = c.access_log?.topic || ''
  f.access_kafka_tls = !!c.access_log?.use_tls
  f.access_kafka_tls_skip = c.access_log?.tls_skip_verify !== false
  f.access_kafka_sasl = c.access_log?.sasl || 'none'
  f.access_user = c.access_log?.username || ''
  f.access_pass = c.access_log?.password || ''
  // 访问日志本地记录（access_log_record）：老配置无节时回默认（off/空站点/7 天/1024 MB），
  // 站点选项取站点首域名（与访问日志 Site 列同口径，小写）
  accessRecordSiteOptions.value = [...new Set((c.sites || [])
    .map(s => String((s.domains && s.domains[0]) || '').trim().toLowerCase())
    .filter(Boolean))]
  const recForm = loadAccessRecordForm(c)
  f.access_record_mode = recForm.mode
  f.access_record_sites = recForm.sites
  f.access_record_retention_days = recForm.retention
  f.access_record_max_disk_mb = recForm.maxDisk
  // AI 会话审计
  f.aiaudit_enabled = !!c.ai_audit?.enabled
  f.aiaudit_sample = c.ai_audit?.sample_pct || 100
  f.aiaudit_max_req_kb = Math.round((c.ai_audit?.max_request_bytes || 32768) / 1024)
  f.aiaudit_max_resp_kb = Math.round((c.ai_audit?.max_response_bytes || 65536) / 1024)
  f.aiaudit_redact = c.ai_audit?.redact_content !== false
  f.aiaudit_embed = !!c.ai_audit?.include_embeddings
  f.aiaudit_unknown = !!c.ai_audit?.include_unknown
  f.aiaudit_retention = c.ai_audit?.retention_days || 30
  f.aiaudit_ship_enabled = !!c.ai_audit?.ship?.enabled
  f.aiaudit_ship_use_audit = !!c.ai_audit?.ship?.use_audit_channel
  f.aiaudit_ship_type = c.ai_audit?.ship?.type || 'elasticsearch'
  f.aiaudit_ship_sample = c.ai_audit?.ship?.sample_pct || 100
  f.aiaudit_ship_url = c.ai_audit?.ship?.url || ''
  f.aiaudit_ship_index = c.ai_audit?.ship?.index || 'kingmoat_ai_sessions'
  f.aiaudit_ship_user = c.ai_audit?.ship?.username || ''
  f.aiaudit_ship_pass = c.ai_audit?.ship?.password || ''
  f.aiaudit_ship_s3_endpoint = c.ai_audit?.ship?.s3?.endpoint || ''
  f.aiaudit_ship_s3_bucket = c.ai_audit?.ship?.s3?.bucket || ''
  f.aiaudit_ship_s3_prefix = c.ai_audit?.ship?.s3?.prefix || c.ai_audit?.ship?.prefix || 'kingmoat/ai'
  f.aiaudit_ship_s3_ak = c.ai_audit?.ship?.s3?.access_key || ''
  f.aiaudit_ship_s3_sk = c.ai_audit?.ship?.s3?.secret_key || ''
  f.aiaudit_ship_s3_ssl = !!(c.ai_audit?.ship?.s3?.use_ssl ?? c.ai_audit?.ship?.use_ssl)
  f.aiaudit_ship_sys_format = c.ai_audit?.ship?.syslog?.format || 'rfc5424'
  f.aiaudit_ship_sys_hostname = c.ai_audit?.ship?.syslog?.hostname || ''
  f.aiaudit_ship_kafka_brokers = (c.ai_audit?.ship?.brokers || []).join('\n')
  f.aiaudit_ship_kafka_topic = c.ai_audit?.ship?.topic || ''
  f.aiaudit_ship_kafka_tls = !!c.ai_audit?.ship?.use_tls
  f.aiaudit_ship_kafka_tls_skip = c.ai_audit?.ship?.tls_skip_verify !== false
  f.aiaudit_ship_kafka_sasl = c.ai_audit?.ship?.sasl || 'none'
  f.webhook_enabled = !!c.webhook
  f.webhook_url = c.webhook?.url || ''
  f.webhook_secret = c.webhook?.secret || ''
  f.webhook_keyword = c.webhook?.keyword || ''
  // 告警与通知
  f.alerts_enabled = !!c.alerts?.enabled
  f.alerts_interval = c.alerts?.interval_sec || 60
  f.alerts_cooldown = c.alerts?.cooldown_min || 10
  f.alerts_webhook = !!c.alerts?.notify_webhook
  f.alerts_email = !!c.alerts?.notify_email
  const src = c.alerts?.rules || {}
  const defs = { cpu: 80, mem: 80, disk: 80, web_requests: 20000, web_attacks: 10000, blocked: 10000, top_attack_ip: 20000, top_target: 20000 }
  const keyMap = { cpu: 'cpu', mem: 'mem', disk: 'disk', requests: 'web_requests', attacks: 'web_attacks', blocked: 'blocked', top_ip: 'top_attack_ip', top_target: 'top_target' }
  for (const k of Object.keys(keyMap)) {
    const bk = keyMap[k]
    const r = src[bk]
    f.alert_rules[k] = r ? { enabled: !!r.enabled, threshold: r.threshold || defs[bk], window_sec: r.window_sec || 60 } : { enabled: true, threshold: defs[bk], window_sec: 60 }
  }
  // 邮件通道
  f.email_enabled = !!c.email?.enabled
  f.email_host = c.email?.host || ''
  f.email_port = c.email?.port || 465
  f.email_from = c.email?.from || ''
  f.email_user = c.email?.username || ''
  f.email_pass = c.email?.password || ''
  f.email_ssl = !!c.email?.ssl
  f.email_to = [...(c.email?.to || [])]
  // 安全设置(迁回)
  f.sec_min_len = c.security?.password_min_len || 8
  f.sec_complexity = !!c.security?.password_complexity
  f.sec_max_age = c.security?.password_max_age_days || 0
  f.sec_session = c.security?.session_timeout_min || 0
  f.sec_pw_history = c.security?.password_history_count || 0
  f.sec_login_max = c.security?.login_max_failures || 10
  f.sec_lockout_min = c.security?.login_lockout_min || 15
  f.console_ips = [...(c.console?.allowed_ips || [])]
  f.bp_title = c.block_page?.title || ''
  f.bp_message = c.block_page?.message || ''
  f.bp_footer = c.block_page?.footer || ''
  f.bp_html = c.block_page?.html || ''
  f.ai_enabled = !!c.ai?.enabled
  f.ai_template = c.ai?.provider?.template || 'openai'
  f.ai_base = c.ai?.provider?.base_url || ''
  f.ai_model = c.ai?.provider?.model || ''
  f.ai_max_tokens = c.ai?.provider?.max_tokens || 4096
  f.ai_temperature = c.ai?.provider?.temperature > 0 ? c.ai.provider.temperature : 0.2
  f.ai_timeout = c.ai?.provider?.timeout_sec || 120
  f.ai_sysprompt = c.ai?.system_prompt || ''
  f.ai_ctx_tokens = c.ai?.chat?.context_window_tokens || 0
  f.ai_keep_turns = c.ai?.chat?.keep_recent_turns || 4
  f.ai_history_days = c.ai?.chat?.history_retention_days || 0
  f.ai_sanitize = c.ai?.sanitize?.enabled !== false
  f.ai_analysis = !!c.ai?.analysis?.enabled
  f.ai_report_tokens_wan = Math.max(1, Math.round((c.ai?.analysis?.max_tokens_per_day || 200000) / 10000))
  const daily = (c.ai?.analysis?.schedules || []).find(s => s.kind === 'attack_summary_daily')
  f.ai_report_channel = daily?.channel === 'email' ? 'email' : 'webhook'
  f.ai_report_webhook = daily?.webhook || ''
  f.ai_report_email = daily?.email || ''
  if (daily?.cron) {
    const parsed = parseReportCron(daily.cron)
    if (parsed) {
      f.ai_report_time = parsed.time
      f.ai_report_days = parsed.days
    }
  } else {
    f.ai_report_time = '08:00'
    f.ai_report_days = [1, 2, 3, 4, 5, 6, 0]
  }
  refreshAIKeyStatus()
  loadConsolePort()
  loadUpgradeStatus()
  refreshLoadNotes()
}

// parseReportCron 把日报 cron（分 时 * * dow）解析回时间与星期多选；
// 支持全选 *、区间（1-5）、逗号列表与单日；解析失败返回 null（保留表单默认值）。
function parseReportCron(expr) {
  const parts = String(expr || '').trim().split(/\s+/)
  if (parts.length !== 5 || parts[2] !== '*' || parts[3] !== '*') return null
  const m = Number(parts[0]), h = Number(parts[1])
  if (!Number.isInteger(m) || m < 0 || m > 59 || !Number.isInteger(h) || h < 0 || h > 23) return null
  const dow = parts[4]
  let days = []
  if (dow === '*') {
    days = [0, 1, 2, 3, 4, 5, 6]
  } else {
    for (const seg of dow.split(',')) {
      const range = seg.match(/^(\d+)-(\d+)$/)
      if (range) {
        const lo = Number(range[1]), hi = Number(range[2])
        if (lo > hi) return null
        for (let d = lo; d <= hi; d++) days.push(d % 7)
      } else if (/^\d+$/.test(seg)) {
        days.push(Number(seg) % 7)
      } else {
        return null
      }
    }
  }
  days = [...new Set(days)].sort((a, b) => a - b)
  if (!days.length) return null
  return { time: `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`, days }
}

// buildReportCron 由时间（HH:mm）与星期多选生成日报 cron；全选输出 *。
function buildReportCron(time, days) {
  const [h, m] = String(time || '08:00').split(':').map(v => Number(v) || 0)
  const ds = [...new Set((days || []).map(Number))].sort((a, b) => a - b)
  const dow = (ds.length === 7 || ds.length === 0) ? '*' : ds.join(',')
  return `${m} ${h} * * ${dow}`
}

// sysPayload 组装 syslog 子结构（format 必带，hostname 可选）；
// log_shipper / access_log / ai_audit.ship 三处的 syslog 外发共用
const sysPayload = (fmt, host) => {
  const s = { format: fmt }
  if (host) s.hostname = host
  return s
}

const templates = [
  { id: 'openai', name: 'OpenAI' }, { id: 'deepseek', name: 'DeepSeek' },
  { id: 'qwen', name: '通义千问' }, { id: 'zhipu', name: '智谱' },
  { id: 'moonshot', name: 'Kimi' }, { id: 'doubao', name: '豆包' },
  { id: 'openrouter', name: 'OpenRouter' }, { id: 'ollama', name: 'Ollama' },
  { id: 'vllm', name: 'vLLM' }, { id: 'custom', name: '自定义' }
]
function onTemplate(id) {
  const hints = { openai: 'https://api.openai.com/v1', deepseek: 'https://api.deepseek.com/v1',
    qwen: 'https://dashscope.aliyuncs.com/compatible-mode/v1', zhipu: 'https://open.bigmodel.cn/api/paas/v4',
    moonshot: 'https://api.moonshot.cn/v1', openrouter: 'https://openrouter.ai/api/v1' }
  if (hints[id]) f.ai_base = hints[id]
}

// ===== 外发节载荷构造器（A1-1 收拢：每节一个唯一构造器，探测与保存共用）=====
// 两条既有语义差异以 mode 显式保留，不得抹平：
//   probe（POST /api/outbound/test，只读探测）= 后端 overlay 语义：settings 里出现的键
//         覆盖已保存值（含显式 false 与空串）、缺席键保留已保存值。表单可表达的字段
//         全部显式携带——凭据空串也要带上（= 按表单探测而非沿用已保存凭据）；
//         复用开启时 syslog 键不携带（置灰字段由后端以已保存块补齐，APP-NAME 身份
//         不因探测分叉丢失）；休眠 s3 仅携带本节对象前缀（what-if，无块也允许）。
//   save（POST /api/config/publish，整节替换发布）= 只提交最终生效形态：空凭据键省略
//         （缺省即空，终态与探测的显式空串等价）；休眠块由 carryDormant* 以刚拉取的
//         已保存节为底整块回带（无块不造块，见各 builder 尾部与 helper 注释）。
const splitBrokers = v => String(v || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean)

// 休眠 syslog/kafka 块整块回带（A4，save 专用）：整节替换会抹掉未被生效类型选中、
// 表单未渲染的 syslog 块与 kafka 传输字段——以刚拉取的已保存节为底原样回带（与
// 复用开启态同源语义）；已保存节没有的键不凭表单默认值凭空造块。凭据字段
// （username/password）与 ch/es/loki 认证是同源共享字段，不在本函数回带（C4 修正：
// 原先的归属判定写在 if(t!=='kafka') 块内对 kafka 永不可达；A1 write-only 契约下
// 省略凭据键即可——后端按「空/占位=保留库中原值」处理，kafka+SASL=none 等表单
// 未表达凭据的类型在保存后旧凭据保留在库中但不再被 sink 使用，切回 SASL 认证
// 无需重输；要换凭据在表单输入新值提交即可）。后端发布校验只查生效类型块
// （internal/config/security.go Validate 按 a.Type switch），休眠块不参与。
function carryDormantSyslogKafka(p, saved, t) {
  if (!saved || typeof saved !== 'object') return
  if (t !== 'syslog' && saved.syslog && typeof saved.syslog === 'object' && Object.keys(saved.syslog).length && p.syslog === undefined) {
    p.syslog = { ...saved.syslog }
  }
  if (t !== 'kafka') {
    for (const k of ['brokers', 'topic', 'use_tls', 'tls_skip_verify', 'sasl']) {
      if (saved[k] !== undefined && saved[k] !== null && p[k] === undefined) p[k] = saved[k]
    }
  }
}

function buildShipperPayload(mode) {
  const t = f.shipper_type
  if (t === 's3') {
    return { type: t, index: f.shipper_index, endpoint: f.s3_endpoint, bucket: f.s3_bucket, prefix: f.s3_prefix, access_key: f.s3_ak, secret_key: f.s3_sk, use_ssl: f.s3_ssl }
  }
  if (t === 'kafka') {
    const p = { type: t, index: f.shipper_index, brokers: splitBrokers(f.shipper_kafka_brokers), topic: f.shipper_kafka_topic, use_tls: f.shipper_kafka_tls }
    if (mode === 'probe') {
      p.tls_skip_verify = f.shipper_kafka_tls_skip
      p.sasl = f.shipper_kafka_sasl
      p.username = f.shipper_user
      p.password = f.shipper_pass
    } else {
      p.sasl = f.shipper_kafka_sasl
      if (f.shipper_kafka_tls) p.tls_skip_verify = !!f.shipper_kafka_tls_skip
      if (f.shipper_kafka_sasl !== 'none') {
        if (f.shipper_user) p.username = f.shipper_user
        if (f.shipper_pass) p.password = f.shipper_pass
      }
    }
    return p
  }
  if (t === 'syslog') {
    return { type: t, url: f.shipper_url, index: f.shipper_index, syslog: sysPayload(f.shipper_sys_format, f.shipper_sys_hostname) }
  }
  const p = { type: t, url: f.shipper_url, index: f.shipper_index }
  if (mode === 'probe') { p.username = f.shipper_user; p.password = f.shipper_pass }
  else { if (f.shipper_user) p.username = f.shipper_user; if (f.shipper_pass) p.password = f.shipper_pass }
  return p
}

function buildAccessPayload(mode, saved) {
  const t = f.access_type
  const p = mode === 'save'
    ? { enabled: true, type: t, index: f.access_index, sample_pct: f.access_sample }
    : { type: t, index: f.access_index, sample_pct: f.access_sample, use_audit_channel: f.access_use_audit }
  if (mode === 'save' && f.access_use_audit) p.use_audit_channel = true
  if (t === 's3') {
    // 后端 AccessLogSettings 只认嵌套 s3 对象（S3Settings）——旧版平铺提交被后端静默丢弃；
    // 复用开关打开时字段照传、由后端忽略
    p.s3 = { endpoint: f.access_s3_endpoint, bucket: f.access_s3_bucket, prefix: f.access_s3_prefix, access_key: f.access_s3_ak, secret_key: f.access_s3_sk, use_ssl: f.access_s3_ssl }
  } else if (t === 'kafka') {
    p.brokers = splitBrokers(f.access_kafka_brokers)
    p.topic = f.access_kafka_topic
    p.use_tls = f.access_kafka_tls
    if (mode === 'probe') {
      p.tls_skip_verify = f.access_kafka_tls_skip
      p.sasl = f.access_kafka_sasl
      p.username = f.access_user
      p.password = f.access_pass
    } else {
      p.sasl = f.access_kafka_sasl
      if (f.access_kafka_tls) p.tls_skip_verify = !!f.access_kafka_tls_skip
      if (f.access_kafka_sasl !== 'none') {
        if (f.access_user) p.username = f.access_user
        if (f.access_pass) p.password = f.access_pass
      }
    }
  } else {
    p.url = f.access_url
    if (t === 'syslog') {
      if (mode === 'save') {
        // 整节替换会抹掉休眠字段：复用开启时 syslog 通道字段置灰（格式/主机名由通道供给），
        // 以已保存块为底整体保留——app_name 是本节身份字段，块被丢掉后 overlaySyslogTransport
        // 会回落默认 APP-NAME；复用关闭时表单可编辑，以表单值为准
        p.syslog = (f.access_use_audit && saved?.syslog) ? { ...saved.syslog } : sysPayload(f.access_sys_format, f.access_sys_hostname)
      } else if (!f.access_use_audit) {
        p.syslog = sysPayload(f.access_sys_format, f.access_sys_hostname)
      }
    } else if (mode === 'probe') { p.username = f.access_user; p.password = f.access_pass }
    else { if (f.access_user) p.username = f.access_user; if (f.access_pass) p.password = f.access_pass }
  }
  if (mode === 'save') {
    // 休眠 s3 块整块保留（A4，复用开/关同源语义）：本节非 s3 时以已保存 s3 块为底回带，
    // 只发 {prefix} 会把已保存的 endpoint/bucket/access_key/secret_key/use_ssl 一并抹掉。
    // 对象前缀（本节身份字段）仅在生效类型为 s3、表单可编辑时以表单值为准——置灰或
    // 已保存无 s3 块时不用表单默认值凭空造块
    if (t !== 's3') {
      const merged = { ...(saved?.s3 || {}) }
      if (accessEffType.value === 's3') merged.prefix = f.access_s3_prefix
      if (Object.keys(merged).length) p.s3 = merged
    }
    carryDormantSyslogKafka(p, saved, t)
  } else if (t !== 's3' && f.access_use_audit && f.access_s3_prefix) {
    // overlay 语义下的 what-if：仅携带本节对象前缀，其余键由后端以已保存值补齐
    p.s3 = { prefix: f.access_s3_prefix }
  }
  return p
}

// ===== 访问日志本地记录（access_log_record 独立顶层节）=====
// 与外发 access_log 节完全独立（控制台关外发会整节删 access_log，两者不得互相牵连）。
// 站点选项：/api/config 的 sites[].domains[0]（站点首域名，与访问日志 Site 列同口径），小写去重
const accessRecordSiteOptions = ref([])

// loadAccessRecordForm 从已保存配置回填「访问日志配置」表单。老配置无该节（nil = 默认关）
// 时回默认：off / 空站点 / 7 天 / 1024 MB；站点值统一小写（后端按小写首域名比对）。
// 单独封装以便提取验证（整节替换语义下的回填是「别的 Tab 保存不丢节」的防护核心）。
function loadAccessRecordForm(c) {
  const r = c && typeof c === 'object' ? c.access_log_record : null
  const mode = r && ['off', 'all', 'sites'].includes(String(r.mode)) ? String(r.mode) : 'off'
  const sites = [...new Set((r && Array.isArray(r.sites) ? r.sites : [])
    .map(s => String(s || '').trim().toLowerCase()).filter(Boolean))]
  return {
    mode,
    sites,
    retention: r && Number(r.retention_days) > 0 ? Number(r.retention_days) : 7,
    maxDisk: r && Number(r.max_disk_mb) > 0 ? Number(r.max_disk_mb) : 1024,
  }
}

// buildAccessRecordPayload 组装 access_log_record 节（save 专用，整节替换发布）。
// 返回 undefined = 从发布载荷中删除该节。提交形态依据：
//   - mode=off → 删节：后端节缺失（nil）与 {mode:"off"} 语义等价（ModeOrDefault 空=off、
//     Validate 对 nil 直接放行），删节让配置回到「默认关」的干净形态，避免残留半截节；
//   - mode=all/sites → 以刚拉取的已保存节为底展开（保留表单未表达的 batch_size/flush_sec
//     等休眠字段，整节替换不抹掉），表单四字段覆盖；all 模式表单站点作为休眠值保留
//     （后端 Validate 仅在 sites 模式校验站点，携带不报错）；
//   - sites 统一首域名小写去重（后端 Validate 对未知域名拒发布并附有效站点清单）。
function buildAccessRecordPayload(saved) {
  const mode = f.access_record_mode
  if (mode !== 'all' && mode !== 'sites') return undefined
  const p = { ...(saved && typeof saved === 'object' ? saved : {}), mode }
  const sites = [...new Set((f.access_record_sites || [])
    .map(s => String(s || '').trim().toLowerCase()).filter(Boolean))]
  if (sites.length) p.sites = sites
  else delete p.sites
  const rd = Number(f.access_record_retention_days)
  if (Number.isFinite(rd) && rd > 0) p.retention_days = rd
  else delete p.retention_days
  const md = Number(f.access_record_max_disk_mb)
  if (Number.isFinite(md) && md > 0) p.max_disk_mb = md
  else delete p.max_disk_mb
  return p
}

function buildAiShipPayload(mode, saved) {
  const t = f.aiaudit_ship_type
  const idx = f.aiaudit_ship_index || 'kingmoat_ai_sessions'
  const p = mode === 'save'
    ? { enabled: true, type: t, index: idx, sample_pct: f.aiaudit_ship_sample }
    : { type: t, index: idx, sample_pct: f.aiaudit_ship_sample, use_audit_channel: f.aiaudit_ship_use_audit }
  if (mode === 'save' && f.aiaudit_ship_use_audit) p.use_audit_channel = true
  if (t === 's3') {
    p.s3 = { endpoint: f.aiaudit_ship_s3_endpoint, bucket: f.aiaudit_ship_s3_bucket, prefix: f.aiaudit_ship_s3_prefix, access_key: f.aiaudit_ship_s3_ak, secret_key: f.aiaudit_ship_s3_sk, use_ssl: f.aiaudit_ship_s3_ssl }
  } else if (t === 'kafka') {
    p.brokers = splitBrokers(f.aiaudit_ship_kafka_brokers)
    p.topic = f.aiaudit_ship_kafka_topic
    p.use_tls = f.aiaudit_ship_kafka_tls
    if (mode === 'probe') {
      p.tls_skip_verify = f.aiaudit_ship_kafka_tls_skip
      p.sasl = f.aiaudit_ship_kafka_sasl
      p.username = f.aiaudit_ship_user
      p.password = f.aiaudit_ship_pass
    } else {
      p.sasl = f.aiaudit_ship_kafka_sasl
      if (f.aiaudit_ship_kafka_tls) p.tls_skip_verify = !!f.aiaudit_ship_kafka_tls_skip
      if (f.aiaudit_ship_kafka_sasl !== 'none') {
        if (f.aiaudit_ship_user) p.username = f.aiaudit_ship_user
        if (f.aiaudit_ship_pass) p.password = f.aiaudit_ship_pass
      }
    }
  } else {
    p.url = f.aiaudit_ship_url
    if (t === 'syslog') {
      if (mode === 'save') {
        // 同访问日志：复用开启时以已保存块为底整体保留（app_name 身份字段不丢），
        // 复用关闭时表单可编辑、以表单值为准
        p.syslog = (f.aiaudit_ship_use_audit && saved?.syslog) ? { ...saved.syslog } : sysPayload(f.aiaudit_ship_sys_format, f.aiaudit_ship_sys_hostname)
      } else if (!f.aiaudit_ship_use_audit) {
        p.syslog = sysPayload(f.aiaudit_ship_sys_format, f.aiaudit_ship_sys_hostname)
      }
    } else if (mode === 'probe') { p.username = f.aiaudit_ship_user; p.password = f.aiaudit_ship_pass }
    else { if (f.aiaudit_ship_user) p.username = f.aiaudit_ship_user; if (f.aiaudit_ship_pass) p.password = f.aiaudit_ship_pass }
  }
  if (mode === 'save') {
    if (t !== 's3') {
      // 同访问日志：休眠 s3 整块保留（endpoint/bucket/ak/sk/ssl 为切回备查值），
      // 前缀仅在生效类型为 s3、表单可编辑时以表单值为准，置灰时保留已保存值
      const merged = { ...(saved?.s3 || {}) }
      if (aiauditEffType.value === 's3') merged.prefix = f.aiaudit_ship_s3_prefix
      if (Object.keys(merged).length) p.s3 = merged
    }
    carryDormantSyslogKafka(p, saved, t)
    // A5：遗留扁平 prefix/use_ssl（deprecated 兼容位；type 非 s3 的形态加载迁移不覆盖）
    // 随整节替换会丢——作为休眠值随 payload 回带；仅当新 payload 无嵌套 s3 块
    //（有嵌套块时扁平值按「新建配置用嵌套块」约定弃用，避免双写）
    if (!p.s3) {
      if (typeof saved?.prefix === 'string' && saved.prefix) p.prefix = saved.prefix
      if (saved?.use_ssl !== undefined && saved?.use_ssl !== null) p.use_ssl = saved.use_ssl
    }
  } else if (t !== 's3' && f.aiaudit_ship_use_audit && f.aiaudit_ship_s3_prefix) {
    p.s3 = { prefix: f.aiaudit_ship_s3_prefix }
  }
  return p
}

// stripProbeSentinels removes write-only mask sentinels from a probe payload
// (recursing into nested blocks like s3): the GET /api/config write-only
// contract seeds the form with placeholder values ("******" for credential
// fields, masked URLs, "<redacted>" for unmaskable URLs). Sending those
// literally would make the probe authenticate with the sentinel itself and
// report a misleading auth failure for channels whose credentials are already
// stored. The probe endpoint uses partial-override semantics (absent keys
// keep the stored value), so dropping the key lets the server test the real
// stored credential.
function stripProbeSentinels(p) {
  for (const k of Object.keys(p)) {
    const v = p[k]
    if (Array.isArray(v)) {
      // Arrays (brokers): filter in place instead of delete, so a stray
      // sentinel element never leaves a sparse hole that would serialize
      // as null and unmarshal as an empty-string element server-side.
      p[k] = v.filter(x => typeof x !== 'string' || (x !== '******' && x !== '<redacted>'))
      continue
    }
    if (v && typeof v === 'object') { stripProbeSentinels(v); continue }
    if (typeof v !== 'string') continue
    if (v === '******' || v === '<redacted>' || (k === 'url' && v.includes('******'))) delete p[k]
  }
  return p
}

async function runOutboundTest(kind) {
  if (probeBusy[kind]) return
  probeBusy[kind] = true
  probeResults[kind] = null
  const settings = stripProbeSentinels(kind === 'audit' ? buildShipperPayload('probe') : kind === 'access' ? buildAccessPayload('probe') : buildAiShipPayload('probe'))
  try {
    probeResults[kind] = await outboundTest({ kind, settings })
  } catch (e) {
    let detail
    if (e.status === 403) detail = '权限不足：外发测试需要 operator 及以上角色（当前角色：' + (role() || '未知') + '）'
    else if (e.status === 429) detail = (e.message || '已有外发探测在执行') + '，请稍后重试'
    else if (!e.status) detail = '请求失败：' + (e.message || '网络异常或会话已过期') + '（请检查网络，或重新登录后重试）'
    else detail = e.message || '请求失败'
    probeResults[kind] = { state: 'fail', ok: false, detail, error: true }
  } finally {
    probeBusy[kind] = false
  }
}



async function save() {
  // AI 日报表单校验（整页单保存按钮，与其它节无关）
  if (f.ai_enabled && f.ai_analysis) {
    if (!f.ai_report_time) return ElMessage.warning('请选择 AI 日报执行时间')
    if (!f.ai_report_days.length) return ElMessage.warning('AI 日报请至少选择一个重复日')
    const wan = Number(f.ai_report_tokens_wan)
    if (!Number.isFinite(wan) || wan < 1 || wan > 1000) return ElMessage.warning('单日 Token 限额需在 1–1000 万之间')
  }
  // 数据面监听保存前拦截：格式/端口约束与后端 config.Validate 对齐，不合法不发请求
  const lh = parseListenAddr(f.listen_http)
  const ls = parseListenAddr(f.listen_https)
  if (!lh.ok) return ElMessage.error('HTTP 监听地址无效：' + lh.msg)
  if (!ls.ok) return ElMessage.error('HTTPS 监听地址无效：' + ls.msg)
  if (lh.empty && ls.empty) return ElMessage.error('至少需要配置一个全局监听地址（HTTP / HTTPS 至少一项）')
  if (!lh.empty && !ls.empty && lh.port === ls.port) return ElMessage.error('HTTP 与 HTTPS 监听端口不能相同')
  // 「使用防护日志通道」前置校验：复用开关依赖防护日志外发（log_shipper）已启用，
  // 与后端 Config.Validate 跨节校验保持一致，避免发布被拒才暴露
  if (f.access_enabled && f.access_use_audit && !f.shipper_enabled) {
    return ElMessage.error('访问日志外发已开启「使用防护日志通道」，但防护日志外发未启用——请先在「日志外发」页签启用防护日志外发，或关闭该开关')
  }
  if (f.aiaudit_enabled && f.aiaudit_ship_enabled && f.aiaudit_ship_use_audit && !f.shipper_enabled) {
    return ElMessage.error('AI 会话外发已开启「使用防护日志通道」，但防护日志外发未启用——请先在「日志外发」页签启用防护日志外发，或关闭该开关')
  }
  // 访问日志本地记录前置校验（与后端 access_log_record.Validate 对齐）：
  // sites 模式必须至少选一个站点，且均为当前配置中的有效站点（未知域名后端拒发布）
  if (f.access_record_mode === 'sites') {
    const chosen = [...new Set((f.access_record_sites || []).map(s => String(s || '').trim().toLowerCase()).filter(Boolean))]
    if (!chosen.length) {
      return ElMessage.error('访问日志配置已选「指定站点」，请至少勾选一个站点，或改为「全部站点」/「关闭」')
    }
    const validSet = new Set(accessRecordSiteOptions.value)
    const unknownSites = chosen.filter(s => !validSet.has(s))
    if (unknownSites.length) {
      return ElMessage.error('访问日志记录站点含当前配置中不存在的站点：' + unknownSites.join(', ') + '（请重新勾选，或改为「全部站点」）')
    }
  }
  let d
  try {
    d = await api('/api/config')
  } catch (e) {
    // The publish below lives in its own try/catch; without this branch a
    // failed config read (session expiry, backend 5xx, network) aborted the
    // save silently and the button looked dead.
    ElMessage.error('读取当前配置失败：' + (e.message || e))
    return
  }
  const cfg = d.config
  // 休眠块保留基准：以刚拉取的已保存节为底（而非 load 回填的表单绑定），
  // 避免两次拉取之间的配置漂移被表单陈旧值覆盖；下方 s3/syslog 保留逻辑共用
  const savedAccess = cfg.access_log
  const savedAiShip = cfg.ai_audit?.ship
  // 数据面监听（仅监听地址）：随整份配置发布（从站点防护页迁入）；
  // sites、acme_email 等其余字段取自刚拉取的最新配置，发布不会丢失或清空监听设置
  cfg.listen_http = (f.listen_http || '').trim()
  cfg.listen_https = (f.listen_https || '').trim()
  cfg.capture_requests = f.capture_requests
  // 匿名安装统计：缺省键 = 关闭（与后端语义一致）
  if (f.telemetry_enabled) cfg.telemetry = { enabled: true }
  else delete cfg.telemetry
  cfg.audit_retention_days = f.audit_retention_days
  cfg.audit_archive = { ...(cfg.audit_archive || {}), retention_days: f.archive_retention_days, enabled: cfg.audit_archive?.enabled !== false }
  if (f.query_degraded) cfg.audit_query = { ...(cfg.audit_query || {}), degraded: true }
  else delete cfg.audit_query
  if (f.metrics_enabled) {
    cfg.metrics = { enabled: true }
    if (f.metrics_push_url) {
      let pu = f.metrics_push_url.trim()
      if (!/^https?:\/\//i.test(pu)) pu = 'https://' + pu
      cfg.metrics.push = { url: pu, interval_sec: f.metrics_push_interval || 30, bearer_token: f.metrics_push_token || undefined }
    }
  } else {
    delete cfg.metrics
  }
  if (f.api_assets_enabled) cfg.api_assets = { ...(cfg.api_assets || {}), enabled: true }
  else delete cfg.api_assets
  if (f.risks_enabled) cfg.risks = { ...(cfg.risks || {}), enabled: true }
  else delete cfg.risks
  if (f.shipper_enabled) {
    cfg.log_shipper = buildShipperPayload('save')
  } else delete cfg.log_shipper
  if (f.access_enabled) {
    cfg.access_log = buildAccessPayload('save', savedAccess)
  } else delete cfg.access_log
  // 访问日志本地记录（access_log_record）：独立顶层节，与上方外发 access_log 的组装/删除
  // 相互独立，任何一方开关变化都不得影响另一方；mode=off 删节（默认关语义，见
  // buildAccessRecordPayload 注释），all/sites 整节组装（以已保存节为底保留休眠字段）
  const accessRecordPayload = buildAccessRecordPayload(cfg.access_log_record)
  if (accessRecordPayload === undefined) delete cfg.access_log_record
  else cfg.access_log_record = accessRecordPayload
  // AI 会话审计（保存发布后即时热生效；外发 ship 同批热换）
  if (f.aiaudit_enabled) {
    cfg.ai_audit = {
      enabled: true,
      sample_pct: f.aiaudit_sample,
      max_request_bytes: f.aiaudit_max_req_kb * 1024,
      max_response_bytes: f.aiaudit_max_resp_kb * 1024,
      redact_content: f.aiaudit_redact,
      include_embeddings: f.aiaudit_embed,
      include_unknown: f.aiaudit_unknown,
      retention_days: f.aiaudit_retention,
    }
    if (f.aiaudit_ship_enabled) {
      cfg.ai_audit.ship = buildAiShipPayload('save', savedAiShip)
    }
  } else delete cfg.ai_audit
  // webhook 通知渠道在「告警与通知」Tab 配置（含加签/关键词字段）
  if (f.webhook_url) {
    cfg.webhook = { ...(cfg.webhook || {}), url: f.webhook_url }
    if (f.webhook_secret) cfg.webhook.secret = f.webhook_secret
    if (f.webhook_keyword) cfg.webhook.keyword = f.webhook_keyword
  } else if (cfg.alerts && (f.alerts_webhook || f.alerts_email)) {
    delete cfg.webhook
  }
  // 告警引擎 + 阈值
  if (f.alerts_enabled) {
    cfg.alerts = {
      enabled: true,
      interval_sec: f.alerts_interval,
      cooldown_min: f.alerts_cooldown,
      notify_webhook: f.alerts_webhook,
      notify_email: f.alerts_email,
      rules: {
        cpu: { enabled: f.alert_rules.cpu.enabled, threshold: f.alert_rules.cpu.threshold, window_sec: f.alert_rules.cpu.window_sec || 60 },
        mem: { enabled: f.alert_rules.mem.enabled, threshold: f.alert_rules.mem.threshold, window_sec: f.alert_rules.mem.window_sec || 60 },
        disk: { enabled: f.alert_rules.disk.enabled, threshold: f.alert_rules.disk.threshold },
        web_requests: { enabled: f.alert_rules.requests.enabled, threshold: f.alert_rules.requests.threshold },
        web_attacks: { enabled: f.alert_rules.attacks.enabled, threshold: f.alert_rules.attacks.threshold },
        blocked: { enabled: f.alert_rules.blocked.enabled, threshold: f.alert_rules.blocked.threshold },
        top_attack_ip: { enabled: f.alert_rules.top_ip.enabled, threshold: f.alert_rules.top_ip.threshold },
        top_target: { enabled: f.alert_rules.top_target.enabled, threshold: f.alert_rules.top_target.threshold },
      },
    }
  } else delete cfg.alerts
  // 邮件通道(SMTP)
  if (f.email_enabled && f.email_host && f.email_from) {
    cfg.email = {
      enabled: true, host: f.email_host, port: f.email_port, from: f.email_from,
      username: f.email_user, password: f.email_pass, ssl: f.email_ssl,
      to: f.email_to.filter(Boolean),
    }
  } else if (cfg.email && !f.email_enabled) {
    cfg.email = { ...(cfg.email || {}), enabled: false }
  }
  // 安全设置(密码策略/会话超时/登录锁定/密码历史)
  cfg.security = {
    password_min_len: f.sec_min_len,
    password_complexity: f.sec_complexity,
    password_max_age_days: f.sec_max_age,
    session_timeout_min: f.sec_session,
    password_history_count: f.sec_pw_history,
    login_max_failures: f.sec_login_max,
    login_lockout_min: f.sec_lockout_min,
  }
  if (f.console_ips.filter(Boolean).length) {
    cfg.console = { allowed_ips: f.console_ips.filter(Boolean) }
  } else delete cfg.console
  // 管理面 IP 白名单由「用户管理 → 安全设置」维护，此处不再触碰 cfg.console
  // 拦截页定制（block_page）：四项全空则整体删除，回落内置拦截页
  if (f.bp_title || f.bp_message || f.bp_footer || f.bp_html) {
    cfg.block_page = { title: f.bp_title, message: f.bp_message, footer: f.bp_footer }
    if (f.bp_html) cfg.block_page.html = f.bp_html
  } else delete cfg.block_page
  if (f.ai_enabled) {
    // 从加载的 c.ai 展开/合并：透传保留 api_key_hash/api_key_cipher 等
    // 表单不回显的字段，否则本次发布会把已存库的 Key 字段丢掉
    cfg.ai = {
      ...(cfg.ai || {}),
      enabled: true,
      provider: {
        ...(cfg.ai?.provider || {}),
        template: f.ai_template, base_url: f.ai_base, model: f.ai_model,
        max_tokens: f.ai_max_tokens, temperature: Number(f.ai_temperature) || 0.2, timeout_sec: f.ai_timeout,
      },
      chat: { context_window_tokens: f.ai_ctx_tokens || undefined, keep_recent_turns: f.ai_keep_turns, history_retention_days: f.ai_history_days || undefined },
      sanitize: { ...(cfg.ai?.sanitize || {}), enabled: !!f.ai_sanitize },
      analysis: { ...(cfg.ai?.analysis || {}), enabled: !!f.ai_analysis, max_tokens_per_day: Math.round(Number(f.ai_report_tokens_wan) * 10000) },
    }
    if (f.ai_analysis) {
      // 只重建 attack_summary_daily 条目，其它 kind 的既有计划保留不动
      const daily = { kind: 'attack_summary_daily', cron: buildReportCron(f.ai_report_time, f.ai_report_days), channel: f.ai_report_channel }
      if (f.ai_report_channel === 'webhook') daily.webhook = (f.ai_report_webhook || '').trim()
      else daily.email = (f.ai_report_email || '').trim()
      const others = (cfg.ai.analysis.schedules || []).filter(s => s.kind !== 'attack_summary_daily')
      cfg.ai.analysis.schedules = [...others, daily]
    }
    if (f.ai_sysprompt) cfg.ai.system_prompt = f.ai_sysprompt
  } else if (typeof cfg.ai === 'object') {
    cfg.ai = { ...(cfg.ai || {}), enabled: false }
  }
  try {
    const r = await post('/api/config/publish', { note: 'settings update', config: cfg })
    applyNotice(r, '已发布并热生效（版本 ' + r.revision + '）')
    // 发布成功后后端清空 load_notes（A2）：通知 Layout 全局横幅立即复查，不必等下一轮 30s 轮询
    window.dispatchEvent(new Event('km-status-refresh'))
    load()
  } catch (e) {
    ElMessage.error('发布失败：' + e.message)
  }
}

onMounted(load)
onBeforeUnmount(() => { if (portCountdown) clearInterval(portCountdown); stopUpgradePoll() })
</script>

<style scoped>
.km-load-note { font-size: 12px; line-height: 1.8; font-family: ui-monospace, SFMono-Regular, Consolas, 'Courier New', monospace; color: var(--km-txt-2); word-break: break-all; }
.km-upg-notes { white-space: pre-wrap; font-size: 12.5px; line-height: 1.9; max-height: 200px; overflow-y: auto; color: var(--km-txt-2); }
.km-upg-steps { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.km-upg-step { display: inline-flex; align-items: center; gap: 6px; padding: 5px 12px; border-radius: 999px; font-size: 12px; border: 1px solid var(--km-line); background: var(--km-panel-2); color: var(--km-txt-3); }
.km-upg-step .dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; opacity: .55; }
.km-upg-step.done { color: var(--km-green); opacity: .9; }
.km-upg-step.on { background: var(--km-nav-grad); color: var(--km-nav-tx); border-color: transparent; font-weight: 600; }
.km-upg-step.on .dot { opacity: 1; animation: kmUpgPulse 1.2s infinite; }
.km-upg-arrow { color: var(--km-txt-3); font-size: 11px; }
@keyframes kmUpgPulse { 50% { opacity: .35; } }
</style>
