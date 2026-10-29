<template>
  <div>
    <div class="km-toolbar">
      <el-alert type="info" :closable="false" show-icon style="flex:1"
                title="策略保存即发布为新配置版本并热生效；CRS 阈值、微引擎规则与自定义规则对所有开启 WAF 的站点生效" />
      <el-tag effect="plain" type="success" class="km-tag">● 规则 revision #{{ rev }} 已发布 · 热加载生效</el-tag>
    </div>

    <div style="display:flex;gap:16px;align-items:flex-start">
      <!-- 左栏二级菜单（复用 Settings.vue .km-set-nav 三件套） -->
      <el-card shadow="never" class="km-set-nav" :body-style="{ padding: '8px' }">
        <div v-for="t in tabs" :key="t.id" class="item" :class="{ on: tab === t.id }" @click="tab = t.id">
          <span>{{ t.icon }} {{ t.name }}</span>
        </div>
      </el-card>

      <div style="flex:1;min-width:0">
        <!-- ① CRS 异常评分阈值 -->
        <template v-if="tab === 'thresholds'">
          <el-card shadow="never">
            <div class="km-title">CRS 异常评分阈值</div>
            <el-form label-width="220px" label-position="left">
              <el-form-item label="入站异常评分阈值（inbound）">
                <div style="width:100%">
                  <el-input-number v-model="p.inbound" :min="1" :max="100" />
                  <div class="km-dim" style="font-size:12px;margin-top:4px">默认 5。命中规则按严重级别累计异常分（CRITICAL +5 / ERROR +4 / WARNING +3 / NOTICE +2），累计达到阈值即阻断；合法范围 1–100，调高减少误拦，调低更严格</div>
                </div>
              </el-form-item>
              <el-form-item label="出站异常评分阈值（outbound）">
                <div style="width:100%">
                  <el-input-number v-model="p.outbound" :min="1" :max="100" />
                  <div class="km-dim" style="font-size:12px;margin-top:4px">默认 4。出站（响应侧）命中规则按严重级别累计异常分，累计达到阈值即阻断；合法范围 1–100，调高减少误拦，调低更严格</div>
                </div>
              </el-form-item>
            </el-form>
            <div class="km-dim" style="font-size:12px;margin-top:4px;padding:10px 14px;border:1px solid var(--km-line-soft);border-radius:6px;background:var(--km-bg-2)">
              <div style="margin-bottom:4px">计分规则：命中规则按严重级别累计异常分，累计达到阈值即阻断（入站 / 出站分别评估）。</div>
              <table style="border-collapse:collapse;font-size:12px">
                <tbody>
                  <tr>
                    <th style="text-align:left;padding:3px 18px 3px 0;color:var(--km-txt-3);font-weight:500">严重级别</th>
                    <th style="text-align:left;padding:3px 18px 3px 0;color:var(--km-txt-3);font-weight:500">分值</th>
                    <th style="text-align:left;padding:3px 18px 3px 0;color:var(--km-txt-3);font-weight:500">典型来源</th>
                  </tr>
                  <tr><td style="padding:3px 18px 3px 0">CRITICAL</td><td style="padding:3px 18px 3px 0">5</td><td style="padding:3px 0">应用攻击类规则（SQL 注入、XSS、RCE、LFI/RFI 等）</td></tr>
                  <tr><td style="padding:3px 18px 3px 0">ERROR</td><td style="padding:3px 18px 3px 0">4</td><td style="padding:3px 0">出站信息泄露类规则</td></tr>
                  <tr><td style="padding:3px 18px 3px 0">WARNING</td><td style="padding:3px 18px 3px 0">3</td><td style="padding:3px 0">恶意客户端类规则</td></tr>
                  <tr><td style="padding:3px 18px 3px 0">NOTICE</td><td style="padding:3px 18px 3px 0">2</td><td style="padding:3px 0">协议合规类规则</td></tr>
                </tbody>
              </table>
              <div style="margin-top:8px">详细技术说明：<a href="https://gitee.com/aiuc-labs/KingMoat-WAF/blob/main/docs/CRS-ANOMALY-SCORING.md" target="_blank" rel="noopener" style="color:var(--km-cyan)">Gitee</a><span style="margin:0 6px">·</span><a href="https://github.com/aiuc-labs/KingMoat-WAF/blob/main/docs/CRS-ANOMALY-SCORING.md" target="_blank" rel="noopener" style="color:var(--km-cyan)">GitHub</a></div>
            </div>
            <div style="text-align:right">
              <el-button type="primary" :loading="saving" :disabled="!can('operator')" @click="saveThresholds">
                保存并发布（热生效）
              </el-button>
            </div>
          </el-card>
        </template>

        <!-- ② 黑白名单管理 -->
        <template v-else-if="tab === 'acl'">
          <el-card shadow="never">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
              <div class="km-title" style="margin:0">黑白名单管理（全局 · 先于站点 ACL）</div>
              <div class="km-seg" style="margin-left:auto">
                <span class="seg-item" :class="{ on: blTab === 'black' }" @click="blTab = 'black'">黑名单（{{ p.gBlack.filter(Boolean).length }}）</span>
                <span class="seg-item" :class="{ on: blTab === 'white' }" @click="blTab = 'white'">白名单（{{ p.gWhite.filter(Boolean).length }}）</span>
              </div>
            </div>
            <div class="km-dim" style="font-size:12px;margin-bottom:10px" v-if="blTab === 'black'">黑名单命中即拦截（403）。</div>
            <div class="km-dim" style="font-size:12px;margin-bottom:10px" v-else>白名单在 CRS 之前短路放行（信任来源）；支持从攻击日志一键加白，加白记录见「微引擎规则防护」页签。</div>
            <div v-for="row in pagedBL" :key="row.i" style="display:flex;gap:8px;margin-bottom:6px">
              <el-input v-model="blList[row.i]" placeholder="IP/CIDR/group:名称" class="km-mono" />
              <el-button link type="danger" @click="blList.splice(row.i, 1)"><el-icon><Delete /></el-icon></el-button>
            </div>
            <el-button size="small" @click="addBlankBL"><el-icon><Plus /></el-icon>&nbsp;新增</el-button>
            <div v-if="blList.length > blPageSize" style="display:flex;justify-content:flex-end;gap:10px;align-items:center;padding:10px 0 0">
              <span class="km-dim" style="font-size:12px">每页</span>
              <el-select v-model="blPageSize" size="small" style="width:84px"
                         @change="() => { const max = Math.max(1, Math.ceil(blList.length / blPageSize)); if (blPage > max) blPage = max }">
                <el-option v-for="n in [10, 20, 50, 100]" :key="n" :label="n + ' 条'" :value="n" />
              </el-select>
              <el-pagination layout="prev, pager, next" small background :total="blList.length"
                             :page-size="blPageSize" :current-page="blPage"
                             @current-change="p => blPage = p" />
            </div>
            <div style="text-align:right;margin-top:12px">
              <el-button type="primary" :loading="saving" :disabled="!can('operator')" @click="saveACL">
                保存并发布（热生效）
              </el-button>
            </div>
          </el-card>
        </template>

        <!-- ③ IP 组管理 -->
        <template v-else-if="tab === 'ipgroups'">
          <el-card shadow="never">
            <div style="display:flex;align-items:center;gap:10px">
              <div class="km-title" style="margin:0">IP 组管理（手动维护 / 订阅，ACL 中以 group:名称 引用）</div>
              <el-button v-if="can('operator')" size="small" type="primary" style="margin-left:auto" @click="openGroup(-1)"><el-icon><Plus /></el-icon>&nbsp;新建 IP 组</el-button>
            </div>
            <el-table :data="pagedGroups" size="small" style="margin-top:10px">
              <el-table-column prop="name" label="组名" width="140" class-name="km-mono" />
              <el-table-column label="类型" width="90">
                <template #default="{ row }">
                  <el-tag size="small" effect="plain" :type="row.type === 'manual' ? 'primary' : 'success'" class="km-tag">{{ row.type === 'manual' ? '手动' : '订阅' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="来源 / 成员" show-overflow-tooltip>
                <template #default="{ row }">
                  {{ row.type === 'manual' ? ((row.members || []).join(', ') || '-') : (row.url || row.file) }}
                </template>
              </el-table-column>
              <el-table-column prop="entries" label="成员" width="80" />
              <el-table-column label="预览" show-overflow-tooltip>
                <template #default="{ row }">{{ (row.sample || []).join(', ') }}</template>
              </el-table-column>
              <el-table-column label="操作" width="150">
                <template #default="{ row }">
                  <el-button v-if="can('operator') && row.type === 'manual'" link type="primary" size="small" @click="openGroup(ipGroups.indexOf(row))">编辑</el-button>
                  <el-button v-if="can('operator') && row.type !== 'manual'" link type="primary" size="small" @click="refreshGroup(row.name)">刷新</el-button>
                  <el-button v-if="can('operator')" link type="danger" size="small" @click="delGroup(row.name)">删除</el-button>
                </template>
              </el-table-column>
            </el-table>
            <div v-if="ipGroups.length > grpPageSize" style="display:flex;justify-content:flex-end;gap:10px;align-items:center;padding:10px 0 0">
              <span class="km-dim" style="font-size:12px">每页</span>
              <el-select v-model="grpPageSize" size="small" style="width:84px"
                         @change="() => { const max = Math.max(1, Math.ceil(ipGroups.length / grpPageSize)); if (grpPage > max) grpPage = max }">
                <el-option v-for="n in [10, 20, 50, 100]" :key="n" :label="n + ' 条'" :value="n" />
              </el-select>
              <el-pagination layout="prev, pager, next" small background :total="ipGroups.length"
                             :page-size="grpPageSize" :current-page="grpPage"
                             @current-change="p => grpPage = p" />
            </div>
            <div class="km-muted" style="font-size:11.5px;margin-top:8px">手动组发布后立即生效；订阅组按间隔自动拉取，被 ACL 引用中的组删除前请先移除引用</div>
          </el-card>
        </template>

        <!-- ④ 微引擎规则防护 -->
        <template v-else-if="tab === 'matchers'">
          <el-alert v-if="legacyWhitelist.length" type="warning" :closable="false" style="margin-bottom:16px">
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
              <span>发现 {{ legacyWhitelist.length }} 条旧版误报加白记录（exception 模式），可一键迁移为微引擎放行规则</span>
              <el-button size="small" type="primary" :loading="migrating" @click="migrateWhitelist">一键迁移</el-button>
              <el-button size="small" @click="dismissMigration">忽略</el-button>
            </div>
          </el-alert>

          <el-card shadow="never" style="margin-bottom:16px">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
              <div class="km-title" style="margin:0">微引擎规则防护</div>
              <div style="flex:1"></div>
              <el-button v-if="can('operator')" type="primary" size="small" @click="openMatcher(-1)"><el-icon><Plus /></el-icon>&nbsp;新建规则</el-button>
            </div>
            <div class="km-dim" style="font-size:12px;margin-bottom:10px">
              基于来源 / 域名 / 路径 / 方法 / Header 等条件的轻量匹配，先于 CRS 全量规则执行，用于高频场景的快速放行与拦截；支持命中后关闭指定检测模块。
            </div>
            <div style="display:flex;gap:10px;align-items:center;margin-bottom:10px;flex-wrap:wrap">
              <el-input v-model="mFilterName" size="small" placeholder="按名称查询" clearable style="width:200px" />
              <el-input v-model="mFilterPath" size="small" placeholder="按路径查询（条件值/规则名）" clearable style="width:240px" class="km-mono" />
              <el-select v-model="mFilterSite" size="small" placeholder="按站点筛选" clearable style="width:220px">
                <el-option label="全部站点" value="__all__" />
                <el-option v-for="d in siteOptions" :key="d" :value="d" :label="d" />
              </el-select>
              <span class="km-dim" style="font-size:12px">共 {{ filteredMatchers.length }} / {{ matchers.length }} 条</span>
              <el-button v-if="mFilterName || mFilterPath || (mFilterSite && mFilterSite !== '__all__')"
                         link type="primary" size="small" @click="resetMatcherFilters">清空筛选</el-button>
            </div>
            <el-table :data="pagedMatchers" size="small">
              <el-table-column label="规则名称" width="200">
                <template #default="{ row }">
                  <span>{{ row.name }}</span>
                  <el-tag v-if="isWhitelistRule(row)" size="small" type="success" effect="plain" class="km-tag" style="margin-left:6px">误报加白</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="作用站点" width="150" show-overflow-tooltip>
                <template #default="{ row }">{{ (row.sites && row.sites.length) ? row.sites.join(', ') : '全部站点' }}</template>
              </el-table-column>
              <el-table-column label="条件" show-overflow-tooltip>
                <template #default="{ row }">
                  <span class="km-mono" style="font-size:12px">
                    {{ (row.conditions || []).map(c => condLabel(c)).join(row.logic === 'or' ? ' 或 ' : ' 且 ') }}
                  </span>
                </template>
              </el-table-column>
              <el-table-column label="动作" width="110">
                <template #default="{ row }">
                  <el-tag size="small" :type="{ deny: 'danger', allow: 'success', monitor: 'info', disable: 'warning' }[row.action]" effect="dark" class="km-tag">
                    {{ { deny: '拦截', allow: '放行(信任)', monitor: '观察', disable: '关闭模块' }[row.action] }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column label="命中次数" width="90" align="center">
                <template #default="{ row }">
                  <span :style="(matcherHits[row.name] || 0) > 0 ? 'font-weight:700;color:var(--km-soft-blue)' : 'color:var(--km-txt-3)'">{{ (matcherHits[row.name] || 0).toLocaleString() }}</span>
                </template>
              </el-table-column>
              <el-table-column label="记录日志" width="90" align="center">
                <template #default="{ row }">
                  <el-tooltip content="开启后命中该规则的请求写入攻击日志，可点击「日志」查看命中详情" placement="top">
                    <el-switch v-model="row.log_enabled" size="small" :disabled="!can('operator')" @change="toggleMatcherLog(row)" />
                  </el-tooltip>
                </template>
              </el-table-column>
              <el-table-column label="状态" width="80">
                <template #default="{ row }">
                  <el-tag size="small" :type="row.enabled ? 'success' : 'info'" effect="dark" class="km-tag">{{ row.enabled ? '启用' : '停用' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column width="170">
                <template #default="{ row }">
                  <el-button link type="primary" size="small" @click="openMatcher(matchers.indexOf(row))">编辑</el-button>
                  <el-button v-if="row.log_enabled && (matcherHits[row.name] || 0) > 0" link type="primary" size="small" @click="gotoRuleLogs('matcher/' + row.name)">日志</el-button>
                  <el-button link type="danger" size="small" @click="removeMatcher(row)">删除</el-button>
                </template>
              </el-table-column>
            </el-table>
            <div v-if="filteredMatchers.length > mPageSize" style="display:flex;justify-content:flex-end;gap:10px;align-items:center;padding:10px 0 0">
              <span class="km-dim" style="font-size:12px">每页</span>
              <el-select v-model="mPageSize" size="small" style="width:84px"
                         @change="() => { const max = Math.max(1, Math.ceil(filteredMatchers.length / mPageSize)); if (mPage > max) mPage = max }">
                <el-option v-for="n in [10, 20, 50, 100]" :key="n" :label="n + ' 条'" :value="n" />
              </el-select>
              <el-pagination layout="prev, pager, next" small background :total="filteredMatchers.length"
                             :page-size="mPageSize" :current-page="mPage"
                             @current-change="p => mPage = p" />
            </div>
          </el-card>

          <el-card shadow="never">
            <div class="km-title" style="margin-bottom:6px">说明</div>
            <div class="km-muted" style="font-size:11.5px">攻击日志页「一键加白」会在此创建名称以「误报加白」开头的放行规则（站点+路径条件，命中后跳过全部检测）；规则可编辑、禁用、删除，与普通微引擎规则一致，变更发布后热生效</div>
          </el-card>
        </template>

        <!-- ⑤ 攻击惩罚 -->
        <template v-else-if="tab === 'penalty'">
          <el-card shadow="never">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
              <div class="km-title" style="margin:0">攻击惩罚（扫描/爆破自动处置）</div>
              <el-switch v-model="p.penalty_enabled" style="margin-left:auto" />
            </div>
            <template v-if="p.penalty_enabled">
              <div class="km-set-row"><div class="grow"><div class="set-name">统计窗口</div><div class="set-desc">窗口内累计同源 IP 的拦截与挑战次数</div></div>
                <el-input-number v-model="p.penalty_window" :min="60" :max="86400" size="small" style="width:130px" /><span class="km-muted" style="font-size:12px">秒</span></div>
              <div class="km-set-row"><div class="grow"><div class="set-name">触发阈值</div><div class="set-desc">达到阈值即对该 IP 施加惩罚</div></div>
                <el-input-number v-model="p.penalty_threshold" :min="3" :max="10000" size="small" style="width:130px" /><span class="km-muted" style="font-size:12px">次</span></div>
              <div class="km-set-row"><div class="grow"><div class="set-name">惩罚方式</div><div class="set-desc">临时封禁或严格限速</div></div>
                <el-radio-group v-model="p.penalty_action" size="small">
                  <el-radio-button value="deny">临时封禁</el-radio-button>
                  <el-radio-button value="throttle">严格限速</el-radio-button>
                </el-radio-group></div>
              <div class="km-set-row"><div class="grow"><div class="set-name">惩罚时长</div><div class="set-desc">默认 3600（1 小时）</div></div>
                <el-input-number v-model="p.penalty_ban" :min="60" :max="86400" size="small" style="width:130px" /><span class="km-muted" style="font-size:12px">秒</span></div>
              <div v-if="p.penalty_action === 'throttle'" class="km-set-row"><div class="grow"><div class="set-name">限速</div><div class="set-desc">惩罚期内超出即 429</div></div>
                <el-input-number v-model="p.penalty_per_min" :min="1" :max="1000" size="small" style="width:130px" /><span class="km-muted" style="font-size:12px">次/分</span></div>
            </template>
            <div class="km-muted" style="font-size:11.5px;margin-top:8px">
              惩罚状态保存在内存中，配置发布或服务重启后清空；命中惩罚的请求以 penalty/engine 记录在攻击日志中
            </div>
            <div style="text-align:right;margin-top:12px">
              <el-button type="primary" :loading="saving" :disabled="!can('operator')" @click="savePenalty">
                保存并发布（热生效）
              </el-button>
            </div>
          </el-card>
        </template>

      <template v-else-if="tab === 'custom'">
        <RuleExpert />

        <!-- 自定义规则列表：启用/禁用、修改、检索、命中日志（数据仍存 policy.custom_rules 文本） -->
        <el-card shadow="never">
          <div class="km-card-head">
            <span class="km-card-title">自定义规则（{{ crules.length }}）</span>
            <div class="extra" style="display:flex;gap:8px;align-items:center">
              <el-input v-model="crSearch" size="small" style="width:220px" placeholder="检索：ID / 描述 / 规则内容" clearable />
              <el-button size="small" :loading="crHitLoading" @click="loadCrHits">刷新命中</el-button>
              <el-dropdown trigger="click" @command="crExportAs">
                <el-button size="small" :disabled="!crules.length">
                  导出{{ crSelected.length ? '（选中 ' + crSelected.length + '）' : '全部' }}
                  <el-icon class="el-icon--right"><ArrowDown /></el-icon>
                </el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="json">JSON（含启用状态，可回灌）</el-dropdown-item>
                    <el-dropdown-item command="seclang">SecLang 文本（.txt，通用格式）</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
              <el-button size="small" :disabled="!can('operator')" @click="crFileInput && crFileInput.click()">导入</el-button>
              <input ref="crFileInput" type="file" accept=".json,.txt,.conf,.seclang,.rules" style="display:none" @change="crImport" />
              <el-button size="small" :disabled="!can('operator')" @click="crAdd">新增规则</el-button>
              <el-button size="small" type="primary" :loading="saving" :disabled="!can('operator')" @click="saveCustom">保存并发布（热生效）</el-button>
              <el-button size="small" @click="openRt">测试命中</el-button>
            </div>
          </div>
          <el-table :data="crPaged" size="small" border @selection-change="onCrSelection">
            <el-table-column type="selection" width="44" />
            <el-table-column label="ID" width="110">
              <template #default="{ row }"><span class="km-mono">{{ row.id || '-' }}</span></template>
            </el-table-column>
            <el-table-column label="状态" width="88">
              <template #default="{ row }">
                <el-switch :model-value="!row.disabled" size="small" :disabled="!can('operator')" @change="() => crToggle(row)" />
              </template>
            </el-table-column>
            <el-table-column label="命中(24h)" width="112" align="right">
              <template #default="{ row }">
                <el-button link type="primary" size="small" :loading="crHitLoading"
                           :disabled="!crHitMap[row.id]" @click="crLogs(row)"
                           :title="crHitMap[row.id] ? '点击查看命中日志' : '24 小时内无命中'">
                  {{ crHitMap[row.id] || 0 }}
                </el-button>
              </template>
            </el-table-column>
            <el-table-column label="描述" min-width="180" show-overflow-tooltip>
              <template #default="{ row }">{{ row.msg || '(无 msg)' }}</template>
            </el-table-column>
            <el-table-column label="规则内容" min-width="340">
              <template #default="{ row }">
                <span class="km-mono" style="font-size:12px;white-space:pre-wrap;word-break:break-all">{{ row.preview }}</span>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="220">
              <template #default="{ row }">
                <el-button link type="primary" size="small" :disabled="!can('operator')" @click="crEdit(row)">修改</el-button>
                <el-button link type="primary" size="small" @click="crLogs(row)">命中日志</el-button>
                <el-button link type="danger" size="small" :disabled="!can('operator')" @click="crRemove(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-if="!crules.length" description="暂无自定义规则" :image-size="70" />
          <div v-if="crFiltered.length > crPageSize" style="display:flex;justify-content:flex-end;gap:10px;padding:10px 16px 14px">
            <span class="km-dim" style="font-size:12px">每页</span>
            <el-select v-model="crPageSize" size="small" style="width:84px">
              <el-option v-for="n in [10, 20, 50, 100]" :key="n" :label="n + ' 条'" :value="n" />
            </el-select>
            <el-pagination layout="prev, pager, next" small background :total="crFiltered.length"
                           :page-size="crPageSize" :current-page="crPage" @current-change="p2 => crPage = p2" />
          </div>
          <div class="km-dim" style="font-size:12px;padding:0 16px 12px">
            保存时服务端会编译校验，语法错误将拒绝发布并保留旧配置；命中记录在「攻击日志」，点击「命中日志」可按规则名
            <span class="km-mono">rule-&lt;id&gt;</span> 过滤。
          </div>
          <el-collapse style="padding:0 12px 12px">
            <el-collapse-item title="高级：直接编辑原始 SecLang 文本" name="raw">
              <el-input v-model="p.customRules" type="textarea" :rows="12" class="km-mono" spellcheck="false" :disabled="!can('operator')" />
            </el-collapse-item>
          </el-collapse>
        </el-card>

        <!-- 规则编辑弹窗 -->
        <el-dialog v-model="crDlg" :title="crIdx < 0 ? '新增自定义规则' : ('修改规则 ' + ((crules[crIdx] || {}).id || ''))" width="680px">
          <el-form label-width="90px">
            <el-form-item label="描述 msg">
              <el-input v-model="crForm.msg" placeholder="如：拦截 /api/v1/exec 的命令注入" />
            </el-form-item>
            <el-form-item label="规则文本">
              <el-input v-model="crForm.text" type="textarea" :rows="10" class="km-mono" spellcheck="false"
                        placeholder="SecRule ARGS_GET:cmd &quot;@rx ...&quot; &quot;id:100001,phase:2,deny,status:403,log,msg:&#39;...&#39;&quot;" />
            </el-form-item>
          </el-form>
          <template #footer>
            <el-button @click="crDlg = false">取消</el-button>
            <el-button type="primary" @click="crSave">确定</el-button>
          </template>
        </el-dialog>
        <el-dialog v-model="rt.dlg" title="规则测试命中（用样例请求验证，不会发布）" width="720px">
          <el-form label-width="90px">
            <el-form-item label="请求">
              <div style="display:flex;gap:8px;flex-wrap:wrap;width:100%">
                <el-select v-model="rt.method" size="small" style="width:106px">
                  <el-option v-for="m in ['GET', 'POST', 'PUT', 'DELETE']" :key="m" :label="m" :value="m" />
                </el-select>
                <el-input v-model="rt.path" size="small" style="width:230px" class="km-mono" placeholder="/api/v1/exec" />
                <el-input v-model="rt.query" size="small" style="width:250px" class="km-mono" placeholder="cmd=id;whoami（不含 ?）" />
              </div>
            </el-form-item>
            <el-form-item label="请求头">
              <el-input v-model="rt.headers" type="textarea" :rows="2" class="km-mono" placeholder="每行 Key: Value（可留空）" />
            </el-form-item>
            <el-form-item label="请求体">
              <el-input v-model="rt.body" type="textarea" :rows="3" class="km-mono" placeholder="POST 时使用（可留空）" />
            </el-form-item>
          </el-form>
          <div style="display:flex;gap:10px;align-items:center">
            <el-button size="small" type="primary" :loading="rt.testing" :disabled="!(p.customRules || '').trim()" @click="runRt">执行测试</el-button>
            <span class="km-dim" style="font-size:12px">使用当前草稿规则（含未发布的修改）；只读，不会写配置</span>
          </div>
          <el-alert v-if="rt.err" type="error" :closable="false" style="margin-top:12px" :title="'规则无效：' + rt.err" />
          <div v-if="rt.res" style="margin-top:12px">
            <el-alert v-if="rtHits.length" type="success" :closable="false" :title="'命中 ' + rtHits.length + ' 条自定义规则'" />
            <el-alert v-else type="warning" :closable="false" title="未命中任何自定义规则（规则可编译，但该样例请求没有触发）" />
            <el-table v-if="rtHits.length" :data="rtHits" size="small" style="margin-top:8px">
              <el-table-column prop="id" label="规则 ID" width="120" />
              <el-table-column prop="message" label="msg" />
            </el-table>
            <div class="km-dim" style="font-size:12px;margin-top:8px">
              完整 CRS 栈下：{{ rt.res.full_stack && rt.res.full_stack.denied ? ('被规则 ' + (rt.res.full_stack.interrupt_rule_id || '-') + ' 拦截') : '放行' }}
              <span v-if="rt.res.full_stack && rt.res.full_stack.denied && !rtHits.length">（该 ID 通常来自 CRS；自定义规则追加在 CRS 之后，被 CRS 拦下的请求不会到达自定义规则）</span>
            </div>
          </div>
        </el-dialog>

      </template>

        <!-- ⑦ 引擎与规则版本(编译期内嵌只读) -->
        <template v-else-if="tab === 'versions'">
          <el-card shadow="never">
            <div class="km-title" style="margin-bottom:8px">引擎与规则版本</div>
            <div class="ver-grid">
              <div class="ver-item"><div class="ver-k">检测引擎</div><div class="ver-v km-mono">{{ engine.coraza || '-' }}</div></div>
              <div class="ver-item"><div class="ver-k">规则集</div><div class="ver-v km-mono">{{ engine.crs ? 'OWASP CRS ' + engine.crs.replace('v', '') : '-' }}</div></div>
              <div class="ver-item"><div class="ver-k">控制台版本</div><div class="ver-v km-mono">{{ version || '-' }}</div><div class="ver-s">发布物与引擎同版本构建</div></div>
            </div>
          </el-card>
        </template>

        <!-- ⑧ 检测分类与引擎（CRS 全局默认 + 站点级引擎启用聚合） -->
        <template v-else-if="tab === 'engines'">
          <el-row :gutter="16">
            <el-col :span="13">
              <el-card shadow="never" style="height:100%">
                <div class="km-title" style="margin:0 0 4px">CRS 检测分类全局默认</div>
                <div class="km-dim" style="font-size:12px;margin-bottom:12px">
                  新建站点与未单独配置分类的站点按此默认装载 CRS 检测类别；站点可在「站点管理」页单独覆盖
                </div>
                <div class="cat-grid">
                  <div v-for="c in CRS_CATEGORIES" :key="c.id" class="cat-item" :class="{ 'cat-off': !wafCats[c.id] }">
                    <span class="cat-label">{{ c.label }}</span>
                    <el-switch v-model="wafCats[c.id]" size="small" :disabled="!can('operator')" />
                  </div>
                </div>
                <div style="display:flex;justify-content:space-between;align-items:center;margin-top:14px">
                  <el-button link type="primary" size="small" :disabled="!can('operator')" @click="setAllWafCats(true)">全部启用</el-button>
                  <el-button type="primary" :loading="saving" :disabled="!can('operator')" @click="saveWafCategories">
                    保存并发布（热生效）
                  </el-button>
                </div>
              </el-card>
            </el-col>
            <el-col :span="11">
              <el-card shadow="never" style="height:100%">
                <div class="km-title" style="margin:0 0 4px">检测引擎启用情况（按站点聚合）</div>
                <div class="km-dim" style="font-size:12px;margin-bottom:12px">各引擎在「站点防护」中按站点独立开关</div>
                <div class="eng-grid">
                  <div v-for="e in engineStats" :key="e.name" class="eng-item" :class="{ 'eng-off': !e.count }">
                    <div class="eng-head">
                      <span class="eng-name">{{ e.name }}</span>
                      <span class="eng-count" :class="{ 'eng-on': e.count }">{{ e.count }}/{{ totalSites }}</span>
                    </div>
                    <div class="eng-desc">{{ e.desc }}</div>
                    <el-progress :percentage="totalSites ? Math.round(e.count * 100 / totalSites) : 0"
                                 :stroke-width="6" :show-text="false"
                                 :color="e.count ? '#4da3ff' : '#3a4356'" />
                  </div>
                </div>
              </el-card>
            </el-col>
          </el-row>
        </template>
      </div>
    </div>

    <!-- 条件组合规则构建器 -->
    <el-dialog v-model="mDlg" :title="mEditIndex < 0 ? '新建微引擎规则' : '编辑规则 · ' + m.name" width="720px">
      <el-form label-width="90px" label-position="left">
        <el-form-item label="规则名称"><el-input v-model="m.name" placeholder="如 封禁扫描器 UA" /></el-form-item>
        <el-form-item label="匹配动作">
          <el-radio-group v-model="m.action" @change="onMatcherActionChange">
            <el-radio-button value="deny">拦截</el-radio-button>
            <el-radio-button value="allow">放行（信任）</el-radio-button>
            <el-radio-button value="monitor">仅观察</el-radio-button>
            <el-radio-button value="disable">关闭检测模块</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="m.action === 'disable'" label="关闭模块">
          <el-checkbox-group v-model="m.disable_stages" style="width:100%" @change="onStagesChange">
            <div class="km-dim" style="font-size:12px;margin-bottom:10px">命中该规则后，作用站点的这些检测模块/分类被关闭（重新发布配置或删除规则后恢复）；访问控制类模块不可关闭</div>
            <div class="mod-row">
              <el-checkbox value="coraza" border size="small">CRS 签名检测</el-checkbox>
              <el-checkbox value="semantic" border size="small">语义检测</el-checkbox>
              <el-checkbox value="botdetect" border size="small">BOT 识别</el-checkbox>
              <el-checkbox value="botchallenge" border size="small">BOT 挑战</el-checkbox>
              <el-checkbox value="ratelimit" border size="small">CC 限流</el-checkbox>
              <el-checkbox value="captcha" border size="small">人机验证</el-checkbox>
            </div>
            <div class="cats-toggle" :class="{ 'cats-on': catsOpen, 'cats-disabled': m.disable_stages.includes('coraza') }"
                 @click="toggleCats">
              <el-icon class="cats-arrow" :class="{ open: catsOpen }"><ArrowRight /></el-icon>
              <span>按分类关闭 CRS</span>
              <span class="cats-sub">与「CRS 签名检测」整模块互斥</span>
            </div>
            <el-collapse-transition>
              <div v-if="catsOpen" class="cats-panel">
                <div class="cats-grid">
                  <el-checkbox v-for="c in CRS_CATEGORIES" :key="c.id" :value="'coraza:' + c.id" border size="small"
                               :disabled="m.disable_stages.includes('coraza')">{{ c.label }}</el-checkbox>
                </div>
                <div class="km-dim" style="font-size:11.5px;margin-top:14px">命中后仅这些分类的检测被关闭，其余分类照常拦截；两者并存请拆成两条规则</div>
              </div>
            </el-collapse-transition>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item label="作用站点">
          <el-select v-model="m.sites" multiple filterable allow-create default-first-option
                     placeholder="留空 = 全部站点" style="width:100%">
            <el-option v-for="d in siteOptions" :key="d" :value="d" :label="d" />
          </el-select>
        </el-form-item>
        <el-form-item label="条件逻辑">
          <el-radio-group v-model="m.logic">
            <el-radio-button value="and">全部满足（AND）</el-radio-button>
            <el-radio-button value="or">任一满足（OR）</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="条件列表">
          <div style="width:100%">
            <div v-for="(c, i) in m.conditions" :key="i" style="display:flex;gap:6px;margin-bottom:6px">
              <el-select v-model="c.field" style="width:190px" filterable allow-create default-first-option>
                <el-option-group label="基础字段">
                  <el-option label="来源 IP" value="client_ip" /><el-option label="域名" value="hostname" />
                  <el-option label="路径" value="path" /><el-option label="完整 URI" value="uri" />
                  <el-option label="请求方法" value="method" /><el-option label="User-Agent" value="user_agent" />
                  <el-option label="Referer" value="referer" /><el-option label="请求体" value="body" />
                </el-option-group>
                <el-option-group label="组合字段">
                  <el-option label="请求头（header:名）" value="header:" /><el-option label="查询参数（query:名）" value="query:" />
                  <el-option label="Cookie（cookie:名）" value="cookie:" />
                </el-option-group>
              </el-select>
              <el-select v-model="c.op" style="width:130px">
                <el-option label="等于" value="eq" /><el-option label="不等于" value="neq" />
                <el-option label="包含" value="contains" /><el-option label="不包含" value="not_contains" />
                <el-option label="前缀" value="prefix" /><el-option label="后缀" value="suffix" />
                <el-option label="正则" value="regex" /><el-option label="CIDR" value="cidr" />
                <el-option label="属于列表" value="in" />
              </el-select>
              <el-input v-model="c.value" placeholder="值" style="flex:1" class="km-mono" />
              <el-button link type="danger" @click="m.conditions.splice(i, 1)"><el-icon><Delete /></el-icon></el-button>
            </div>
            <el-button size="small" @click="m.conditions.push({ field: 'client_ip', op: 'contains', value: '' })">
              <el-icon><Plus /></el-icon>&nbsp;添加条件
            </el-button>
          </div>
        </el-form-item>
        <el-form-item label="备注"><el-input v-model="m.comment" /></el-form-item>
        <el-form-item label="记录日志">
          <div>
            <el-switch v-model="m.log_enabled" />
            <div class="km-dim" style="font-size:12px;margin-top:4px">开启后，命中该规则的请求写入攻击日志（含站点/来源/路径），可在规则列表点击「日志」查看命中详情；关闭时仅计数不记日志，动作照常执行。切换动作时自动按默认值联动：关闭检测类默认开启，其余默认关闭，可手动调整</div>
          </div>
        </el-form-item>
        <el-form-item label="启用"><el-switch v-model="m.enabled" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="mDlg = false">取消</el-button>
        <el-button type="primary" :loading="savingMatcher" @click="saveMatcher">保存并发布</el-button>
      </template>
    </el-dialog>

    <!-- IP 组新建/编辑弹窗(手动成员 或 订阅源) -->
    <el-dialog v-model="gDlg" :title="gEditName ? '编辑 IP 组 · ' + gEditName : '新建 IP 组'" width="560px">
      <el-form label-width="90px" label-position="left">
        <el-form-item label="组名">
          <el-input v-model="g.name" placeholder="如 grp-office-cn" class="km-mono" :disabled="!!gEditName" />
        </el-form-item>
        <el-form-item label="维护方式">
          <el-radio-group v-model="g.mode">
            <el-radio-button value="manual">手动维护</el-radio-button>
            <el-radio-button value="subscription">订阅源</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="g.mode === 'manual'" label="成员列表">
          <el-input v-model="g.members" type="textarea" :rows="7" class="km-mono" spellcheck="false"
                    placeholder="每行一个 IP 或 CIDR，如&#10;10.0.0.0/8&#10;192.168.1.5&#10;# 注释行会被忽略" />
        </el-form-item>
        <template v-if="g.mode === 'subscription'">
          <el-form-item label="来源类型">
            <el-radio-group v-model="g.srcType">
              <el-radio-button value="url">URL 订阅</el-radio-button>
              <el-radio-button value="file">本地文件</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item label="来源地址">
            <el-input v-model="g.source" :placeholder="g.srcType === 'url' ? 'https://example.com/ip-list.txt' : '/path/to/list.txt'" class="km-mono" />
          </el-form-item>
          <el-form-item label="刷新间隔">
            <el-input-number v-model="g.interval" :min="10" :max="1440" size="small" style="width:130px" />
            <span class="km-dim" style="margin-left:8px;font-size:12px">分钟（默认 60）</span>
          </el-form-item>
        </template>
      </el-form>
      <template #footer>
        <el-button @click="gDlg = false">取消</el-button>
        <el-button type="primary" :loading="gSaving" @click="saveGroup">保存并发布</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, applyNotice, can, del, post } from '../api'
import RuleExpert from '../components/RuleExpert.vue'

const router = useRouter()
const route = useRoute()

// 二级菜单：8 个策略模块页签（样式复用 Settings.vue 的 .km-set-nav 三件套）
const tabs = [
  { id: 'thresholds', name: 'CRS 异常评分阈值', icon: '🎚️' },
  { id: 'acl', name: '黑白名单管理', icon: '🛡️' },
  { id: 'ipgroups', name: 'IP 组管理', icon: '👥' },
  { id: 'matchers', name: '微引擎规则防护', icon: '🧩' },
  { id: 'penalty', name: '攻击惩罚', icon: '⛔' },
  { id: 'custom', name: '自定义规则', icon: '📜' },
  { id: 'engines', name: '检测分类与引擎', icon: '🧭' },
  { id: 'versions', name: '引擎与规则版本', icon: 'ℹ️' },
]
const tab = ref('thresholds')

// CRS 10 个检测类别：固定顺序与中英文标签，与 Sites 页站点级子面板、后端规则类别一致
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

const FIELD_LABELS = {
  client_ip: '来源 IP', hostname: '域名', path: '路径', uri: '完整 URI', method: '请求方法',
  user_agent: 'User-Agent', referer: 'Referer', body: '请求体',
  'header:': '请求头', 'query:': '查询参数', 'cookie:': 'Cookie'
}
const OP_LABELS = { eq: '=', neq: '≠', contains: '包含', not_contains: '不包含', prefix: '前缀',
  suffix: '后缀', regex: '正则', cidr: 'CIDR', in: '属于' }
function condLabel(c) {
  const f = FIELD_LABELS[c.field] || (c.field.startsWith('header:') ? '头 ' + c.field.slice(7)
    : c.field.startsWith('query:') ? '参数 ' + c.field.slice(6) : c.field.startsWith('cookie:') ? 'Cookie ' + c.field.slice(7) : c.field)
  return `${f} ${OP_LABELS[c.op] || c.op} ${c.value}`
}

const saving = ref(false)

// ---- 自定义规则列表（UI 结构化；存储仍是 policy.custom_rules 文本）----
const crSearch = ref('')
const crPage = ref(1)
const crPageSize = ref(10)
const crDlg = ref(false)
const crIdx = ref(-1)
const crForm = reactive({ msg: '', text: '' })
// 每条规则的命中数（24h，来自 /api/policy/custom-rules/hits，SQL 聚合）
const crHitMap = ref({})
const crHitLoading = ref(false)
// 勾选与导入导出
const crSelected = ref([])
const crFileInput = ref(null)

function onCrSelection(rows) { crSelected.value = rows }

function crNextIDFrom(usedSet) {
  for (let id = 100001; id <= 199999; id++) if (!usedSet.has(id)) return id
  return 100001
}

// 导出：可整体或仅选中；cmd=json（含状态，可回灌）/ cmd=seclang（纯文本，通用）
function crExportAs(cmd) {
  const list = (crSelected.value.length ? crSelected.value : crules.value)
  if (!list.length) return ElMessage.warning('没有可导出的规则')
  if (cmd === 'seclang') return crExportText(list)
  const payload = {
    format: 'kingmoat-custom-rules',
    version: 1,
    exported_at: new Date().toISOString(),
    rules: list.map(r => ({ id: r.id || 0, message: r.msg || '', disabled: !!r.disabled, rule: r.text })),
  }
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = 'kingmoat-custom-rules-' + new Date().toISOString().slice(0, 10) + '.json'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  setTimeout(() => URL.revokeObjectURL(a.href), 2000)
  ElMessage.success('已导出 ' + list.length + ' 条规则')
}

// 纯 SecLang 文本导出：逐块拼接，禁用规则保持 "# " 注释（其它引擎可直接使用）
function crExportText(list) {
  const head = [
    '# KingMoat WAF 自定义规则导出（SecLang / ModSecurity 兼容）',
    '# 导出时间: ' + new Date().toISOString(),
    '# 说明: 以 "# " 开头的规则为「已禁用」，在其它引擎导入时可按需去掉注释启用；',
    '#       规则 ID 段 100001-199999 为本产品控制台约定，其它引擎可自行调整。',
    '',
  ]
  const body = list.map(r => (r.disabled ? r.text.split('\n').map(l => '# ' + l).join('\n') : r.text))
  const text = head.join('\n') + body.join('\n\n') + '\n'
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
  const el = document.createElement('a')
  el.href = URL.createObjectURL(blob)
  el.download = 'kingmoat-custom-rules-' + new Date().toISOString().slice(0, 10) + '.txt'
  document.body.appendChild(el)
  el.click()
  document.body.removeChild(el)
  setTimeout(() => URL.revokeObjectURL(el.href), 2000)
  ElMessage.success('已导出 ' + list.length + ' 条规则（SecLang 文本）')
}

// 导入：JSON（本页导出格式或 {rules:[...]} / [...]）或原始 SecLang 文本
function crImport(ev) {
  const f = ev.target.files && ev.target.files[0]
  ev.target.value = ''
  if (!f) return
  if (f.size > 2 * 1024 * 1024) return ElMessage.error('导入文件超过 2MB')
  const reader = new FileReader()
  reader.onload = () => {
    try {
      mergeImported(String(reader.result || ''))
    } catch (e) {
      ElMessage.error('导入失败：' + (e.message || '文件格式无法解析'))
    }
  }
  reader.readAsText(f)
}

function mergeImported(raw) {
  let items = null
  const trimmed = String(raw || '').trim()
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    const doc = JSON.parse(trimmed)
    if (Array.isArray(doc)) items = doc
    else if (doc && Array.isArray(doc.rules)) items = doc.rules
    else throw new Error('JSON 里没有 rules 数组')
  }
  if (!items) {
    // 原始 SecLang 文本
    items = parseRuleBlocks(trimmed).map(r => ({ id: r.id, message: r.msg, disabled: r.disabled, rule: r.text }))
  }
  const lines = String(p.customRules || '').split('\n')
  const used = new Set(parseRuleBlocks(p.customRules).map(r => r.id).filter(Boolean))
  let added = 0
  let skipped = 0
  for (const it of items) {
    const text = String((typeof it === 'string' ? it : (it.rule || it.text || '')) || '').trim()
    if (!text) continue
    let id = Number((typeof it === 'object' && it.id) || 0)
    if (!id) {
      const m = text.match(/id\s*:\s*(\d+)/)
      id = m ? Number(m[1]) : 0
    }
    if (!id) id = crNextIDFrom(used)
    if (used.has(id)) { skipped++; continue }
    used.add(id)
    const disabled = !!(it && it.disabled)
    const block = text.split('\n').map(l => (disabled ? '# ' + l : l))
    if (String(lines.join('\n')).trim()) lines.push('')
    lines.push(...block)
    added++
  }
  p.customRules = lines.join('\n').replace(/\n{3,}/g, '\n\n')
  if (added) {
    ElMessage.success('已导入 ' + added + ' 条规则' + (skipped ? ('，跳过重复 ID ' + skipped + ' 条') : '') + '；记得点「保存并发布」')
  } else {
    ElMessage.warning(skipped ? ('全部为重复 ID（' + skipped + ' 条），未导入') : '文件里没有解析到规则')
  }
}

async function loadCrHits() {
  crHitLoading.value = true
  try {
    const d = await api('/api/policy/custom-rules/hits?hours=24')
    const m = {}
    ;(d.items || []).forEach(it => { m[it.id] = it.count })
    crHitMap.value = m
  } catch (e) {
    crHitMap.value = {}
  } finally {
    crHitLoading.value = false
  }
}

// SecRule 块解析：行尾反斜杠续行；`# km-disabled` 标记行表示该规则被禁用
// 解析任意 SecLang 文本为规则块（禁用规则为整块 "# " 注释）
function parseRuleBlocks(text) {
  const ls = String(text || '').split('\n')
  const out = []
  for (let i = 0; i < ls.length; i++) {
    // 启用：行首直接是 SecRule；禁用：整块被 "# " 注释掉（设备侧不会加载）
    const disabled = /^#\s+SecRule\s/i.test(ls[i])
    if (!disabled && !/^\s*SecRule\s/i.test(ls[i])) continue
    let j = i
    while (ls[j].trimEnd().endsWith('\\') && j + 1 < ls.length) j++
    const text = ls.slice(i, j + 1).join('\n')
    const idM = text.match(/id\s*:\s*(\d+)/)
    const msgM = text.match(/msg\s*:\s*(?:'([^']*)'|"([^"]*)")/)
    const plain = disabled ? text.split('\n').map(l => l.replace(/^#\s?/, '')).join('\n') : text
    const idM2 = plain.match(/id\s*:\s*(\d+)/)
    const msgM2 = plain.match(/msg\s*:\s*(?:'([^']*)'|"([^"]*)")/)
    out.push({
      start: i, end: j, marker: -1, text: plain,
      id: idM2 ? Number(idM2[1]) : 0,
      msg: msgM2 ? (msgM2[1] || msgM2[2] || '') : '',
      disabled,
      preview: plain.replace(/\s+/g, ' ').slice(0, 260),
    })
    i = j
  }
  return out
}

const crules = computed(() => parseRuleBlocks(p.customRules))
const crFiltered = computed(() => {
  const q = crSearch.value.trim().toLowerCase()
  if (!q) return crules.value
  return crules.value.filter(r => String(r.id).includes(q) || (r.msg || '').toLowerCase().includes(q) || (r.text || '').toLowerCase().includes(q))
})
const crPaged = computed(() => {
  const s = (crPage.value - 1) * crPageSize.value
  return crFiltered.value.slice(s, s + crPageSize.value)
})
watch([crSearch, crPageSize], () => { crPage.value = 1 })
watch(tab, v => { if (v === 'custom') loadCrHits() })

function crWrite(ls) {
  p.customRules = ls.join('\n').replace(/\n{3,}/g, '\n\n').replace(/^\n+|\n+$/g, '')
  ElMessage.info('已修改草稿，记得点「保存并发布」')
}

function crToggle(row) {
  const ls = String(p.customRules || '').split('\n')
  if (row.disabled) {
    // 启用：去掉行首 "# "
    for (let k = row.start; k <= row.end; k++) ls[k] = ls[k].replace(/^#\s?/, '')
  } else {
    // 禁用：整块逐行加 "# "（SecLang 注释，规则不会被加载）
    for (let k = row.start; k <= row.end; k++) ls[k] = '# ' + ls[k]
  }
  crWrite(ls)
}

function crRemove(row) {
  const ls = String(p.customRules || '').split('\n')
  ls.splice(row.start, row.end - row.start + 1)
  crWrite(ls)
}

function crNextID() {
  const used = new Set(crules.value.map(r => r.id))
  for (let id = 100001; id <= 199999; id++) if (!used.has(id)) return id
  return 100001
}

function crAdd() {
  crIdx.value = -1
  crForm.msg = ''
  crForm.text = 'SecRule REQUEST_URI "@rx ^/api/v1/exec" \\\n    "id:' + crNextID() + ',phase:1,deny,status:403,log,msg:\'请填写说明\'"'
  crDlg.value = true
}

function crEdit(row) {
  crIdx.value = crules.value.indexOf(row)
  crForm.msg = row.msg
  crForm.text = row.text
  crDlg.value = true
}

function crSave() {
  let text = String(crForm.text || '').trim()
  if (!text) return ElMessage.error('规则文本不能为空')
  const msg = String(crForm.msg || '').trim()
  if (msg) {
    if (/msg\s*:\s*(?:'[^']*'|"[^"]*")/i.test(text)) {
      text = text.replace(/msg\s*:\s*(?:'[^']*'|"[^"]*")/i, "msg:'" + msg.replace(/'/g, "\\'") + "'")
    } else {
      ElMessage.warning('规则里没有 msg 动作，描述不会写入规则')
    }
  }
  const ls = String(p.customRules || '').split('\n')
  const row = crules.value[crIdx.value]
  if (!row) {
    const head = ls.join('\n').trim()
    p.customRules = (head ? head + '\n\n' : '') + text
    ElMessage.info('已新增草稿，记得点「保存并发布」')
  } else {
    const newLines = text.split('\n').map(l => row.disabled ? ('# ' + l) : l)
    ls.splice(row.start, row.end - row.start + 1, ...newLines)
    p.customRules = ls.join('\n')
    ElMessage.info('已更新草稿，记得点「保存并发布」')
  }
  crDlg.value = false
}

function crLogs(row) {
  router.push({ path: '/logs', query: { rule: row.id ? ('rule-' + row.id) : '' } })
}

// ---- 规则测试命中（后端两趟编译：仅自定义规则 / CRS+自定义规则）----
const rt = reactive({ dlg: false, method: 'GET', path: '/', query: '', headers: '', body: '', testing: false, res: null, err: '' })
const rtHits = computed(() => {
  const pass = rt.res && rt.res.rules_only
  return ((pass && pass.matched) || []).filter(m => m.custom)
})

function openRt() {
  rt.dlg = true
  rt.err = ''
  rt.res = null
}

function rtHeaders() {
  const out = {}
  String(rt.headers || '').split('\n').forEach(line => {
    const i = line.indexOf(':')
    if (i <= 0) return
    const k = line.slice(0, i).trim()
    const v = line.slice(i + 1).trim()
    if (k) out[k] = v
  })
  return out
}

async function runRt() {
  rt.testing = true
  rt.err = ''
  rt.res = null
  try {
    rt.res = await post('/api/policy/custom-rules/test', {
      rules: p.customRules || '',
      method: rt.method,
      path: rt.path || '/',
      query: rt.query || '',
      headers: rtHeaders(),
      body: rt.body || '',
    })
  } catch (e) {
    rt.err = e.message || '测试失败'
  } finally {
    rt.testing = false
  }
}


// 旧版误报加白记录（exception 模式）：仅用于迁移检测，不再单独展示。
const legacyWhitelist = ref([])
const migrating = ref(false)
const migrationDismissed = ref(false)
const ipGroups = ref([])
const matchers = ref([])
const siteOptions = ref([])
const blTab = ref('black')
const rev = ref(0)
const version = ref('')
const engine = ref({})
const mDlg = ref(false)
const mEditIndex = ref(-1)
const mEditName = ref('')
const savingMatcher = ref(false)
const catsOpen = ref(false)

// 分类面板开合：整模块 coraza 已勾选时不可展开（互斥）
function toggleCats() {
  if (m.disable_stages.includes('coraza')) {
    ElMessage.info('已勾选「CRS 签名检测」整模块；如需按分类关闭，请先取消整模块勾选')
    return
  }
  catsOpen.value = !catsOpen.value
}

// 互斥联动：勾选整模块时自动清掉已勾的分类（两类并存保存会被拒绝，提前联动消除冲突态），
// 同时收起分类面板（避免面板卡在展开态、切换条反复弹误导提示）
function onStagesChange() {
  if (!m.disable_stages.includes('coraza')) return
  if (scopedCorazaCats(m.disable_stages).length) {
    m.disable_stages = m.disable_stages.filter(s => s.indexOf('coraza:') !== 0)
    catsOpen.value = false
    ElMessage.info('「CRS 签名检测」已包含全部分类，已自动取消分类勾选；如需按分类关闭请先取消整模块勾选')
  }
}
const m = reactive({ name: '', action: 'deny', logic: 'and', sites: [], enabled: true, log_enabled: false, comment: '', disable_stages: [], conditions: [{ field: 'client_ip', op: 'contains', value: '' }] })
const p = reactive({
  inbound: 5, outbound: 4,
  gBlack: [], gWhite: [],
  customRules: '',
  penalty_enabled: false, penalty_window: 600, penalty_threshold: 20, penalty_ban: 3600,
  penalty_action: 'deny', penalty_per_min: 10
})

// CRS 检测分类全局默认开关状态（policy.waf_categories；nil = 全部启用）
const wafCats = reactive({})

// 一键全部启用（全关会被 policy 层「waf_categories 不得为空」拒绝，不提供）
function setAllWafCats(on) {
  for (const x of CRS_CATEGORIES) wafCats[x.id] = on
}

// 站点级引擎启用统计(读当前配置聚合)
const totalSites = ref(0)
const engineStats = ref([])
function aggregateEngines(cfg) {
  const sites = cfg.sites || []
  totalSites.value = sites.length
  const count = fn => sites.filter(fn).length
  engineStats.value = [
    { name: '签名检测（CRS）', desc: 'Coraza + OWASP CRS 请求体检测', count: count(s => !s.waf || s.waf?.enabled !== false) },
    { name: '语义检测', desc: 'libinjection SQLi / XSS', count: count(s => s.security?.semantic?.enabled) },
    { name: 'BOT 识别', desc: '指纹分类观察 / 拦截 / 挑战', count: count(s => s.security?.bot_detect?.enabled) },
    { name: 'CC 限流', desc: '固定窗口频率限制', count: count(s => s.security?.ratelimit) },
    { name: 'GeoIP 封禁', desc: '国家黑白名单', count: count(s => s.security?.geo?.enabled) },
    { name: '人机验证', desc: '滑块验证码 + JS 质询', count: count(s => s.security?.captcha?.enabled) },
    { name: '响应脱敏', desc: '手机号 / 身份证 / 密钥', count: count(s => s.security?.resp_filter?.enabled) },
  ]
}

async function load() {
  const d = await api('/api/config')
  const c = d.config
  rev.value = d.revision
  siteOptions.value = [...new Set((c.sites || []).flatMap(s => s.domains || []))]
  p.inbound = c.policy?.inbound_threshold || 5
  p.outbound = c.policy?.outbound_threshold || 4
  p.gBlack = [...(c.policy?.global_acl?.blacklist || [])]
  p.gWhite = [...(c.policy?.global_acl?.whitelist || [])]
  p.customRules = c.policy?.custom_rules || ''
  p.penalty_enabled = !!c.policy?.penalty?.enabled
  p.penalty_window = c.policy?.penalty?.window_sec || 600
  p.penalty_threshold = c.policy?.penalty?.threshold || 20
  p.penalty_ban = c.policy?.penalty?.ban_sec || 3600
  p.penalty_action = c.policy?.penalty?.action || 'deny'
  p.penalty_per_min = c.policy?.penalty?.throttle_per_min || 10
  const wafCatCfg = c.policy?.waf_categories
  const activeCats = Array.isArray(wafCatCfg) ? wafCatCfg : CRS_CATEGORIES.map(x => x.id)
  for (const x of CRS_CATEGORIES) wafCats[x.id] = activeCats.includes(x.id)
  matchers.value = c.policy?.matchers || []
  aggregateEngines(c)
  try { legacyWhitelist.value = migrationDismissed.value ? [] : (await api('/api/policy/exceptions') || []) }
  catch (e) { legacyWhitelist.value = [] }
  try { ipGroups.value = await api('/api/ipgroups') } catch (e) { ipGroups.value = [] }
  try {
    const st = await api('/api/status')
    version.value = st.version || ''
    engine.value = st.engine || {}
  } catch (e) { /* version card optional */ }
  loadMatcherHits()
}

// ---- 微引擎规则命中计数（GET /api/policy/micro-rules/hits，进程内计数，重启归零）----
const matcherHits = ref({})
async function loadMatcherHits() {
  try {
    const d = await api('/api/policy/micro-rules/hits')
    const m = {}
    for (const it of (d.items || [])) m[it.rule] = it.count || 0
    matcherHits.value = m
  } catch (e) {
    matcherHits.value = {}
  }
}

// 跳转到攻击日志页并按规则标识过滤（deny 与开启日志的命中事件都携带 matcher/<名称>）
function gotoRuleLogs(rule) {
  router.push('/logs?rule=' + encodeURIComponent(rule))
}

// 表格内直接切换「记录日志」：读全量 config → 改对应规则 → publish；失败回滚开关状态。
// 按规则名定位（而非列表下标）：避免其他管理员并发变更列表后开关写错规则。
async function toggleMatcherLog(row) {
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.policy = cfg.policy || {}
    const list = cfg.policy.matchers || []
    const i = list.findIndex(x => x.name === row.name)
    if (i < 0) {
      ElMessage.error('规则 ' + row.name + ' 已被其他管理员修改，请刷新后重试')
      row.log_enabled = !row.log_enabled
      return
    }
    if (row.log_enabled) list[i].log_enabled = true
    else delete list[i].log_enabled
    const r = await post('/api/config/publish', { note: 'matcher log toggle: ' + row.name, config: cfg })
    applyNotice(r, row.log_enabled ? '已开启命中日志并热生效' : '已关闭命中日志并热生效')
    load()
  } catch (e) {
    ElMessage.error('发布失败：' + e.message)
    row.log_enabled = !row.log_enabled
  }
}

// ---- 列表分页（默认 10，可选 10/20/50/100）----
const blPage = ref(1)
const blPageSize = ref(10)
const blList = computed(() => (blTab.value === 'black' ? p.gBlack : p.gWhite))
const pagedBL = computed(() => {
  const start = (blPage.value - 1) * blPageSize.value
  return blList.value.slice(start, start + blPageSize.value).map((v, k) => ({ v, i: start + k }))
})
watch(blTab, () => { blPage.value = 1 })
function addBlankBL() {
  blList.value.push('')
  blPage.value = Math.max(1, Math.ceil(blList.value.length / blPageSize.value))
}

const grpPage = ref(1)
const grpPageSize = ref(10)
const pagedGroups = computed(() => {
  const start = (grpPage.value - 1) * grpPageSize.value
  return ipGroups.value.slice(start, start + grpPageSize.value)
})

const mPage = ref(1)
const mPageSize = ref(10)
// 微引擎规则条件查询：名称/路径（条件值或规则名）/站点筛选
const mFilterName = ref('')
const mFilterPath = ref('')
const mFilterSite = ref('__all__')
const filteredMatchers = computed(() => {
  const name = (mFilterName.value || '').trim().toLowerCase()
  const path = (mFilterPath.value || '').trim().toLowerCase()
  const site = mFilterSite.value && mFilterSite.value !== '__all__' ? mFilterSite.value.toLowerCase() : ''
  return matchers.value.filter(m => {
    if (name && !String(m.name || '').toLowerCase().includes(name)) return false
    if (path) {
      const condHit = (m.conditions || []).some(c => ['path', 'uri'].includes(c.field) && String(c.value || '').toLowerCase().includes(path))
      if (!condHit && !String(m.name || '').toLowerCase().includes(path)) return false
    }
    if (site) {
      const sites = Array.isArray(m.sites) ? m.sites : []
      // 空 sites = 全部站点生效，按站点筛选时也应命中
      if (sites.length && !sites.some(s => String(s).toLowerCase() === site)) return false
    }
    return true
  })
})
function resetMatcherFilters() {
  mFilterName.value = ''
  mFilterPath.value = ''
  mFilterSite.value = '__all__'
}
watch([mFilterName, mFilterPath, mFilterSite], () => { mPage.value = 1 })
const pagedMatchers = computed(() => {
  const start = (mPage.value - 1) * mPageSize.value
  return filteredMatchers.value.slice(start, start + mPageSize.value)
})

// 误报加白来源的微引擎规则：按 Name/Comment 前缀识别（与后端命名约定一致）
function isWhitelistRule(row) {
  return (row.name || '').startsWith('误报加白') || (row.comment || '').startsWith('误报加白')
}

// 一键迁移：逐条转换为 POST /api/policy/whitelist（幂等，重复迁移安全），
// 全部成功后按下标删除旧记录——先删大下标后删小下标，避免删険位移。
async function migrateWhitelist() {
  migrating.value = true
  const items = [...legacyWhitelist.value]
  try {
    for (const it of items) {
      await post('/api/policy/whitelist', {
        site: it.site || '', path: it.path, prefix: !!it.prefix, comment: it.comment || ''
      })
    }
    for (let i = items.length - 1; i >= 0; i--) {
      await del('/api/policy/exceptions/' + i)
    }
    ElMessage.success('已迁移 ' + items.length + ' 条旧版加白记录为微引擎放行规则')
    legacyWhitelist.value = []
    load()
  } catch (e) {
    ElMessage.error('迁移失败：' + e.message)
    load()
  } finally {
    migrating.value = false
  }
}

function dismissMigration() {
  migrationDismissed.value = true
  legacyWhitelist.value = []
}

async function refreshGroup(name) {
  try {
    await post('/api/ipgroups/' + encodeURIComponent(name) + '/refresh')
    ElMessage.success('已刷新')
    load()
  } catch (e) { ElMessage.error(e.message) }
}

// ---- IP 组新建/编辑/删除(手动成员 或 订阅) ----
const gDlg = ref(false)
const gSaving = ref(false)
const gEditName = ref('')
const g = reactive({ name: '', mode: 'manual', members: '', srcType: 'url', source: '', interval: 60 })

function openGroup(idx) {
  gEditName.value = ''
  if (idx >= 0 && ipGroups.value[idx]) {
    const row = ipGroups.value[idx]
    gEditName.value = row.name
    g.name = row.name
    if (row.type === 'manual') {
      g.mode = 'manual'
      g.members = (row.members || []).join('\n')
    } else {
      g.mode = 'subscription'
      g.members = ''
      g.srcType = row.url ? 'url' : 'file'
      g.source = row.url || row.file || ''
      g.interval = row.interval_min || 60
    }
  } else {
    Object.assign(g, { name: '', mode: 'manual', members: '', srcType: 'url', source: '', interval: 60 })
  }
  gDlg.value = true
}

async function saveGroup() {
  const name = (g.name || '').trim()
  if (!name) return ElMessage.error('请填写组名')
  const entry = { name }
  if (g.mode === 'manual') {
    const members = g.members.split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#'))
    if (!members.length) return ElMessage.error('手动组至少需要一个成员(IP/CIDR)')
    entry.members = members
  } else {
    if (!g.source.trim()) return ElMessage.error('请填写订阅来源')
    if (g.srcType === 'url') entry.url = g.source.trim()
    else entry.file = g.source.trim()
    entry.interval_min = g.interval
  }
  gSaving.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.ip_groups = cfg.ip_groups || []
    const at = cfg.ip_groups.findIndex(x => x.name === name)
    if (gEditName.value && at >= 0) cfg.ip_groups[at] = entry
    else if (at >= 0) cfg.ip_groups[at] = entry
    else cfg.ip_groups.push(entry)
    const r = await post('/api/config/publish', { note: 'ip group: ' + name, config: cfg })
    applyNotice(r, 'IP 组已发布并热生效（版本 ' + r.revision + '）')
    gDlg.value = false
    load()
  } catch (e) {
    ElMessage.error('发布失败：' + e.message)
  } finally {
    gSaving.value = false
  }
}

async function delGroup(name) {
  try {
    await ElMessageBox.confirm('删除 IP 组 ' + name + '？引用它的 ACL 条目将失效。', '确认', { type: 'warning' })
  } catch (e) { return }
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.ip_groups = (cfg.ip_groups || []).filter(x => x.name !== name)
    const r = await post('/api/config/publish', { note: 'ip group removed: ' + name, config: cfg })
    applyNotice(r, '已删除并热生效')
    load()
  } catch (e) { ElMessage.error(e.message) }
}

// ---- 按 tab 粒度的保存函数：读全量 config → 只改本块字段 → publish，
// spread 保留其余块字段，未展示块字段不丢 ----
// apply 三态提示已抽为共享 applyNotice（../api），各发布入口统一使用

async function publish(cfg, note) {
  const r = await post('/api/config/publish', { note, config: cfg })
  applyNotice(r, '策略已发布并热生效（版本 ' + r.revision + '）')
  await load()
}

async function saveThresholds() {
  saving.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.policy = { ...(cfg.policy || {}), inbound_threshold: p.inbound, outbound_threshold: p.outbound }
    await publish(cfg, 'policy: crs thresholds')
  } catch (e) {
    ElMessage.error('发布失败（旧配置保持生效）：' + e.message)
  } finally {
    saving.value = false
  }
}

async function saveWafCategories() {
  const enabled = CRS_CATEGORIES.map(x => x.id).filter(id => wafCats[id])
  if (!enabled.length) return ElMessage.error('至少启用一个分类')
  saving.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.policy = { ...(cfg.policy || {}) }
    // 全部启用 = 恢复默认，不写 waf_categories 字段（后端字段缺省即全类别装载）
    if (enabled.length === CRS_CATEGORIES.length) delete cfg.policy.waf_categories
    else cfg.policy.waf_categories = enabled
    await publish(cfg, 'policy: waf categories default')
  } catch (e) {
    ElMessage.error('发布失败（旧配置保持生效）：' + e.message)
  } finally {
    saving.value = false
  }
}

async function saveACL() {
  saving.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    const acl = { blacklist: p.gBlack.filter(Boolean), whitelist: p.gWhite.filter(Boolean) }
    cfg.policy = { ...(cfg.policy || {}) }
    if (acl.blacklist.length || acl.whitelist.length) cfg.policy.global_acl = acl
    else delete cfg.policy.global_acl
    await publish(cfg, 'policy: global acl')
  } catch (e) {
    ElMessage.error('发布失败（旧配置保持生效）：' + e.message)
  } finally {
    saving.value = false
  }
}

async function savePenalty() {
  saving.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.policy = { ...(cfg.policy || {}) }
    if (p.penalty_enabled) {
      cfg.policy.penalty = {
        enabled: true,
        window_sec: p.penalty_window,
        threshold: p.penalty_threshold,
        ban_sec: p.penalty_ban,
        action: p.penalty_action,
        throttle_per_min: p.penalty_per_min
      }
    } else {
      delete cfg.policy.penalty
    }
    await publish(cfg, 'policy: penalty')
  } catch (e) {
    ElMessage.error('发布失败（旧配置保持生效）：' + e.message)
  } finally {
    saving.value = false
  }
}

async function saveCustom() {
  saving.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.policy = { ...(cfg.policy || {}), custom_rules: p.customRules }
    if (!p.customRules) delete cfg.policy.custom_rules
    await publish(cfg, 'policy: custom rules')
    await loadCrHits()
  } catch (e) {
    ElMessage.error('发布失败（旧配置保持生效）：' + e.message)
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  // 深链接：Settings 等页面通过 /policy?tab=custom 直达指定模块
  const q = route.query.tab
  if (q && tabs.some(t => t.id === String(q))) tab.value = String(q)
  load()
  if (tab.value === 'custom') loadCrHits()
})

function openMatcher(i) {
  mEditIndex.value = i
  // 记录打开时的规则名：保存时按名字回写，避免并发变更后按下标写错规则
  mEditName.value = i >= 0 ? (matchers.value[i] ? matchers.value[i].name : '') : ''
  if (i >= 0) {
    const r = matchers.value[i]
    // 先铺默认值再覆盖规则字段：规则缺失的字段（如未开启过 log_enabled）不残留上一次编辑的值
    Object.assign(m, matcherDefaults(), JSON.parse(JSON.stringify(r)))
    if (!m.conditions.length) m.conditions.push({ field: 'client_ip', op: 'contains', value: '' })
  } else {
    Object.assign(m, matcherDefaults())
  }
  // 回显分类子选择：disable_stages 携带 coraza:<分类> 时展开子选项区
  catsOpen.value = scopedCorazaCats(m.disable_stages).length > 0
  mDlg.value = true
}

function matcherDefaults() {
  return { name: '', action: 'deny', logic: 'and', sites: [], enabled: true, log_enabled: false, comment: '', disable_stages: [],
    conditions: [{ field: 'client_ip', op: 'contains', value: '' }] }
}

// 切换动作时按默认值联动「记录日志」：关闭检测类默认开，其余默认关（用户可再手动调整）
function onMatcherActionChange(a) {
  m.log_enabled = a === 'disable'
}

// disable_stages 中的 coraza:<分类> 复合值（分类粒度关闭 CRS）
function scopedCorazaCats(stages) {
  return (stages || []).filter(s => typeof s === 'string' && s.startsWith('coraza:'))
}

// 与后端校验规则一致：disable 至少勾一项；分类必须合法；「CRS 签名检测」与分类子项不得混用（需拆成两条规则）
function validateDisableStages() {
  const stages = m.disable_stages || []
  if (!stages.length) return '至少勾选一个检测模块或 CRS 分类'
  const scoped = scopedCorazaCats(stages)
  for (const s of scoped) {
    if (!CRS_CATEGORIES.some(c => 'coraza:' + c.id === s)) return '未知的 CRS 分类：' + s
  }
  if (stages.includes('coraza') && scoped.length) {
    return '「CRS 签名检测」与其分类子项不能同时勾选：整段关闭请只勾「CRS 签名检测」，按分类关闭请勾选子项；两者并存请拆成两条规则'
  }
  return ''
}

async function saveMatcher() {
  if (!m.name.trim()) return ElMessage.error('请填写规则名称')
  if (!m.conditions.length) return ElMessage.error('至少一个条件')
  if (m.action === 'disable') {
    const dsErr = validateDisableStages()
    if (dsErr) return ElMessage.error(dsErr)
  }
  // 规则名必须唯一：重名会让按名回写/命中计数混淆（findIndex 只命中首个）。
  // 查重基于刚拉取的服务端配置（并发新增的同名规则一并拦下），比较与落库
  // 统一用 trim 后的名字（与服务端校验同口径，空白变体不再绕过查重）
  const newName = m.name.trim()
  const d = await api('/api/config')
  const cfg = d.config
  cfg.policy = cfg.policy || {}
  cfg.policy.matchers = cfg.policy.matchers || []
  const norm = n => String(n || '').trim()
  const editing = mEditIndex.value >= 0 ? norm(mEditName.value) : null
  const dupIdx = cfg.policy.matchers.findIndex(x => norm(x.name) === newName && norm(x.name) !== editing)
  if (dupIdx >= 0) return ElMessage.error('规则名「' + newName + '」已存在，请换一个名称')
  const rule = JSON.parse(JSON.stringify(m))
  rule.name = newName
  rule.logic = rule.logic || 'and'
  if (!rule.log_enabled) delete rule.log_enabled
  if (rule.action !== 'disable' || !Array.isArray(rule.disable_stages) || !rule.disable_stages.length) delete rule.disable_stages
  if (mEditIndex.value >= 0) {
    // 按打开时的规则名回写（并发安全）：规则已被删除时中止，避免静默变为新增
    const at = cfg.policy.matchers.findIndex(x => x.name === mEditName.value)
    if (at < 0) {
      return ElMessage.error('规则 ' + (mEditName.value || m.name) + ' 已被其他管理员删除，请刷新列表后重试')
    }
    cfg.policy.matchers[at] = rule
  } else cfg.policy.matchers.push(rule)
  try {
    const r = await post('/api/config/publish', { note: 'matcher rule: ' + rule.name, config: cfg })
    applyNotice(r, '规则已发布并热生效（版本 ' + r.revision + '）')
    mDlg.value = false
    load()
  } catch (e) {
    ElMessage.error('发布失败：' + e.message)
  }
}

async function removeMatcher(row) {
  const d = await api('/api/config')
  const cfg = d.config
  cfg.policy = cfg.policy || {}
  // 按规则名定位（并发安全）：其他管理员已删除同名规则时提示刷新
  const i = (cfg.policy.matchers || []).findIndex(x => x.name === row.name)
  if (i < 0) return ElMessage.error('规则 ' + row.name + ' 已被其他管理员删除，请刷新列表')
  cfg.policy.matchers.splice(i, 1)
  try {
    const r = await post('/api/config/publish', { note: 'matcher removed: ' + row.name, config: cfg })
    applyNotice(r, '已删除并热生效')
    load()
  } catch (e) { ElMessage.error(e.message) }
}
</script>

<style scoped>
.ver-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.ver-item .ver-k { font-size: 11px; color: var(--km-txt-3); }
.ver-item .ver-v { font-size: 15px; font-weight: 700; color: var(--km-txt); margin: 2px 0; }
.ver-item .ver-s { font-size: 11px; color: var(--km-txt-3); }
.km-config-row .name { font-size: 13px; font-weight: 600; color: var(--km-txt); }
.km-config-row .desc { font-size: 11.5px; color: var(--km-txt-3); }
.km-config-row .right { margin-left: auto; display: flex; align-items: center; gap: 10px; }
.km-config-row .val { font-size: 12px; color: var(--km-txt-2); }
.cat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 12px; }
.cat-item { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 7px 12px; border-radius: 8px; background: var(--km-panel-2); border: 1px solid var(--km-line-soft); }
.cat-item .cat-label { font-size: 12.5px; color: var(--km-txt-2); }
.cat-item.cat-off { opacity: .55; }
/* 微引擎弹窗：关闭模块复选卡 + 分类面板 */
.mod-row { display: flex; flex-wrap: wrap; gap: 8px; }
.mod-row :deep(.el-checkbox.el-checkbox--small.is-bordered) { margin-right: 0; border-radius: 6px; height: 32px; padding: 0 12px; }
.cats-toggle { display: inline-flex; align-items: center; gap: 6px; margin-top: 10px; padding: 5px 12px; border: 1px solid var(--km-line-soft); border-radius: 6px; cursor: pointer; font-size: 12.5px; color: var(--km-txt-2); background: var(--km-panel-2); user-select: none; transition: border-color .15s, color .15s; }
.cats-toggle:hover { border-color: var(--km-soft-blue); color: var(--km-soft-blue); }
.cats-toggle.cats-on { border-color: var(--km-soft-blue); color: var(--km-soft-blue); background: transparent; }
.cats-toggle.cats-disabled { opacity: .5; cursor: not-allowed; }
.cats-toggle .cats-sub { font-size: 11px; color: var(--km-txt-3); }
.cats-toggle .cats-arrow { font-size: 12px; transition: transform .15s; }
.cats-toggle .cats-arrow.open { transform: rotate(90deg); }
.cats-panel { margin-top: 10px; padding: 12px 14px; background: var(--km-panel-2); border: 1px solid var(--km-line-soft); border-radius: 8px; }
.cats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 14px; }
.cats-grid :deep(.el-checkbox.el-checkbox--small.is-bordered) { margin-right: 0; width: 100%; border-radius: 6px; height: 30px; padding: 0 10px; }
.eng-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.eng-item { border: 1px solid var(--km-line-soft); border-radius: 8px; padding: 9px 11px; background: var(--km-panel-2); transition: border-color .15s, opacity .15s; }
.eng-item:hover { border-color: var(--km-soft-blue); }
.eng-item.eng-off { opacity: .55; }
.eng-item .eng-head { display: flex; justify-content: space-between; align-items: center; }
.eng-item .eng-name { font-size: 12.5px; font-weight: 600; color: var(--km-txt); }
.eng-item .eng-count { font-size: 11px; color: var(--km-txt-3); }
.eng-item .eng-count.eng-on { color: var(--km-soft-blue); font-weight: 700; }
.eng-item .eng-desc { font-size: 11px; color: var(--km-txt-3); margin: 2px 0 7px; }
</style>
