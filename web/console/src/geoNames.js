// ISO 3166-1 alpha-2 → 简体中文名共享映射（单一定义源）。
// Dashboard（TOP5/攻击IP/报表导出）、Logs（来源地区）、Sites（防护概览卡）统一从这里取显示文案。
//
// 与后端契约对齐（internal/geoip/geoip.go LookupCountry + internal/api/geo_stats.go）：
// - 攻击日志事件字段 geo_country 为 ISO 两字母码，空串是唯一「无国家」哨兵
//   （私网/回环/链路本地/CGNAT、公网但库无记录、解析失败、内置库缺失）；
//   历史事件 raw JSON 无该键（undefined），同样按空串处理。
// - 本地/私网口径 = geoip.isLocalOrigin：RFC1918、回环、链路本地（169.254/16 与 fe80::/10）、
//   CGNAT 100.64.0.0/10、IPv6 ULA fc00::/7。isLocalOriginIP 与其逐条对齐，勿单方面增删。
// - /api/stats/geo 聚合结果中私网来源已由后端并入中文标签「本地局域网」（非两字母码，
//   geoCountryName 原样透传）。

export const LOCAL_LABEL = '本地局域网'
export const UNKNOWN_LABEL = '未知地区'

// 全量 ISO 3166-1 alpha-2 官方分配码（249 项）+ DB-IP 可能返回的 user-assigned 码
// （XK 科索沃、AC 阿森松）+ 常见遗留/特殊码（A1/A2/AP/AN/EU/CS/SU/UK/QO）。
export const GEO_NAMES = {
  AD: '安道尔', AE: '阿联酋', AF: '阿富汗', AG: '安提瓜和巴布达', AI: '安圭拉',
  AL: '阿尔巴尼亚', AM: '亚美尼亚', AO: '安哥拉', AQ: '南极洲', AR: '阿根廷',
  AS: '美属萨摩亚', AT: '奥地利', AU: '澳大利亚', AW: '阿鲁巴', AX: '奥兰群岛',
  AZ: '阿塞拜疆',
  BA: '波黑', BB: '巴巴多斯', BD: '孟加拉国', BE: '比利时', BF: '布基纳法索',
  BG: '保加利亚', BH: '巴林', BI: '布隆迪', BJ: '贝宁', BL: '圣巴泰勒米',
  BM: '百慕大', BN: '文莱', BO: '玻利维亚', BQ: '荷属加勒比区', BR: '巴西',
  BS: '巴哈马', BT: '不丹', BV: '布韦岛', BW: '博茨瓦纳', BY: '白俄罗斯',
  BZ: '伯利兹',
  CA: '加拿大', CC: '科科斯（基林）群岛', CD: '刚果（金）', CF: '中非共和国',
  CG: '刚果（布）', CH: '瑞士', CI: '科特迪瓦', CK: '库克群岛', CL: '智利',
  CM: '喀麦隆', CN: '中国', CO: '哥伦比亚', CR: '哥斯达黎加', CU: '古巴',
  CV: '佛得角', CW: '库拉索', CX: '圣诞岛', CY: '塞浦路斯', CZ: '捷克',
  DE: '德国', DJ: '吉布提', DK: '丹麦', DM: '多米尼克', DO: '多米尼加共和国',
  DZ: '阿尔及利亚',
  EC: '厄瓜多尔', EE: '爱沙尼亚', EG: '埃及', EH: '西撒哈拉', ER: '厄立特里亚',
  ES: '西班牙', ET: '埃塞俄比亚',
  FI: '芬兰', FJ: '斐济', FK: '福克兰群岛（马尔维纳斯）', FM: '密克罗尼西亚联邦',
  FO: '法罗群岛', FR: '法国',
  GA: '加蓬', GB: '英国', GD: '格林纳达', GE: '格鲁吉亚', GF: '法属圭亚那',
  GG: '根西岛', GH: '加纳', GI: '直布罗陀', GL: '格陵兰', GM: '冈比亚',
  GN: '几内亚', GP: '瓜德罗普', GQ: '赤道几内亚', GR: '希腊',
  GS: '南乔治亚和南桑威奇群岛', GT: '危地马拉', GU: '关岛', GW: '几内亚比绍',
  GY: '圭亚那',
  HK: '中国香港', HM: '赫德岛和麦克唐纳群岛', HN: '洪都拉斯', HR: '克罗地亚',
  HT: '海地', HU: '匈牙利',
  ID: '印度尼西亚', IE: '爱尔兰', IL: '以色列', IM: '马恩岛', IN: '印度',
  IO: '英属印度洋领地', IQ: '伊拉克', IR: '伊朗', IS: '冰岛', IT: '意大利',
  JE: '泽西岛', JM: '牙买加', JO: '约旦', JP: '日本',
  KE: '肯尼亚', KG: '吉尔吉斯斯坦', KH: '柬埔寨', KI: '基里巴斯', KM: '科摩罗',
  KN: '圣基茨和尼维斯', KP: '朝鲜', KR: '韩国', KW: '科威特', KY: '开曼群岛',
  KZ: '哈萨克斯坦',
  LA: '老挝', LB: '黎巴嫩', LC: '圣卢西亚', LI: '列支敦士登', LK: '斯里兰卡',
  LR: '利比里亚', LS: '莱索托', LT: '立陶宛', LU: '卢森堡', LV: '拉脱维亚',
  LY: '利比亚',
  MA: '摩洛哥', MC: '摩纳哥', MD: '摩尔多瓦', ME: '黑山', MF: '法属圣马丁',
  MG: '马达加斯加', MH: '马绍尔群岛', MK: '北马其顿', ML: '马里', MM: '缅甸',
  MN: '蒙古', MO: '中国澳门', MP: '北马里亚纳群岛', MQ: '马提尼克',
  MR: '毛里塔尼亚', MS: '蒙特塞拉特', MT: '马耳他', MU: '毛里求斯',
  MV: '马尔代夫', MW: '马拉维', MX: '墨西哥', MY: '马来西亚', MZ: '莫桑比克',
  NA: '纳米比亚', NC: '新喀里多尼亚', NE: '尼日尔', NF: '诺福克岛',
  NG: '尼日利亚', NI: '尼加拉瓜', NL: '荷兰', NO: '挪威', NP: '尼泊尔',
  NR: '瑙鲁', NU: '纽埃', NZ: '新西兰',
  OM: '阿曼',
  PA: '巴拿马', PE: '秘鲁', PF: '法属波利尼西亚', PG: '巴布亚新几内亚',
  PH: '菲律宾', PK: '巴基斯坦', PL: '波兰', PM: '圣皮埃尔和密克隆',
  PN: '皮特凯恩群岛', PR: '波多黎各', PS: '巴勒斯坦', PT: '葡萄牙',
  PW: '帕劳', PY: '巴拉圭',
  QA: '卡塔尔',
  RE: '留尼汪', RO: '罗马尼亚', RS: '塞尔维亚', RU: '俄罗斯', RW: '卢旺达',
  SA: '沙特阿拉伯', SB: '所罗门群岛', SC: '塞舌尔', SD: '苏丹', SE: '瑞典',
  SG: '新加坡', SH: '圣赫勒拿', SI: '斯洛文尼亚', SJ: '斯瓦尔巴和扬马延',
  SK: '斯洛伐克', SL: '塞拉利昂', SM: '圣马力诺', SN: '塞内加尔', SO: '索马里',
  SR: '苏里南', SS: '南苏丹', ST: '圣多美和普林西比', SV: '萨尔瓦多',
  SX: '荷属圣马丁', SY: '叙利亚', SZ: '斯威士兰',
  TC: '特克斯和凯科斯群岛', TD: '乍得', TF: '法属南部领地', TG: '多哥',
  TH: '泰国', TJ: '塔吉克斯坦', TK: '托克劳', TL: '东帝汶', TM: '土库曼斯坦',
  TN: '突尼斯', TO: '汤加', TR: '土耳其', TT: '特立尼达和多巴哥', TV: '图瓦卢',
  TW: '中国台湾', TZ: '坦桑尼亚',
  UA: '乌克兰', UG: '乌干达', UM: '美国本土外小岛屿', US: '美国', UY: '乌拉圭',
  UZ: '乌兹别克斯坦',
  VA: '梵蒂冈', VC: '圣文森特和格林纳丁斯', VE: '委内瑞拉', VG: '英属维尔京群岛',
  VI: '美属维尔京群岛', VN: '越南', VU: '瓦努阿图',
  WF: '瓦利斯和富图纳', WS: '萨摩亚',
  YE: '也门', YT: '马约特',
  ZA: '南非', ZM: '赞比亚', ZW: '津巴布韦',
  XK: '科索沃', AC: '阿森松岛',
  A1: '匿名代理', A2: '卫星网络', AP: '亚太地区', AN: '荷属安的列斯',
  EU: '欧盟', CS: '塞尔维亚和黑山', SU: '苏联', UK: '英国', QO: '大洋洲其他地区',
}

const TWO_LETTER = /^[A-Z]{2}$/
const V4_SEGMENT = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/

// 单码显示：两字母码 → 中文名；库可能返回但映射未收录的码 → 「未知地区(XX)」
// （内联保留原始码，便于对照库数据排障）；非两字母值（如后端聚合标签）原样透传。
export function geoCountryName(cc) {
  const code = String(cc ?? '').trim().toUpperCase()
  if (!code) return UNKNOWN_LABEL
  if (GEO_NAMES[code]) return GEO_NAMES[code]
  if (TWO_LETTER.test(code)) return `${UNKNOWN_LABEL}(${code})`
  return code
}

// 双参显示（后端约定）：cc 非空按码显示；cc 为空时由 IP 分流——
// 私网/回环/链路本地/CGNAT → 「本地局域网」，其余（含解析失败/IP 为空）→ 「未知地区」。
// 老数据 raw JSON 无 geo_country 键时 cc 为 undefined，走同一兜底。
export function geoDisplayName(cc, ip) {
  const code = String(cc ?? '').trim().toUpperCase()
  if (code) return geoCountryName(code)
  return isLocalOriginIP(ip) ? LOCAL_LABEL : UNKNOWN_LABEL
}

// 私网/回环/保留判定，逐条对齐后端 geoip.isLocalOrigin：
// IsPrivate（RFC1918 10/8、172.16/12、192.168/16 + IPv6 ULA fc00::/7）、
// IsLoopback（127/8、::1）、IsLinkLocalUnicast（169.254/16、fe80::/10）、
// CGNAT 100.64.0.0/10。IPv4 前导零与含 zone（fe80::1%eth0）一律不认，
// 与 Go net.ParseIP 的拒绝行为一致，避免与后端口径分叉。
export function isLocalOriginIP(ip) {
  if (typeof ip !== 'string') return false
  const s = ip.trim()
  if (!s) return false
  const mapped = s.match(/^::ffff:(\S+)$/i)
  if (mapped) return isLocalIPv4(mapped[1])
  if (s.includes(':')) return isLocalIPv6(s)
  if (s.includes('.')) return isLocalIPv4(s)
  return false
}

function isLocalIPv4(s) {
  const p = s.split('.')
  if (p.length !== 4 || !p.every(x => V4_SEGMENT.test(x))) return false
  const a = Number(p[0])
  const b = Number(p[1])
  if (a === 10 || a === 127) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 169 && b === 254) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  return false
}

function isLocalIPv6(s) {
  const g = expandIPv6(s)
  if (!g) return false
  if (g[0] >= 0xfc00 && g[0] <= 0xfdff) return true
  if (g[0] === 0xfe80 || (g[0] > 0xfe80 && g[0] <= 0xfebf)) return true
  if (g.slice(0, 7).every(x => x === 0) && g[7] === 1) return true
  return false
}

// 展开 IPv6 为 8 个 16 位组（支持 :: 压缩与末段 IPv4 形式）；非法输入返回 null。
function expandIPv6(s) {
  if (!/^[0-9A-Fa-f:.]+$/.test(s)) return null
  const parts = s.split('::')
  if (parts.length > 2) return null
  const head = parseV6Groups(parts[0])
  if (!head) return null
  const tail = parts.length === 2 ? parseV6Groups(parts[1]) : []
  if (!tail) return null
  const total = head.length + tail.length
  if (parts.length === 2) {
    const fill = 8 - total
    if (fill < 0) return null
    return head.concat(new Array(fill).fill(0), tail)
  }
  return total === 8 ? head : null
}

function parseV6Groups(str) {
  if (!str) return []
  const segs = str.split(':')
  const out = []
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i]
    if (seg.includes('.')) {
      if (i !== segs.length - 1) return null
      const o = seg.split('.')
      if (o.length !== 4 || !o.every(x => V4_SEGMENT.test(x))) return null
      out.push(((Number(o[0]) << 8) | Number(o[1])) & 0xffff, ((Number(o[2]) << 8) | Number(o[3])) & 0xffff)
    } else {
      if (!/^[0-9A-Fa-f]{1,4}$/.test(seg)) return null
      out.push(parseInt(seg, 16))
    }
  }
  return out
}
