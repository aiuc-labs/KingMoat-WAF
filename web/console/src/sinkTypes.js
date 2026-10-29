// 外发 sink 后端类型 → 控制台显示名（单一来源）：
// OutboundProbeResult（探测结果标题）与 Settings（复用提示的生效类型）共用
export const SINK_TYPE_LABELS = {
  elasticsearch: 'Elasticsearch', clickhouse: 'ClickHouse', loki: 'Loki',
  s3: 'S3 对象存储', syslog: 'Syslog', kafka: 'Kafka',
}
export const sinkTypeLabel = (t) => SINK_TYPE_LABELS[t] || t
