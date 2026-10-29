// Prometheus text exposition (format version 0.0.4) rendered directly from
// the in-process atomic counters and gauges - no Prometheus client
// dependency. Served by the optional /metrics endpoint behind console auth
// (config.metrics.enabled).
package metrics

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
)

// escapeLabel applies the exposition-format escaping for label values
// (backslash, double quote, newline).
func escapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

// escapeHelp applies the exposition-format escaping for HELP strings.
func escapeHelp(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

// writeGauge emits a single-sample gauge family.
func writeGauge(b *strings.Builder, name, help string, v float64) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(escapeHelp(help))
	b.WriteString("\n# TYPE ")
	b.WriteString(name)
	b.WriteString(" gauge\n")
	fmt.Fprintf(b, "%s %s\n", name, formatValue(v))
}

func formatValue(v float64) string {
	return fmt.Sprintf("%v", v)
}

// writeCounterLabeled emits a counter family from a live counterVec; every
// queued label key is split on the internal \x00 separator and mapped onto
// labelNames (missing labels render empty).
func writeCounterLabeled(b *strings.Builder, name, help string, c *counterVec, labelNames []string) {
	writeCounterLabeledSnapshot(b, name, help, c.Snapshot(), labelNames)
}

// writeCounterLabeledSnapshot emits a counter family from a pre-assembled
// label-key snapshot (the site-bytes family renders the persisted baseline
// merged with the live counters so the value stays monotonic across
// restarts).
func writeCounterLabeledSnapshot(b *strings.Builder, name, help string, snap map[string]uint64, labelNames []string) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(escapeHelp(help))
	b.WriteString("\n# TYPE ")
	b.WriteString(name)
	b.WriteString(" counter\n")
	if len(snap) == 0 {
		fmt.Fprintf(b, "%s 0\n", name)
		return
	}
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts := strings.Split(k, "\x00")
		var pairs []string
		for i, ln := range labelNames {
			v := ""
			if i < len(parts) {
				v = parts[i]
			}
			pairs = append(pairs, ln+"=\""+escapeLabel(v)+"\"")
		}
		fmt.Fprintf(b, "%s{%s} %d\n", name, strings.Join(pairs, ","), snap[k])
	}
}

// PrometheusText renders the full metrics exposition. version is reported
// via kingmoat_build_info. The family set mirrors the data-plane counters,
// the queue/dropped observability gauges and the Go runtime basics.
func PrometheusText(version string) string {
	var b strings.Builder
	b.WriteString("# HELP kingmoat_build_info Build metadata (version).\n# TYPE kingmoat_build_info gauge\n")
	fmt.Fprintf(&b, "kingmoat_build_info{version=\"%s\"} 1\n", escapeLabel(version))

	writeCounterLabeled(&b, "kingmoat_requests_total",
		"Data-plane requests by site and outcome (forwarded/blocked/challenged/redirected/monitor_forwarded).",
		RequestsTotal, []string{"site", "outcome"})
	writeCounterLabeled(&b, "kingmoat_stage_hits_total",
		"Detection pipeline stage hits.", StageHits, []string{"stage"})
	writeCounterLabeled(&b, "kingmoat_upstream_errors_total",
		"Upstream connection or request errors by site.", UpstreamErrors, []string{"site"})
	writeCounterLabeled(&b, "kingmoat_config_reloads_total",
		"Configuration reload attempts by outcome.", Reloads, []string{"outcome"})
	writeCounterLabeled(&b, "kingmoat_bot_requests_total",
		"Bot-classified requests by site and class (good/unknown/bad).",
		BotRequestsTotal, []string{"site", "class"})
	writeCounterLabeled(&b, "kingmoat_bot_denied_total",
		"Denied bot requests by site.", BotDeniedTotal, []string{"site"})
	writeCounterLabeled(&b, "kingmoat_bot_challenged_total",
		"Challenged bot requests by site.", BotChallengedTotal, []string{"site"})
	writeCounterLabeled(&b, "kingmoat_body_bypass_total",
		"Requests whose body passed the WAF without full inspection because the site body limit was exceeded (policy=bypass: not inspected at all, policy=prefix: only the first body_limit_bytes were inspected).",
		BodyBypassTotal, []string{"site", "policy"})
	writeCounterLabeled(&b, "kingmoat_body_guard_rejected_total",
		"Requests answered 503 because the aggregate request-body buffer budget (body_buffer_budget_mb) was exhausted.",
		BodyGuardRejected, []string{"site"})
	writeCounterLabeled(&b, "kingmoat_body_idle_aborts_total",
		"Request-body reads aborted after the body idle timeout (no read progress).",
		BodyIdleAborts, []string{"site"})
	writeCounterLabeledSnapshot(&b, "kingmoat_site_bytes_total",
		"Transferred payload bytes by site and direction (down = response bytes sent to the client, up = request-body bytes received from the client; cumulative, persisted across restarts via the site-bytes-state.json state file). WebSocket upgrades bypass the response recorder and are not counted.",
		SnapshotSiteBytesCumulative(), []string{"site", "direction"})

	writeGauge(&b, "kingmoat_audit_dropped_total",
		"Audit events dropped due to queue overflow (monotonic).", AuditDropped.Get())
	writeGauge(&b, "kingmoat_audit_queue_depth",
		"Audit events queued but not yet committed.", AuditQueueDepth.Get())
	writeGauge(&b, "kingmoat_accesslog_dropped_total",
		"Access-log entries dropped due to queue overflow (monotonic).", AccessLogDropped.Get())
	writeGauge(&b, "kingmoat_accesslog_queue_depth",
		"Access-log entries queued but not yet shipped.", AccessLogQueueDepth.Get())
	writeGauge(&b, "kingmoat_accesslog_local_dropped_total",
		"Access-log entries dropped by the LOCAL recorder due to queue overflow (monotonic).", AccessLocalDropped.Get())
	writeGauge(&b, "kingmoat_accesslog_local_queue_depth",
		"Access-log entries queued but not yet committed by the LOCAL recorder.", AccessLocalQueueDepth.Get())
	writeGauge(&b, "kingmoat_logshipper_dropped_total",
		"Log-shipper entries dropped due to queue overflow (monotonic).", LogShipperDropped.Get())
	writeGauge(&b, "kingmoat_logshipper_queue_depth",
		"Log-shipper entries queued but not yet shipped.", LogShipperQueueDepth.Get())

	writeGauge(&b, "go_goroutines", "Number of goroutines that currently exist.", float64(runtime.NumGoroutine()))
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	writeGauge(&b, "go_memstats_alloc_bytes", "Bytes allocated and still in use.", float64(ms.Alloc))
	writeGauge(&b, "go_memstats_sys_bytes", "Bytes obtained from system.", float64(ms.Sys))
	return b.String()
}