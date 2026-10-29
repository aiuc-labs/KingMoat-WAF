// Local access-log recorder wiring (access_log_record): the chain composer
// and the hot-reload rebuilder for the LOCAL SQLite store. The outbound
// shipper rebuilder (rebuildAccess in main.go) is untouched: both rebuilders
// rewire the data plane through the shared setSink closure, which recomposes
// the chain from the CURRENT instances instead of trusting the argument —
// rebuildAccess hands it a pre-built ring/shipper Tee that cannot carry the
// hot-swappable local recorder.
//
// Closing invariant (mirrors rebuildAccess): the resident ring is never
// closed, and Tee.Close only closes its second — so the local store's close
// is NEVER delegated to a nested Tee. Like the shipper, the replaced local
// instance is closed explicitly after the swap; its Close drains the queue,
// and Write-after-Close is a guarded silent drop (SQLiteSink's mu+closed
// guard, counted in Dropped) — in-flight requests outliving the swap can
// never panic on a closed channel. A failed rebuild keeps the previous
// instance so recording is never silently interrupted, and reports through
// noteFn (the config center's load_notes — the console degradation banner):
// the publish API has already answered "success" at that point, so the
// banner is the only channel that tells the operator the recording posture
// actually stayed on the old config.
package main

import (
	"log/slog"
	"sync/atomic"

	"github.com/kingmoat/kingmoat/internal/accesslog"
	"github.com/kingmoat/kingmoat/internal/config"
)

// composeAccessSink builds the data-plane access sink chain from the current
// instances: resident ring first (live tail; never closed), then the local
// recorder, then the outbound shipper. Members may be nil (feature off).
func composeAccessSink(ring *accesslog.Ring, local *accesslog.SQLiteSink, shipper *accesslog.Shipper) accesslog.Sink {
	var s accesslog.Sink = ring
	if local != nil {
		s = accesslog.NewTee(s, local)
	}
	if shipper != nil {
		s = accesslog.NewTee(s, shipper)
	}
	return s
}

// rebuildLocalAccess hot-applies the access_log_record section: nil (section
// removed) and mode=off share the disable path (stop recording, detach the
// local store, keep the rest of the chain wired); "all"/"sites" build a new
// SQLiteSink. An unchanged section skips the rebuild entirely (no swap, no
// close, no SetSink churn). A failed rebuild keeps the previous instance and
// the data plane is NOT touched; noteFn (nil = wiring without a config
// center, e.g. tests) carries the failure to the console degradation banner.
// On success the recomposed chain replaces the sink BEFORE the old store
// closes, so entries keep flowing during the swap; the old store's Close
// flushes whatever its queue still held.
func rebuildLocalAccess(cur *atomic.Pointer[accesslog.SQLiteSink], setSink func(accesslog.Sink), tr *sectionTracker[config.AccessLogRecordSettings], rec *config.AccessLogRecordSettings, dbPath string, logger *slog.Logger, noteFn func(reason string)) {
	if tr.unchanged(rec) {
		return
	}
	if rec == nil || rec.ModeOrDefault() == config.AccessRecordModeOff {
		old := cur.Swap(nil)
		tr.applied.Store(nil)
		if old != nil {
			setSink(nil) // recompose the chain without the local recorder
			_ = old.Close()
			logger.Info("access log local recording disabled")
		}
		return
	}
	fresh, err := accesslog.NewSQLiteSink(dbPath, *rec, logger)
	if err != nil {
		logger.Error("access log local store rebuild failed, keeping previous", "err", err)
		if noteFn != nil {
			// The publish already reported success; surface the actual
			// posture (old config still recording / recording never started)
			// with the fix hint. The banner text stays generic: the full
			// error (which carries the database path) goes to the server log
			// above, never to the auditor-readable load notes (RC-4). noteFn
			// appends inside the config center's load-notes critical
			// section, rev-guarded against a concurrent newer publish (no
			// stale facts on a newer revision).
			noteFn("访问日志本地记录应用失败，已保持上一配置。" +
				"若此前未开启本地记录，则当前仍未记录；若此前已开启，则仍按旧配置继续记录。" +
				"常见原因：磁盘空间不足或数据目录（audit_log_dir）不可写；排除后重新发布「访问日志设置」即可生效。详细原因见服务端日志。")
		}
		return
	}
	old := cur.Swap(fresh)
	tr.applied.Store(rec)
	setSink(nil) // recompose the chain with the new local recorder
	if old != nil {
		_ = old.Close() // flush the replaced instance AFTER the swap
	}
	logger.Info("access log local store applied",
		"mode", rec.ModeOrDefault(), "db", dbPath,
		"retention_days", rec.RetentionDaysOrDefault(),
		"max_disk_mb", rec.MaxDiskMBOrDefault(),
		"sites", len(rec.Sites))
}
