// POST /api/access_logs/purge: the manual cleanup entry for the LOCAL
// access-log store (access_log_record). Switching recording off never
// deletes data (关闭不自动删数据), so the operator gets an explicit,
// destructive, admin-only endpoint: every recorded row is deleted, the file
// space is reclaimed (DELETE + VACUUM + WAL checkpoint), and the change is
// audit-logged like every other management mutation.
package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/kingmoat/kingmoat/internal/accesslog"
	"github.com/kingmoat/kingmoat/internal/store"
)

// handleAccessPurge serves POST /api/access_logs/purge. RBAC is elevated to
// admin (requireRole, users.go — the destructive action sits one level above
// the read endpoints, same gate shape as the user-management and upgrade
// endpoints). It deletes every recorded row through the LIVE sink when
// recording is on, or through the on-disk database directly when it is off,
// records a change-audit entry and answers with the purged row count plus
// the refreshed record status. Recording never enabled / no database file /
// static assembly (no path wired) answer 200 with purged=0 — never a 500.
func (s *Server) handleAccessPurge(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	var (
		purged int64
		err    error
	)
	if sink := s.accessLocalSink(); sink != nil {
		purged, err = sink.PurgeAll()
		if err != nil && purged == 0 {
			// Close-race guard (same class as the history endpoint): the publish
			// path may swap the accessor to nil and close the sink between our
			// read and PurgeAll. Only an accessor that provably moved on retries
			// — new instance, or the on-disk purge when recording was switched
			// off — a live-instance error stays a real store failure.
			switch fresh := s.accessLocalSink(); {
			case fresh != nil && fresh != sink:
				purged, err = fresh.PurgeAll()
			case fresh == nil && s.opts.AccessLocalDB != "":
				purged, err = accesslog.PurgeLocalAll(s.opts.AccessLocalDB)
			}
		}
	} else if db := s.opts.AccessLocalDB; db != "" {
		purged, err = accesslog.PurgeLocalAll(db)
	}
	if err != nil {
		// Full detail (including the database path) stays server-side only;
		// every auditor-readable surface below answers with generic text (RC-4).
		slog.Error("accesslog: local access-log purge failed",
			"db", s.opts.AccessLocalDB, "err", err)
		// Rows already deleted but the space reclaim failed: the destructive
		// contract held, so the answer stays a success with the warning
		// attached instead of a misleading 500.
		if purged > 0 {
			s.recordChange(r, "accesslog.purge", "access-logs.db",
				fmt.Sprintf("清空本地访问日志 %d 条（文件空间回收失败，详情见服务端日志）", purged))
			writeJSON(w, http.StatusOK, map[string]any{
				"purged":  purged,
				"warning": "本地访问日志已清空，但文件空间回收失败，详情见服务端日志",
				"record":  s.accessRecordStatusFor(),
			})
			return
		}
		writeErr(w, http.StatusInternalServerError, simpleError("本地访问日志清空失败，详情见服务端日志"))
		return
	}
	s.recordChange(r, "accesslog.purge", "access-logs.db",
		fmt.Sprintf("清空本地访问日志 %d 条", purged))
	writeJSON(w, http.StatusOK, map[string]any{
		"purged": purged,
		"record": s.accessRecordStatusFor(),
	})
}
