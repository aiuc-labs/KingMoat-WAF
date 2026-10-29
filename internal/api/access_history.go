// Local access-log history query (GET /api/access_logs/history) plus the
// shared "record" status object both access-log endpoints surface. The
// status derives from the live config (access_log_record section) and the
// CURRENT SQLite sink instance, resolved through Options.AccessLocalFn: the
// accessor must be lazy because publishing the section hot-swaps the sink
// (rebuildLocalAccess), so a boot-time snapshot would keep serving a
// detached instance — same pattern as AIFn/AICentralFn.
package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/kingmoat/kingmoat/internal/accesslog"
)

// accessRecordStatus is the LOCAL recording posture shared by
// GET /api/access_logs (new record field) and GET /api/access_logs/history.
// mode/retention_days/max_disk_mb mirror the effective access_log_record
// config values; enabled/size_bytes/evicted reflect the live sink instance
// (enabled=false when no recorder is running, regardless of the config).
// rows/oldest_ts/dropped report what is still kept on disk and what the
// data plane had to drop: switching recording off never deletes data
// (关闭不自动删数据), so rows/oldest_ts stay populated after an off-switch —
// the console uses them for the "已停止记录，本地仍保留 N 条（最早 …）" hint
// and the POST /api/access_logs/purge entry point (L3: dropped was
// previously Prometheus-only). residual pins the "已停止记录但残留可检索"
// state: enabled=false while the local database still holds queryable data
// (the history endpoint serves it through a read-only fallback).
type accessRecordStatus struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode"`
	RetentionDays int    `json:"retention_days"`
	MaxDiskMB     int    `json:"max_disk_mb"`
	SizeBytes     int64  `json:"size_bytes"`
	Evicted       int64  `json:"evicted"`
	Rows          int64  `json:"rows"`
	OldestTS      string `json:"oldest_ts,omitempty"` // RFC3339, empty = 无留存记录
	Dropped       int64  `json:"dropped"`
	Residual      bool   `json:"residual"`
}

// accessHistoryResponse is the paged local-history payload.
type accessHistoryResponse struct {
	Items    []accesslog.Entry  `json:"items"`
	Total    int                `json:"total"`
	Page     int                `json:"page"`
	PageSize int                `json:"page_size"`
	Record   accessRecordStatus `json:"record"`
}

// accessLocalSink resolves the current local recorder through the lazy
// accessor (nil function or nil result = local recording off / not wired).
func (s *Server) accessLocalSink() *accesslog.SQLiteSink {
	if s.opts.AccessLocalFn == nil {
		return nil
	}
	return s.opts.AccessLocalFn()
}

// accessRecordStatusFor builds the record object from the live config plus
// the live sink (size/evicted/rows/oldest are read from the sink instance
// itself, not cached). Nil-safe on both ends: without a recorder the
// effective config defaults surface with enabled=false and zero usage
// counters, and — when the database path is wired — rows/oldest_ts still
// report the data that stays on disk after an off-switch (via
// accesslog.LocalStats; a missing/unreadable file degrades to zeros,
// never an error response).
func (s *Server) accessRecordStatusFor() accessRecordStatus {
	_, cfg := s.opts.Center.Current()
	rec := cfg.AccessLogRecord
	st := accessRecordStatus{
		Mode:          rec.ModeOrDefault(),
		RetentionDays: rec.RetentionDaysOrDefault(),
		MaxDiskMB:     rec.MaxDiskMBOrDefault(),
	}
	if sink := s.accessLocalSink(); sink != nil {
		st.Enabled = true
		st.SizeBytes = sink.SizeBytes()
		st.Evicted = sink.Evicted()
		st.Dropped = sink.Dropped()
		if rows, err := sink.Rows(); err == nil {
			st.Rows = rows
		}
		if ts, ok := sink.OldestTS(); ok {
			st.OldestTS = ts.UTC().Format(time.RFC3339)
		}
		return st
	}
	// Recording off: report what the (possibly still present) database file
	// holds. Empty path (static/test assemblies) and every failure shape
	// degrade to zeros — the status is informational, never a 500. Residual
	// marks the retained-but-not-recording state for the console hint.
	if rows, oldest, err := accesslog.LocalStats(s.opts.AccessLocalDB); err == nil {
		st.Rows = rows
		st.Residual = rows > 0
		if !oldest.IsZero() {
			st.OldestTS = oldest.UTC().Format(time.RFC3339)
		}
	}
	return st
}

// handleAccessHistory serves GET /api/access_logs/history: the paginated
// LOCAL access-log history kept by the SQLite recorder (access_log_record).
// Parameter style mirrors the audit-log query (parseLogQuery / handleLogs):
// site substring, outcome exact, IP prefix, free-text q over
// path/ua/rule/ip/trace, RFC3339 since/until, page/page_size paging.
// With the recorder ON the query runs on the sink's read pool; with it OFF
// (or the sink not wired) the handler falls back to a strictly READ-ONLY
// query of the on-disk database (query_only + busy_timeout — the fallback
// can never write), so residual data stays searchable with IDENTICAL
// parameters and response shape; record.enabled stays false and
// record.residual reports the retained-data state. A missing or corrupt
// database degrades to an empty 200 page — never an error, so the console
// can poll freely. RBAC sits at the same level as GET /api/access_logs: any
// authenticated console identity (auditor and above), gated by the auth
// middleware.
func (s *Server) handleAccessHistory(w http.ResponseWriter, r *http.Request) {
	qp := r.URL.Query()
	// Paging mirrors handleLogs' paged mode: page default 1, page_size
	// defaulting to the legacy limit parameter (100), hard cap 1000.
	page := 1
	if v, err := strconv.Atoi(qp.Get("page")); err == nil && v > 0 {
		page = v
	}
	size := 100
	if v, err := strconv.Atoi(qp.Get("limit")); err == nil && v > 0 {
		size = v
	}
	if v, err := strconv.Atoi(qp.Get("page_size")); err == nil && v > 0 {
		size = v
	}
	if size > 1000 {
		size = 1000
	}
	var q accesslog.HistoryQuery
	if v := qp.Get("site"); v != "" {
		q.Site = v
	}
	if v := qp.Get("outcome"); v != "" {
		q.Outcome = v
	}
	if v := qp.Get("ip"); v != "" {
		q.IP = v
	}
	if v := qp.Get("q"); v != "" {
		q.Text = v
	}
	// since/until: a malformed value is rejected with 400 instead of being
	// silently ignored (which degenerated the query into a full-store scan
	// the user could mistake for their requested time window).
	if v := qp.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, simpleError(fmt.Sprintf(
				"since 参数无效，需 RFC3339 格式（例如 2026-10-13T08:00:00Z）")))
			return
		}
		q.Since = t
	}
	if v := qp.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, simpleError(fmt.Sprintf(
				"until 参数无效，需 RFC3339 格式（例如 2026-10-13T08:00:00Z）")))
			return
		}
		q.Until = t
	}
	q.Limit = size
	q.Offset = (page - 1) * size

	resp := accessHistoryResponse{
		Items:    []accesslog.Entry{},
		Page:     page,
		PageSize: size,
		Record:   s.accessRecordStatusFor(),
	}
	sink := s.accessLocalSink()
	if sink == nil {
		// Recorder off: read-only fallback so residual data stays searchable
		// (残留可检索), same parameters and response shape as the live sink.
		// Missing/corrupt databases degrade to the empty page — never a 500,
		// never error details to the client.
		if db := s.opts.AccessLocalDB; db != "" {
			hp, err := accesslog.LocalHistory(db, q)
			if err != nil {
				slog.Warn("accesslog history fallback read failed", "err", err)
			} else {
				resp.Items = hp.Items
				resp.Total = hp.Total
			}
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	hp, err := sink.History(q)
	if err != nil {
		// 发布可能在取引用与查询之间热切换 accessor 并关闭旧 sink，
		// 导致在途请求吃到一次性 500。accessor 确已更换时用新实例重试一次；
		// accessor 已切到关闭（nil）时改走残留只读链（与 recorder-off 主路径
		// 同语义）作答；否则保持原始错误语义（真实库错误不重试、不吞）。
		fresh := s.accessLocalSink()
		switch {
		case fresh != nil && fresh != sink:
			hp, err = fresh.History(q)
		case fresh == nil && s.opts.AccessLocalDB != "":
			if rhp, rerr := accesslog.LocalHistory(s.opts.AccessLocalDB, q); rerr == nil {
				hp, err = rhp, nil
			}
		}
	}
	if err != nil {
		slog.Warn("accesslog history read failed", "err", err)
		writeErr(w, http.StatusInternalServerError, simpleError("本地访问日志查询失败"))
		return
	}
	if hp.Items == nil {
		hp.Items = []accesslog.Entry{}
	}
	resp.Items = hp.Items
	resp.Total = hp.Total
	writeJSON(w, http.StatusOK, resp)
}
