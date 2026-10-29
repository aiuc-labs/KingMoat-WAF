package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/kingmoat/kingmoat/internal/apiasset"
	"github.com/kingmoat/kingmoat/internal/store"
)

var (
	errAssetModuleDisabled = fmt.Errorf("API 资产模块未启用")
	errRiskModuleDisabled  = fmt.Errorf("风险模块未启用")
)

// writeAssetStoreErr renders one apiasset store error: the original driver
// text (SQL fragments, internal paths) goes only to the server log, the
// client gets a fixed Chinese message.
func writeAssetStoreErr(w http.ResponseWriter, op string, err error) {
	slog.Error("api: asset store operation failed", "op", op, "err", err)
	writeErr(w, http.StatusInternalServerError, simpleError("资产数据操作失败，详情见服务端日志"))
}

// AssetsOptions carries the API-asset module wiring (nil = disabled).
// The hot-rebuild assembly (all-in-one) treats instances as
// immutable snapshots: a rebuild publishes a fresh value through the atomic
// Options.AssetsRef container instead of mutating a shared one in place.
type AssetsOptions struct {
	Store        *apiasset.Store
	Collector    *apiasset.Collector
	Engine       *apiasset.Engine
	RisksEnabled bool
}

// assetsSnapshot returns the API-asset / risk module wiring for this
// request. With AssetsRef wired (rebuild-on-publish assemblies) it loads
// exactly one immutable snapshot, so a concurrent publish can neither race
// the read nor split the nil-check → use pair; static assemblies keep
// Options.Assets.
func (s *Server) assetsSnapshot() *AssetsOptions {
	if s.opts.AssetsRef != nil {
		return s.opts.AssetsRef.Load()
	}
	return s.opts.Assets
}

func intQuery(r *http.Request, key string, def, max int) int {
	v := def
	if s := r.URL.Query().Get(key); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			v = n
		}
	}
	if v <= 0 {
		v = def
	}
	if v > max {
		v = max
	}
	return v
}

// handleAssetList serves GET /api/assets/apis.
func (s *Server) handleAssetList(w http.ResponseWriter, r *http.Request) {
	opts := s.assetsSnapshot()
	if opts == nil || opts.Store == nil {
		writeErr(w, http.StatusNotFound, errAssetModuleDisabled)
		return
	}
	q := r.URL.Query()
	page := intQuery(r, "page", 1, 10000)
	size := intQuery(r, "page_size", 50, 200)
	assets, total, err := opts.Store.ListAssets(
		q.Get("site"), q.Get("method"), q.Get("tag"), q.Get("q"),
		q.Get("candidates") == "1", (page-1)*size, size)
	if err != nil {
		writeAssetStoreErr(w, "assets.list", err)
		return
	}
	if assets == nil {
		assets = []apiasset.Asset{}
	}
	tracked, dropped := 0, 0
	if opts.Collector != nil {
		tracked, dropped = opts.Collector.Stats()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"assets": assets, "total": total, "page": page, "page_size": size,
		"collector": map[string]int{"tracked": tracked, "dropped": dropped},
	})
}

// handleAssetGet serves GET /api/assets/apis/{id}.
func (s *Server) handleAssetGet(w http.ResponseWriter, r *http.Request) {
	opts := s.assetsSnapshot()
	if opts == nil || opts.Store == nil {
		writeErr(w, http.StatusNotFound, errAssetModuleDisabled)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, simpleError("资产 ID 无效"))
		return
	}
	a, err := opts.Store.GetAsset(id)
	if err != nil {
		// Unknown id is the only client-facing fact; a transient store
		// failure answers the same fixed-message 500 + server log as the
		// sibling handlers (writeAssetStoreErr), never a misleading 404.
		if errors.Is(err, apiasset.ErrAssetNotFound) {
			writeErr(w, http.StatusNotFound, simpleError("资产不存在或已被清理"))
			return
		}
		writeAssetStoreErr(w, "asset.get", err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// handleAssetIgnore serves POST /api/assets/apis/{id}/ignore.
func (s *Server) handleAssetIgnore(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	opts := s.assetsSnapshot()
	if opts == nil || opts.Store == nil {
		writeErr(w, http.StatusNotFound, errAssetModuleDisabled)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, simpleError("资产 ID 无效"))
		return
	}
	var req struct {
		Ignored bool `json:"ignored"`
	}
	if err := decodeBody(r, &req); err != nil {
		slog.Warn("api: asset request body decode failed", "op", "assets.ignore", "err", err)
		writeErr(w, http.StatusBadRequest, simpleError("请求体必须是合法的 JSON"))
		return
	}
	if err := opts.Store.IgnoreAsset(id, req.Ignored); err != nil {
		writeAssetStoreErr(w, "assets.ignore", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAssetSites serves GET /api/assets/sites.
func (s *Server) handleAssetSites(w http.ResponseWriter, r *http.Request) {
	opts := s.assetsSnapshot()
	if opts == nil || opts.Store == nil {
		writeErr(w, http.StatusNotFound, errAssetModuleDisabled)
		return
	}
	sites, err := opts.Store.SiteList()
	if err != nil {
		writeAssetStoreErr(w, "assets.sites", err)
		return
	}
	writeJSON(w, http.StatusOK, sites)
}

// handleRiskList serves GET /api/risks.
func (s *Server) handleRiskList(w http.ResponseWriter, r *http.Request) {
	opts := s.assetsSnapshot()
	if opts == nil || opts.Store == nil {
		writeErr(w, http.StatusNotFound, errAssetModuleDisabled)
		return
	}
	q := r.URL.Query()
	page := intQuery(r, "page", 1, 10000)
	size := intQuery(r, "page_size", 50, 200)
	risks, total, err := opts.Store.ListRisks(
		q.Get("status"), q.Get("level"), q.Get("kind"), (page-1)*size, size)
	if err != nil {
		writeAssetStoreErr(w, "risks.list", err)
		return
	}
	if risks == nil {
		risks = []apiasset.Risk{}
	}
	var lastScan any
	if ts, ok := opts.Store.LastScanAt(); ok {
		lastScan = ts
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"risks": risks, "total": total, "page": page, "page_size": size,
		"last_scan_at": lastScan,
	})
}

// handleRiskScan serves POST /api/risks/scan (manual "scan now").
func (s *Server) handleRiskScan(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	opts := s.assetsSnapshot()
	if opts == nil || opts.Engine == nil {
		writeErr(w, http.StatusNotFound, errRiskModuleDisabled)
		return
	}
	if opts.Collector != nil {
		opts.Collector.FlushNow()
	}
	n, err := opts.Engine.RunScan()
	if err != nil {
		slog.Error("api: asset store operation failed", "op", "risks.scan", "err", err)
		writeErr(w, http.StatusInternalServerError, simpleError("风险扫描执行失败，详情见服务端日志"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"new_findings": n})
}

// handleRiskStatus serves POST /api/risks/{id}/status.
func (s *Server) handleRiskStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	opts := s.assetsSnapshot()
	if opts == nil || opts.Store == nil {
		writeErr(w, http.StatusNotFound, errAssetModuleDisabled)
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := decodeBody(r, &req); err != nil {
		slog.Warn("api: asset request body decode failed", "op", "risks.status", "err", err)
		writeErr(w, http.StatusBadRequest, simpleError("请求体必须是合法的 JSON"))
		return
	}
	// 预校验状态取值，把存储层的英文错误译成明确提示（状态码不变）。
	switch req.Status {
	case "open", "ignored", "resolved":
	default:
		writeErr(w, http.StatusBadRequest, simpleError("status 必须是 open、ignored 或 resolved 之一"))
		return
	}
	if err := opts.Store.SetRiskStatus(r.PathValue("id"), req.Status); err != nil {
		slog.Error("api: asset store operation failed", "op", "risks.status", "err", err)
		writeErr(w, http.StatusBadRequest, simpleError("风险状态更新失败，详情见服务端日志"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
