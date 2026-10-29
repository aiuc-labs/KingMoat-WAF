// Local access-log recording settings: the independent top-level
// "access_log_record" config section. This section is deliberately SEPARATE
// from the outbound access_log section: the console deletes the whole
// access_log key when the off-host pipeline is switched off
// (web/console Settings.vue buildAccessPayload/delete), so anything nested
// inside it would be silently erased together with the switch. Local
// recording has its own lifecycle and defaults to off: a config without the
// section behaves byte-identically to a pre-feature config (nothing was
// stored locally before this feature either).
package config

import (
	"fmt"
	"slices"
	"strings"
)

// Access-log recording modes. "off" records nothing (default), "all" records
// every site (requests with no matching site — the empty site label — are
// excluded: they belong to no site and carry no site-dimension query value),
// "sites" records only the listed sites.
const (
	AccessRecordModeOff   = "off"
	AccessRecordModeAll   = "all"
	AccessRecordModeSites = "sites"
)

// AccessLogRecordSettings controls the LOCAL access-log recording (a
// standalone SQLite database written by the data plane). It is independent
// of AccessLogSettings (the off-host shipper): both can be on, either can be
// on, and the outbound sample_pct sampling does NOT apply to local
// recording — enabled sites are recorded in full (sampling lives inside the
// shipper pipeline, so the two paths are naturally decoupled).
type AccessLogRecordSettings struct {
	// Mode selects what is recorded: "off" (default) | "all" | "sites".
	Mode string `json:"mode,omitempty"`
	// Sites is effective only in "sites" mode: the list of site FIRST
	// domains (the same identity the access-log entries carry, i.e.
	// Sites[].Domains[0], compared lowercase). Unknown domains are rejected
	// at publish/load time.
	Sites []string `json:"sites,omitempty"`
	// RetentionDays: 0 = default 7; accepted range 1-90.
	RetentionDays int `json:"retention_days,omitempty"`
	// MaxDiskMB: storage ceiling for the local database (db + wal + shm);
	// 0 = default 1024; accepted range 128-10240. When exceeded, the oldest
	// days are evicted first (down to 80% of the ceiling).
	MaxDiskMB int `json:"max_disk_mb,omitempty"`
	// BatchSize: batched insert size; 0 = default 256; accepted range 64-2048.
	BatchSize int `json:"batch_size,omitempty"`
	// FlushSec: batch flush interval in seconds; 0 = default 1; range 1-60.
	FlushSec int `json:"flush_sec,omitempty"`
}

// ModeOrDefault returns the normalized recording mode (empty = "off").
func (r *AccessLogRecordSettings) ModeOrDefault() string {
	if r == nil || strings.TrimSpace(r.Mode) == "" {
		return AccessRecordModeOff
	}
	return strings.ToLower(strings.TrimSpace(r.Mode))
}

// RetentionDaysOrDefault returns the effective retention in days (default 7).
func (r *AccessLogRecordSettings) RetentionDaysOrDefault() int {
	if r == nil || r.RetentionDays <= 0 {
		return 7
	}
	return r.RetentionDays
}

// MaxDiskMBOrDefault returns the effective storage ceiling in MB
// (default 1024).
func (r *AccessLogRecordSettings) MaxDiskMBOrDefault() int {
	if r == nil || r.MaxDiskMB <= 0 {
		return 1024
	}
	return r.MaxDiskMB
}

// BatchSizeOrDefault returns the effective batched-insert size (default 256).
func (r *AccessLogRecordSettings) BatchSizeOrDefault() int {
	if r == nil || r.BatchSize <= 0 {
		return 256
	}
	return r.BatchSize
}

// FlushSecOrDefault returns the effective flush interval in seconds
// (default 1).
func (r *AccessLogRecordSettings) FlushSecOrDefault() int {
	if r == nil || r.FlushSec <= 0 {
		return 1
	}
	return r.FlushSec
}

// Validate enforces the section rules (decision D5: an unknown domain in the
// sites list fails publish/load with an actionable message, matching the
// repo-wide publish-time-validation posture). knownSites holds the valid
// site identities (lowercased first domains). Numeric fields accept 0
// (= default); any non-zero out-of-range value is rejected so a typo cannot
// silently fall back to the default.
func (r *AccessLogRecordSettings) Validate(knownSites map[string]struct{}) error {
	if r == nil {
		return nil
	}
	switch mode := r.ModeOrDefault(); mode {
	case AccessRecordModeOff, AccessRecordModeAll:
	case AccessRecordModeSites:
		if len(r.Sites) == 0 {
			return fmt.Errorf("config: access_log_record.mode=sites requires a non-empty sites list (pick at least one site, or set mode to \"all\")")
		}
		var unknown []string
		for _, s := range r.Sites {
			d := strings.ToLower(strings.TrimSpace(s))
			if _, ok := knownSites[d]; !ok {
				unknown = append(unknown, s)
			}
		}
		if len(unknown) > 0 {
			valid := make([]string, 0, len(knownSites))
			for k := range knownSites {
				valid = append(valid, k)
			}
			slices.Sort(valid)
			return fmt.Errorf("config: access_log_record.sites references %d unknown site(s): %s; valid site names: %s (add the site(s) first, or remove them from the recording list)",
				len(unknown), strings.Join(unknown, ", "), strings.Join(valid, ", "))
		}
	default:
		return fmt.Errorf("config: access_log_record.mode must be \"off\", \"all\" or \"sites\", got %q", r.Mode)
	}
	if r.RetentionDays != 0 && (r.RetentionDays < 1 || r.RetentionDays > 90) {
		return fmt.Errorf("config: access_log_record.retention_days must be 0 (= default 7) or within 1-90, got %d", r.RetentionDays)
	}
	if r.MaxDiskMB != 0 && (r.MaxDiskMB < 128 || r.MaxDiskMB > 10240) {
		return fmt.Errorf("config: access_log_record.max_disk_mb must be 0 (= default 1024) or within 128-10240, got %d", r.MaxDiskMB)
	}
	if r.BatchSize != 0 && (r.BatchSize < 64 || r.BatchSize > 2048) {
		return fmt.Errorf("config: access_log_record.batch_size must be 0 (= default 256) or within 64-2048, got %d", r.BatchSize)
	}
	if r.FlushSec != 0 && (r.FlushSec < 1 || r.FlushSec > 60) {
		return fmt.Errorf("config: access_log_record.flush_sec must be 0 (= default 1) or within 1-60, got %d", r.FlushSec)
	}
	return nil
}
