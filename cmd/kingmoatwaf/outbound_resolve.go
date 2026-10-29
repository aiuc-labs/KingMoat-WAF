// Thin wrappers over the outbound-channel resolvers that moved to
// internal/config (byte-identical sink-down): the API probe layer
// (internal/api) needs the same "effective section" semantics behind
// use_audit_channel and cannot import package main, so the implementation
// now lives next to the config types it overlays
// (config.ResolveAccessOut / config.ResolveAIShipOut). The wrappers keep
// the cmd-side call sites (rebuildAccess / rebuildAIShip / the boot-time
// tracker seeding) and the channel-reuse tests unchanged.
package main

import "github.com/kingmoat/kingmoat/internal/config"

// resolveAccessOut resolves the effective access-log outbound section.
// nil, disabled sections and switch-off sections pass through unchanged; a
// switch-on section with a channel present returns the overlay copy (channel
// from ls, identity from the section).
func resolveAccessOut(al *config.AccessLogSettings, ls *config.ShipperSettings) *config.AccessLogSettings {
	return config.ResolveAccessOut(al, ls)
}

// resolveAIShipOut resolves the effective AI-session ship section under the
// same rules as resolveAccessOut.
func resolveAIShipOut(ship *config.AIAuditShipSettings, ls *config.ShipperSettings) *config.AIAuditShipSettings {
	return config.ResolveAIShipOut(ship, ls)
}
