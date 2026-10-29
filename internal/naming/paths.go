package naming

import (
	"log/slog"
	"os"
)

// ResolveDefaultPath returns current when the caller kept the built-in default
// (current == defaultName) BUT the preferred file is absent while the legacy
// file exists — the signature of an install upgraded from the pre-v0.9.6
// naming that has not run the directory/DB migration yet. Any explicit
// non-default path is returned untouched, so an operator override always wins.
func ResolveDefaultPath(current, defaultName, legacyName string) string {
	if current != defaultName {
		return current
	}
	if _, err := os.Stat(current); err == nil {
		return current
	}
	if _, err := os.Stat(legacyName); err == nil {
		slog.Warn("using the legacy file name; rename it (see the naming migration script)",
			"legacy", legacyName, "current", defaultName)
		return legacyName
	}
	return current
}
