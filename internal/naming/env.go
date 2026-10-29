package naming

import (
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Naming convention (v0.9.6+): the LONG form "kingmoatwaf" is used for
// binaries, units, directories and data files; the SHORT form "kmwaf" is the
// environment-variable prefix (CLI names follow the short form too: kmwafctl).
const (
	// EnvPrefix is the current environment-variable prefix.
	EnvPrefix = "KMWAF_"
	// LegacyEnvPrefix is the pre-v0.9.6 prefix, still read as a fallback so an
	// upgrade never loses credentials that live in an existing EnvironmentFile.
	LegacyEnvPrefix = "KINGMOAT_"
)

var envWarned sync.Map

// EnvValue resolves one environment variable by its CONFIGURED name, with a
// cross-prefix fallback (KMWAF_* ↔ KINGMOAT_*) so both the new and the legacy
// spelling keep working during the transition. The first legacy hit logs a
// deprecation warning once per name.
func EnvValue(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if v := os.Getenv(name); v != "" {
		return v
	}
	var legacy string
	if s, ok := strings.CutPrefix(name, EnvPrefix); ok {
		legacy = LegacyEnvPrefix + s
	} else if s, ok := strings.CutPrefix(name, LegacyEnvPrefix); ok {
		legacy = EnvPrefix + s
	}
	if legacy == "" {
		return ""
	}
	v := os.Getenv(legacy)
	if v != "" {
		if _, warned := envWarned.LoadOrStore(name, true); !warned {
			slog.Warn("environment variable uses the legacy prefix; rename it in the EnvironmentFile",
				"legacy", legacy, "current", name)
		}
	}
	return v
}

// Env resolves KMWAF_<suffix> with the legacy KINGMOAT_<suffix> fallback.
func Env(suffix string) string { return EnvValue(EnvPrefix + suffix) }
