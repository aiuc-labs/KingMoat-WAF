package api

import (
	"os"
	"testing"
)

// testBootstrapPassword is the first-boot password pinned for the test binary
// through KMWAF_BOOTSTRAP_PASSWORD: the product no longer ships a hardcoded
// default password, it generates one per install (or takes the env value).
const testBootstrapPassword = "Test-Only-Passw0rd!"

// TestMain pins the bootstrap password for every test in this package before
// any server seeds an empty users table.
func TestMain(m *testing.M) {
	_ = os.Setenv(bootstrapPasswordEnv, testBootstrapPassword)
	os.Exit(m.Run())
}
