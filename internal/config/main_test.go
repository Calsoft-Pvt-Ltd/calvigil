package config

import (
	"os"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestMain pins the secret store to the file backend by default so the test
// suite is hermetic and never prompts an OS keychain. Tests that specifically
// exercise the keyring backend opt into keyring.MockInit() themselves.
func TestMain(m *testing.M) {
	os.Setenv("CALVIGIL_SECRET_BACKEND", "file")
	// MockInit is idempotent; calling it here guarantees keyring-specific
	// tests never touch the real OS credential manager either.
	keyring.MockInit()
	os.Exit(m.Run())
}
