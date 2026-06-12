package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestFileStore_RoundTrip verifies set/get/delete on the file backend.
func TestFileStore_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	s := newFileStore()
	if err := s.Set("alpha", "one"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if v, err := s.Get("alpha"); err != nil || v != "one" {
		t.Fatalf("Get alpha = %q, err=%v", v, err)
	}
	if err := s.Delete("alpha"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("alpha"); err == nil {
		t.Fatal("expected errSecretNotFound after Delete")
	}
}

// TestFileStore_FilePermissions verifies the secrets file is created 0600.
func TestFileStore_FilePermissions(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	s := newFileStore()
	if err := s.Set("k", "v"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	info, err := os.Stat(filepath.Join(tmp, secretsFileName))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 0600", perm)
	}
}

// TestSave_DoesNotWriteSecretsToConfigFile verifies the main config file
// never contains raw secrets after Save — they must live in the store.
func TestSave_DoesNotWriteSecretsToConfigFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	clearConfigEnv(t)

	cfg := &Config{
		OpenAIKey:   "sk-should-not-leak",
		NVDKey:      "nvd-should-not-leak",
		GitHubToken: "ghp_should_not_leak",
		OpenAIModel: "gpt-4",
		OllamaURL:   "http://localhost:11434",
	}
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmp, configFileName))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	body := string(data)
	for _, secret := range []string{"sk-should-not-leak", "nvd-should-not-leak", "ghp_should_not_leak"} {
		if strings.Contains(body, secret) {
			t.Errorf("config file leaks secret %q: %s", secret, body)
		}
	}

	// Secrets file should contain them (file backend is pinned in TestMain).
	secretsData, err := os.ReadFile(filepath.Join(tmp, secretsFileName))
	if err != nil {
		t.Fatalf("read secrets: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(secretsData, &m); err != nil {
		t.Fatalf("parse secrets: %v", err)
	}
	if m[secretKeyOpenAI] != "sk-should-not-leak" {
		t.Errorf("secret store missing openai key, got %q", m[secretKeyOpenAI])
	}
}

// TestLoad_MigratesLegacyPlaintextSecrets verifies that a legacy config
// file with inline secrets is still readable, and that the values are
// migrated into the secret store on the next Save.
func TestLoad_MigratesLegacyPlaintextSecrets(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	clearConfigEnv(t)

	legacy := `{
		"openai_api_key": "legacy-openai",
		"nvd_api_key":    "legacy-nvd",
		"github_token":   "legacy-gh",
		"openai_model":   "gpt-4"
	}`
	if err := os.WriteFile(filepath.Join(tmp, configFileName), []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OpenAIKey != "legacy-openai" {
		t.Errorf("OpenAIKey = %q, want legacy-openai", cfg.OpenAIKey)
	}

	// Re-save and confirm the main config file no longer contains them.
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, configFileName))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	body := string(data)
	for _, legacySecret := range []string{"legacy-openai", "legacy-nvd", "legacy-gh"} {
		if strings.Contains(body, legacySecret) {
			t.Errorf("migration did not remove legacy secret %q: %s", legacySecret, body)
		}
	}
}

// TestKeyringBackend_RoundTrip uses go-keyring's in-memory mock (already
// installed by TestMain) and exercises the keyring code path end-to-end.
func TestKeyringBackend_RoundTrip(t *testing.T) {
	t.Setenv("CALVIGIL_SECRET_BACKEND", "keyring")
	resetStoreForTests()
	t.Cleanup(resetStoreForTests)
	keyring.MockInit()

	if err := saveSecret(secretKeyOpenAI, "kr-value"); err != nil {
		t.Fatalf("saveSecret: %v", err)
	}
	openai, _, _, _, err := loadSecrets()
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}
	if openai != "kr-value" {
		t.Errorf("openai via keyring = %q, want kr-value", openai)
	}

	// Empty value deletes and returns errSecretNotFound.
	if err := saveSecret(secretKeyOpenAI, ""); err != nil {
		t.Fatalf("saveSecret empty: %v", err)
	}
	openai, _, _, _, err = loadSecrets()
	if err != nil {
		t.Fatalf("loadSecrets after delete: %v", err)
	}
	if openai != "" {
		t.Errorf("openai after delete = %q, want empty", openai)
	}
}

// TestValidateImageRef exists in the image package; this test exercises
// the config env override precedence over the secret store.
func TestLoad_EnvOverridesSecretStore(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	clearConfigEnv(t)

	// Seed the store.
	if err := saveSecret(secretKeyOpenAI, "from-store"); err != nil {
		t.Fatalf("saveSecret: %v", err)
	}
	// Env var must win.
	t.Setenv("OPENAI_API_KEY", "from-env")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OpenAIKey != "from-env" {
		t.Errorf("OpenAIKey = %q, want from-env", cfg.OpenAIKey)
	}
}

func clearConfigEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"OPENAI_API_KEY", "OPENAI_MODEL",
		"NVD_API_KEY", "GITHUB_TOKEN",
		"OLLAMA_URL", "OLLAMA_MODEL",
	} {
		t.Setenv(k, "")
	}
}

// TestSet_ClearsSecretWhenEmpty verifies that Set("openai-key", "") removes
// the key from the underlying store, not just blanks it in the config file.
func TestSet_ClearsSecretWhenEmpty(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	clearConfigEnv(t)

	if err := Set("openai-key", "sk-initial"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	cfg, _ := Load()
	if cfg.OpenAIKey != "sk-initial" {
		t.Fatalf("OpenAIKey after set = %q", cfg.OpenAIKey)
	}

	if err := Set("openai-key", ""); err != nil {
		t.Fatalf("Set empty: %v", err)
	}
	cfg, _ = Load()
	if cfg.OpenAIKey != "" {
		t.Errorf("OpenAIKey after clear = %q, want empty", cfg.OpenAIKey)
	}

	// Masked Get must report the sentinel.
	val, err := Get("openai-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "****" {
		t.Errorf("Get openai-key = %q, want ****", val)
	}
}

// TestFileStore_DeleteMissing verifies deleting a nonexistent key is a no-op.
func TestFileStore_DeleteMissing(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	s := newFileStore()
	if err := s.Delete("does-not-exist"); err != nil {
		t.Errorf("Delete missing key = %v, want nil", err)
	}
}

// TestFileStore_CorruptedFile verifies the store surfaces a parse error.
func TestFileStore_CorruptedFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.WriteFile(filepath.Join(tmp, secretsFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := newFileStore()
	if _, err := s.Get("anything"); err == nil {
		t.Error("expected error on corrupted secrets file")
	}
}
