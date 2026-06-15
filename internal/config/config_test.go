package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaskSecret(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"empty":   {input: "", want: "****"},
		"short":   {input: "abc", want: "****"},
		"exact4":  {input: "abcd", want: "****"},
		"longer":  {input: "sk-abc123xyz", want: "****3xyz"},
		"16chars": {input: "0123456789abcdef", want: "****cdef"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := maskSecret(tc.input)
			if got != tc.want {
				t.Errorf("maskSecret(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestLoadDefaults(t *testing.T) {
	clearConfigEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.OpenAIModel != "gpt-4" {
		t.Errorf("default OpenAIModel = %q, want gpt-4", cfg.OpenAIModel)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("OPENAI_MODEL", "gpt-3.5-turbo")
	t.Setenv("NVD_API_KEY", "nvd-key")
	t.Setenv("GITHUB_TOKEN", "gh-token")
	t.Setenv("OSSINDEX_USER", "oss@example.com")
	t.Setenv("OSSINDEX_TOKEN", "oss-token")
	t.Setenv("OLLAMA_URL", "http://localhost:11434")
	t.Setenv("OLLAMA_MODEL", "llama3")
	t.Setenv("CALVIGIL_ENTERPRISE_URL", "https://enterprise.example.com")
	t.Setenv("CALVIGIL_API_KEY", "cvgk_env")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.OpenAIKey != "test-key" {
		t.Errorf("OpenAIKey = %q, want test-key", cfg.OpenAIKey)
	}
	if cfg.OpenAIModel != "gpt-3.5-turbo" {
		t.Errorf("OpenAIModel = %q, want gpt-3.5-turbo", cfg.OpenAIModel)
	}
	if cfg.NVDKey != "nvd-key" {
		t.Errorf("NVDKey = %q, want nvd-key", cfg.NVDKey)
	}
	if cfg.GitHubToken != "gh-token" {
		t.Errorf("GitHubToken = %q, want gh-token", cfg.GitHubToken)
	}
	if cfg.OSSIndexUser != "oss@example.com" {
		t.Errorf("OSSIndexUser = %q, want oss@example.com", cfg.OSSIndexUser)
	}
	if cfg.OSSIndexToken != "oss-token" {
		t.Errorf("OSSIndexToken = %q, want oss-token", cfg.OSSIndexToken)
	}
	if cfg.OllamaURL != "http://localhost:11434" {
		t.Errorf("OllamaURL = %q, want http://localhost:11434", cfg.OllamaURL)
	}
	if cfg.OllamaModel != "llama3" {
		t.Errorf("OllamaModel = %q, want llama3", cfg.OllamaModel)
	}
	if cfg.EnterpriseURL != "https://enterprise.example.com" {
		t.Errorf("EnterpriseURL = %q, want https://enterprise.example.com", cfg.EnterpriseURL)
	}
	if cfg.EnterpriseKey != "cvgk_env" {
		t.Errorf("EnterpriseKey = %q, want cvgk_env", cfg.EnterpriseKey)
	}
}

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("CALVIGIL_SECRET_BACKEND", "file")
	resetStoreForTests()
	t.Cleanup(resetStoreForTests)
	clearConfigEnv(t)

	original := &Config{
		OpenAIKey:     "sk-test-key-12345",
		OpenAIModel:   "gpt-4-turbo",
		NVDKey:        "nvd-key-abcde",
		GitHubToken:   "ghp_testtoken",
		OSSIndexUser:  "oss@example.com",
		OSSIndexToken: "oss-token-abcde",
		OllamaURL:     "http://localhost:11434",
		OllamaModel:   "llama3",
		EnterpriseURL: "https://enterprise.example.com",
		EnterpriseKey: "cvgk_config_secret",
	}

	if err := Save(original); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Verify file was created with correct permissions
	cfgFile := filepath.Join(tmpDir, configFileName)
	info, err := os.Stat(cfgFile)
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("config file permissions = %o, want 0600", perm)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if loaded.OpenAIKey != original.OpenAIKey {
		t.Errorf("OpenAIKey = %q, want %q", loaded.OpenAIKey, original.OpenAIKey)
	}
	if loaded.OpenAIModel != original.OpenAIModel {
		t.Errorf("OpenAIModel = %q, want %q", loaded.OpenAIModel, original.OpenAIModel)
	}
	if loaded.NVDKey != original.NVDKey {
		t.Errorf("NVDKey = %q, want %q", loaded.NVDKey, original.NVDKey)
	}
	if loaded.GitHubToken != original.GitHubToken {
		t.Errorf("GitHubToken = %q, want %q", loaded.GitHubToken, original.GitHubToken)
	}
	if loaded.OSSIndexUser != original.OSSIndexUser {
		t.Errorf("OSSIndexUser = %q, want %q", loaded.OSSIndexUser, original.OSSIndexUser)
	}
	if loaded.OSSIndexToken != original.OSSIndexToken {
		t.Errorf("OSSIndexToken = %q, want %q", loaded.OSSIndexToken, original.OSSIndexToken)
	}
	if loaded.EnterpriseURL != original.EnterpriseURL {
		t.Errorf("EnterpriseURL = %q, want %q", loaded.EnterpriseURL, original.EnterpriseURL)
	}
	if loaded.EnterpriseKey != original.EnterpriseKey {
		t.Errorf("EnterpriseKey = %q, want %q", loaded.EnterpriseKey, original.EnterpriseKey)
	}
}

func TestLoadLegacyOSSIndexTokenFromConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("CALVIGIL_SECRET_BACKEND", "file")
	resetStoreForTests()
	t.Cleanup(resetStoreForTests)
	clearConfigEnv(t)

	cfgFile := filepath.Join(tmpDir, configFileName)
	if err := os.WriteFile(cfgFile, []byte(`{
		"ossindex_user": "legacy@example.com",
		"ossindex_token": "legacy-token"
	}`), 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.OSSIndexUser != "legacy@example.com" {
		t.Fatalf("OSSIndexUser = %q, want legacy@example.com", cfg.OSSIndexUser)
	}
	if cfg.OSSIndexToken != "legacy-token" {
		t.Fatalf("OSSIndexToken = %q, want legacy-token", cfg.OSSIndexToken)
	}
}

func TestSetAndGet(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("CALVIGIL_SECRET_BACKEND", "file")
	resetStoreForTests()
	t.Cleanup(resetStoreForTests)
	clearConfigEnv(t)

	keys := map[string]string{
		"openai-key":     "sk-newkey",
		"openai-model":   "gpt-4o",
		"nvd-key":        "nvd-new",
		"github-token":   "ghp-new",
		"ossindex-user":  "oss@example.com",
		"ossindex-token": "oss-new-token",
		"ollama-url":     "http://host:11434",
		"ollama-model":   "codellama",
		"enterprise-url": "https://enterprise.example.com",
		"enterprise-key": "cvgk_secret_token",
	}

	for key, value := range keys {
		if err := Set(key, value); err != nil {
			t.Errorf("Set(%q, %q) error: %v", key, value, err)
		}
	}

	// Get returns masked values for secrets
	val, err := Get("openai-model")
	if err != nil {
		t.Fatalf("Get(openai-model) error: %v", err)
	}
	if val != "gpt-4o" {
		t.Errorf("Get(openai-model) = %q, want gpt-4o", val)
	}

	val, err = Get("ollama-url")
	if err != nil {
		t.Fatalf("Get(ollama-url) error: %v", err)
	}
	if val != "http://host:11434" {
		t.Errorf("Get(ollama-url) = %q, want http://host:11434", val)
	}
	val, err = Get("ossindex-user")
	if err != nil {
		t.Fatalf("Get(ossindex-user) error: %v", err)
	}
	if val != "oss@example.com" {
		t.Errorf("Get(ossindex-user) = %q, want oss@example.com", val)
	}
	val, err = Get("ossindex-token")
	if err != nil {
		t.Fatalf("Get(ossindex-token) error: %v", err)
	}
	if val != "****oken" {
		t.Errorf("Get(ossindex-token) = %q, want ****oken", val)
	}
	val, err = Get("enterprise-url")
	if err != nil {
		t.Fatalf("Get(enterprise-url) error: %v", err)
	}
	if val != "https://enterprise.example.com" {
		t.Errorf("Get(enterprise-url) = %q, want https://enterprise.example.com", val)
	}
	val, err = Get("enterprise-key")
	if err != nil {
		t.Fatalf("Get(enterprise-key) error: %v", err)
	}
	if val != "****oken" {
		t.Errorf("Get(enterprise-key) = %q, want ****oken", val)
	}
}

func TestSetInvalidKey(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	err := Set("invalid-key", "value")
	if err == nil {
		t.Error("Set with invalid key should return error")
	}
}

func TestGetInvalidKey(t *testing.T) {
	_, err := Get("nonexistent")
	if err == nil {
		t.Error("Get with invalid key should return error")
	}
}

func TestGet_AllSecretKeys(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("CALVIGIL_SECRET_BACKEND", "file")
	resetStoreForTests()
	t.Cleanup(resetStoreForTests)
	clearConfigEnv(t)

	// Set all keys first
	_ = Set("openai-key", "sk-testkey12345678")
	_ = Set("nvd-key", "nvd-testkey12345678")
	_ = Set("github-token", "ghp_testtoken12345678")
	_ = Set("ossindex-user", "oss@example.com")
	_ = Set("ossindex-token", "oss-testtoken12345678")
	_ = Set("ollama-url", "http://localhost:11434")
	_ = Set("ollama-model", "llama3")
	_ = Set("openai-model", "gpt-4-turbo")

	// Test masked keys
	val, err := Get("openai-key")
	if err != nil {
		t.Fatalf("Get(openai-key) error: %v", err)
	}
	if val != "****5678" {
		t.Errorf("Get(openai-key) = %q, want ****5678", val)
	}

	val, err = Get("nvd-key")
	if err != nil {
		t.Fatalf("Get(nvd-key) error: %v", err)
	}
	if val != "****5678" {
		t.Errorf("Get(nvd-key) = %q, want ****5678", val)
	}

	val, err = Get("github-token")
	if err != nil {
		t.Fatalf("Get(github-token) error: %v", err)
	}
	if val != "****5678" {
		t.Errorf("Get(github-token) = %q, want ****5678", val)
	}
	val, err = Get("ossindex-token")
	if err != nil {
		t.Fatalf("Get(ossindex-token) error: %v", err)
	}
	if val != "****5678" {
		t.Errorf("Get(ossindex-token) = %q, want ****5678", val)
	}

	// Non-secret keys
	val, err = Get("ollama-url")
	if err != nil {
		t.Fatalf("Get(ollama-url) error: %v", err)
	}
	if val != "http://localhost:11434" {
		t.Errorf("Get(ollama-url) = %q", val)
	}

	val, err = Get("ollama-model")
	if err != nil {
		t.Fatalf("Get(ollama-model) error: %v", err)
	}
	if val != "llama3" {
		t.Errorf("Get(ollama-model) = %q", val)
	}

	val, err = Get("openai-model")
	if err != nil {
		t.Fatalf("Get(openai-model) error: %v", err)
	}
	if val != "gpt-4-turbo" {
		t.Errorf("Get(openai-model) = %q", val)
	}
}

func TestGet_EmptySecrets(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("CALVIGIL_SECRET_BACKEND", "file")
	resetStoreForTests()
	t.Cleanup(resetStoreForTests)
	clearConfigEnv(t)

	val, err := Get("openai-key")
	if err != nil {
		t.Fatalf("Get(openai-key) error: %v", err)
	}
	if val != "****" {
		t.Errorf("Get(openai-key) with empty = %q, want ****", val)
	}

	val, err = Get("nvd-key")
	if err != nil {
		t.Fatalf("Get(nvd-key) error: %v", err)
	}
	if val != "****" {
		t.Errorf("Get(nvd-key) with empty = %q, want ****", val)
	}

	val, err = Get("github-token")
	if err != nil {
		t.Fatalf("Get(github-token) error: %v", err)
	}
	if val != "****" {
		t.Errorf("Get(github-token) with empty = %q, want ****", val)
	}
	val, err = Get("ossindex-token")
	if err != nil {
		t.Fatalf("Get(ossindex-token) error: %v", err)
	}
	if val != "****" {
		t.Errorf("Get(ossindex-token) with empty = %q, want ****", val)
	}
}

func TestLoadFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	for _, key := range []string{"OPENAI_API_KEY", "OPENAI_MODEL", "NVD_API_KEY", "GITHUB_TOKEN", "OLLAMA_URL", "OLLAMA_MODEL"} {
		t.Setenv(key, "")
	}

	// Write config file directly
	cfgJSON := `{"openai_api_key":"file-key","openai_model":"gpt-3.5","nvd_api_key":"nvd-file","github_token":"ghp-file","ollama_url":"http://remote:11434","ollama_model":"codellama"}`
	os.WriteFile(filepath.Join(tmpDir, configFileName), []byte(cfgJSON), 0600)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.OpenAIKey != "file-key" {
		t.Errorf("OpenAIKey = %q, want file-key", cfg.OpenAIKey)
	}
	if cfg.OllamaURL != "http://remote:11434" {
		t.Errorf("OllamaURL = %q", cfg.OllamaURL)
	}
	if cfg.OllamaModel != "codellama" {
		t.Errorf("OllamaModel = %q", cfg.OllamaModel)
	}
}
