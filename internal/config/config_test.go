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
	// Clear env vars that could interfere
	for _, key := range []string{"OPENAI_API_KEY", "OPENAI_MODEL", "NVD_API_KEY", "GITHUB_TOKEN", "OLLAMA_URL", "OLLAMA_MODEL"} {
		t.Setenv(key, "")
	}

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
	t.Setenv("OLLAMA_URL", "http://localhost:11434")
	t.Setenv("OLLAMA_MODEL", "llama3")

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
	if cfg.OllamaURL != "http://localhost:11434" {
		t.Errorf("OllamaURL = %q, want http://localhost:11434", cfg.OllamaURL)
	}
	if cfg.OllamaModel != "llama3" {
		t.Errorf("OllamaModel = %q, want llama3", cfg.OllamaModel)
	}
}

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Clear env so they don't override file values
	for _, key := range []string{"OPENAI_API_KEY", "OPENAI_MODEL", "NVD_API_KEY", "GITHUB_TOKEN", "OLLAMA_URL", "OLLAMA_MODEL"} {
		t.Setenv(key, "")
	}

	original := &Config{
		OpenAIKey:   "sk-test-key-12345",
		OpenAIModel: "gpt-4-turbo",
		NVDKey:      "nvd-key-abcde",
		GitHubToken: "ghp_testtoken",
		OllamaURL:   "http://localhost:11434",
		OllamaModel: "llama3",
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
}

func TestSetAndGet(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	for _, key := range []string{"OPENAI_API_KEY", "OPENAI_MODEL", "NVD_API_KEY", "GITHUB_TOKEN", "OLLAMA_URL", "OLLAMA_MODEL"} {
		t.Setenv(key, "")
	}

	keys := map[string]string{
		"openai-key":   "sk-newkey",
		"openai-model": "gpt-4o",
		"nvd-key":      "nvd-new",
		"github-token": "ghp-new",
		"ollama-url":   "http://host:11434",
		"ollama-model": "codellama",
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
