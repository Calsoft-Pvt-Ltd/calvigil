package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	configFileName = ".calvigil.json"
)

// Config holds all configuration for the scanner.
//
// Non-secret fields (model names, URLs) are persisted to ~/.calvigil.json.
// Secret fields (API keys, tokens) are stored via the OS credential manager
// when available and fall back to a separate 0600 file. See secrets.go.
type Config struct {
	OpenAIKey     string `json:"openai_api_key,omitempty"`
	OpenAIModel   string `json:"openai_model,omitempty"`
	NVDKey        string `json:"nvd_api_key,omitempty"`
	GitHubToken   string `json:"github_token,omitempty"`
	OSSIndexUser  string `json:"ossindex_user,omitempty"`
	OSSIndexToken string `json:"ossindex_token,omitempty"`
	OllamaURL     string `json:"ollama_url,omitempty"`
	OllamaModel   string `json:"ollama_model,omitempty"`
	LMStudioURL   string `json:"lmstudio_url,omitempty"`
	LMStudioModel string `json:"lmstudio_model,omitempty"`
}

// fileConfig is the on-disk representation. Secret fields are intentionally
// omitted so they can only be written via the secret store.
type fileConfig struct {
	OpenAIModel   string `json:"openai_model,omitempty"`
	OSSIndexUser  string `json:"ossindex_user,omitempty"`
	OllamaURL     string `json:"ollama_url,omitempty"`
	OllamaModel   string `json:"ollama_model,omitempty"`
	LMStudioURL   string `json:"lmstudio_url,omitempty"`
	LMStudioModel string `json:"lmstudio_model,omitempty"`

	// Legacy secret fields kept only for reading older configs so we can
	// migrate them into the secret store on first Save(). They are never
	// written back out.
	LegacyOpenAIKey   string `json:"openai_api_key,omitempty"`
	LegacyNVDKey      string `json:"nvd_api_key,omitempty"`
	LegacyGitHubToken string `json:"github_token,omitempty"`
}

// configFilePath returns the path to the config file in the user's home directory.
func configFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, configFileName), nil
}

// Load reads config from disk and the secret store, then overlays any
// matching environment variables (which always take precedence).
func Load() (*Config, error) {
	cfg := &Config{
		OpenAIModel: "gpt-4",
	}

	// Read non-secrets + any legacy inline secrets from ~/.calvigil.json.
	var fc fileConfig
	cfgPath, err := configFilePath()
	if err == nil {
		data, readErr := os.ReadFile(cfgPath)
		if readErr == nil {
			_ = json.Unmarshal(data, &fc)
			if fc.OpenAIModel != "" {
				cfg.OpenAIModel = fc.OpenAIModel
			}
			cfg.OllamaURL = fc.OllamaURL
			cfg.OllamaModel = fc.OllamaModel
			cfg.LMStudioURL = fc.LMStudioURL
			cfg.LMStudioModel = fc.LMStudioModel
			cfg.OSSIndexUser = fc.OSSIndexUser
			cfg.OpenAIKey = fc.LegacyOpenAIKey
			cfg.NVDKey = fc.LegacyNVDKey
			cfg.GitHubToken = fc.LegacyGitHubToken
		}
	}

	// Pull secrets from the secret store; these win over any legacy
	// plaintext values still sitting in the config file.
	if openai, nvd, gh, ossToken, serr := loadSecrets(); serr == nil {
		if openai != "" {
			cfg.OpenAIKey = openai
		}
		if nvd != "" {
			cfg.NVDKey = nvd
		}
		if gh != "" {
			cfg.GitHubToken = gh
		}
		if ossToken != "" {
			cfg.OSSIndexToken = ossToken
		}
	}

	// Environment variables override everything.
	if v := os.Getenv("OPENAI_API_KEY"); v != "" {
		cfg.OpenAIKey = v
	}
	if v := os.Getenv("OPENAI_MODEL"); v != "" {
		cfg.OpenAIModel = v
	}
	if v := os.Getenv("NVD_API_KEY"); v != "" {
		cfg.NVDKey = v
	}
	if v := os.Getenv("GITHUB_TOKEN"); v != "" {
		cfg.GitHubToken = v
	}
	if v := os.Getenv("OSSINDEX_USER"); v != "" {
		cfg.OSSIndexUser = v
	}
	if v := os.Getenv("OSSINDEX_TOKEN"); v != "" {
		cfg.OSSIndexToken = v
	}
	if v := os.Getenv("OLLAMA_URL"); v != "" {
		cfg.OllamaURL = v
	}
	if v := os.Getenv("OLLAMA_MODEL"); v != "" {
		cfg.OllamaModel = v
	}
	if v := os.Getenv("LMSTUDIO_URL"); v != "" {
		cfg.LMStudioURL = v
	}
	if v := os.Getenv("LMSTUDIO_MODEL"); v != "" {
		cfg.LMStudioModel = v
	}

	return cfg, nil
}

// Save writes the config to disk and the secret store.
//
// Non-secret fields are written to ~/.calvigil.json with mode 0600.
// Secret fields are written via the secret store (OS keyring when
// available, 0600 fallback file otherwise). Any secrets present in an
// older plaintext config file are migrated out and cleared.
func Save(cfg *Config) error {
	cfgPath, err := configFilePath()
	if err != nil {
		return err
	}

	fc := fileConfig{
		OpenAIModel:   cfg.OpenAIModel,
		OSSIndexUser:  cfg.OSSIndexUser,
		OllamaURL:     cfg.OllamaURL,
		OllamaModel:   cfg.OllamaModel,
		LMStudioURL:   cfg.LMStudioURL,
		LMStudioModel: cfg.LMStudioModel,
	}
	data, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal config: %w", err)
	}
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		return fmt.Errorf("cannot write config file: %w", err)
	}

	if err := saveSecret(secretKeyOpenAI, cfg.OpenAIKey); err != nil {
		return fmt.Errorf("cannot save openai key: %w", err)
	}
	if err := saveSecret(secretKeyNVD, cfg.NVDKey); err != nil {
		return fmt.Errorf("cannot save nvd key: %w", err)
	}
	if err := saveSecret(secretKeyGitHub, cfg.GitHubToken); err != nil {
		return fmt.Errorf("cannot save github token: %w", err)
	}
	if err := saveSecret(secretKeyOSSIndex, cfg.OSSIndexToken); err != nil {
		return fmt.Errorf("cannot save oss index token: %w", err)
	}
	return nil
}

// Set updates a single config key and saves.
func Set(key, value string) error {
	cfg, err := Load()
	if err != nil {
		return err
	}

	switch key {
	case "openai-key":
		cfg.OpenAIKey = value
	case "openai-model":
		cfg.OpenAIModel = value
	case "nvd-key":
		cfg.NVDKey = value
	case "github-token":
		cfg.GitHubToken = value
	case "ossindex-user":
		cfg.OSSIndexUser = value
	case "ossindex-token":
		cfg.OSSIndexToken = value
	case "ollama-url":
		cfg.OllamaURL = value
	case "ollama-model":
		cfg.OllamaModel = value
	case "lmstudio-url":
		cfg.LMStudioURL = value
	case "lmstudio-model":
		cfg.LMStudioModel = value
	default:
		return fmt.Errorf("unknown config key: %s (valid keys: openai-key, openai-model, nvd-key, github-token, ossindex-user, ossindex-token, ollama-url, ollama-model, lmstudio-url, lmstudio-model)", key)
	}

	return Save(cfg)
}

// Get returns the value of a config key.
func Get(key string) (string, error) {
	cfg, err := Load()
	if err != nil {
		return "", err
	}

	switch key {
	case "openai-key":
		return maskSecret(cfg.OpenAIKey), nil
	case "openai-model":
		return cfg.OpenAIModel, nil
	case "nvd-key":
		return maskSecret(cfg.NVDKey), nil
	case "github-token":
		return maskSecret(cfg.GitHubToken), nil
	case "ossindex-user":
		return cfg.OSSIndexUser, nil
	case "ossindex-token":
		return maskSecret(cfg.OSSIndexToken), nil
	case "ollama-url":
		return cfg.OllamaURL, nil
	case "ollama-model":
		return cfg.OllamaModel, nil
	case "lmstudio-url":
		return cfg.LMStudioURL, nil
	case "lmstudio-model":
		return cfg.LMStudioModel, nil
	default:
		return "", fmt.Errorf("unknown config key: %s", key)
	}
}

// maskSecret masks all but the last 4 characters of a secret.
func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return "****" + s[len(s)-4:]
}
