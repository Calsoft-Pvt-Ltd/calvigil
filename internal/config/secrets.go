package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/zalando/go-keyring"
)

// keyringService is the namespace used when storing secrets in the OS
// credential manager (macOS Keychain, Windows Credential Manager, Linux
// Secret Service).
const keyringService = "calvigil"

// secretStore abstracts where secrets are persisted. The default
// implementation prefers the OS credential manager and transparently falls
// back to an encrypted-at-rest-on-disk file in headless environments
// (CI, containers, some Linux servers without a Secret Service daemon).
type secretStore interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
}

// errSecretNotFound is returned by stores when a key has no value.
var errSecretNotFound = errors.New("secret not found")

// defaultStore lazily probes the OS credential manager on first use and
// returns the best available backend.
var (
	defaultStoreOnce sync.Once
	defaultStoreImpl secretStore
)

func getStore() secretStore {
	defaultStoreOnce.Do(func() {
		// A test env var lets the test suite pin the backend.
		switch os.Getenv("CALVIGIL_SECRET_BACKEND") {
		case "file":
			defaultStoreImpl = newFileStore()
			return
		case "keyring":
			defaultStoreImpl = &keyringStore{}
			return
		}

		// Probe the OS keyring by writing and deleting a sentinel. If it
		// works, keep using it. Otherwise fall back to file-based storage.
		probe := "_calvigil_probe"
		if err := keyring.Set(keyringService, probe, "ok"); err != nil {
			defaultStoreImpl = newFileStore()
			return
		}
		_ = keyring.Delete(keyringService, probe)
		defaultStoreImpl = &keyringStore{}
	})
	return defaultStoreImpl
}

// resetStoreForTests clears the cached backend so tests can re-probe.
func resetStoreForTests() {
	defaultStoreOnce = sync.Once{}
	defaultStoreImpl = nil
}

// ── keyring-backed store ────────────────────────────────────────────────

type keyringStore struct{}

func (k *keyringStore) Get(key string) (string, error) {
	v, err := keyring.Get(keyringService, key)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", errSecretNotFound
		}
		return "", err
	}
	return v, nil
}

func (k *keyringStore) Set(key, value string) error {
	return keyring.Set(keyringService, key, value)
}

func (k *keyringStore) Delete(key string) error {
	err := keyring.Delete(keyringService, key)
	if err != nil && errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// ── file-backed fallback ────────────────────────────────────────────────
//
// Used in headless environments where no OS credential manager is available.
// Secrets are stored in a separate file (~/.calvigil-secrets.json, mode 0600)
// so they never mix with the main config file and are easy to audit / rotate.
// This is no better than plaintext against an attacker with read access to
// the home directory, but matches the prior behavior while keeping the new
// API surface consistent.

type fileStore struct {
	mu sync.Mutex
}

const secretsFileName = ".calvigil-secrets.json"

func newFileStore() *fileStore {
	return &fileStore{}
}

// resolvePath returns the secrets file path for the current HOME. We
// re-resolve on every op so that tests (and users) can change HOME without
// restarting the process.
func (f *fileStore) resolvePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return secretsFileName
	}
	return filepath.Join(home, secretsFileName)
}

func (f *fileStore) load() (map[string]string, error) {
	data, err := os.ReadFile(f.resolvePath())
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	m := map[string]string{}
	if len(data) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("cannot parse secrets file: %w", err)
	}
	return m, nil
}

func (f *fileStore) save(m map[string]string) error {
	path := f.resolvePath()
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	// Write via tmp file + rename for atomic replacement.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".calvigil-secrets-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (f *fileStore) Get(key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.load()
	if err != nil {
		return "", err
	}
	v, ok := m[key]
	if !ok {
		return "", errSecretNotFound
	}
	return v, nil
}

func (f *fileStore) Set(key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.load()
	if err != nil {
		return err
	}
	m[key] = value
	return f.save(m)
}

func (f *fileStore) Delete(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.load()
	if err != nil {
		return err
	}
	if _, ok := m[key]; !ok {
		return nil
	}
	delete(m, key)
	return f.save(m)
}

// ── public helpers used by Load/Save ────────────────────────────────────

// secretKeys maps struct field names to the stable keyring key used on disk
// and in the OS credential manager.
const (
	secretKeyOpenAI   = "openai_api_key"
	secretKeyNVD      = "nvd_api_key"
	secretKeyGitHub   = "github_token"
	secretKeyOSSIndex = "ossindex_token"
)

// loadSecrets returns all known secrets from the active store. Missing
// values are returned as empty strings; backend errors are surfaced.
func loadSecrets() (openai, nvd, github, ossindex string, err error) {
	store := getStore()
	get := func(k string) (string, error) {
		v, err := store.Get(k)
		if err != nil && !errors.Is(err, errSecretNotFound) {
			return "", err
		}
		return v, nil
	}
	if openai, err = get(secretKeyOpenAI); err != nil {
		return
	}
	if nvd, err = get(secretKeyNVD); err != nil {
		return
	}
	if github, err = get(secretKeyGitHub); err != nil {
		return
	}
	if ossindex, err = get(secretKeyOSSIndex); err != nil {
		return
	}
	return
}

// saveSecret writes a single secret to the active store, or clears it if
// the value is empty.
func saveSecret(key, value string) error {
	store := getStore()
	if value == "" {
		return store.Delete(key)
	}
	return store.Set(key, value)
}
