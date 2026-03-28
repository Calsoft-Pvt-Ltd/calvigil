package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// DefaultTTL is the default cache entry time-to-live.
const DefaultTTL = 24 * time.Hour

// DefaultDir returns the default cache directory (~/.calvigil/cache).
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".calvigil", "cache")
}

// entry is a single cached vulnerability lookup result.
type entry struct {
	Vulns     []models.Vulnerability `json:"vulns"`
	CachedAt  time.Time              `json:"cached_at"`
	ExpiresAt time.Time              `json:"expires_at"`
}

// Cache provides a file-based TTL cache for vulnerability query results.
type Cache struct {
	dir string
	ttl time.Duration
}

// New creates a new Cache. If dir is empty, the default directory is used.
func New(dir string, ttl time.Duration) *Cache {
	if dir == "" {
		dir = DefaultDir()
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Cache{dir: dir, ttl: ttl}
}

// key generates a cache key from a source name and package list.
func key(source string, packages []models.Package) string {
	h := sha256.New()
	h.Write([]byte(source))
	for _, pkg := range packages {
		h.Write([]byte(pkg.Name))
		h.Write([]byte(pkg.Version))
		h.Write([]byte(pkg.Ecosystem))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Get retrieves cached vulnerability results for the given source and packages.
// Returns nil, false if no valid cache entry exists.
func (c *Cache) Get(source string, packages []models.Package) ([]models.Vulnerability, bool) {
	if c.dir == "" {
		return nil, false
	}

	k := key(source, packages)
	path := filepath.Join(c.dir, k+".json")

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var e entry
	if err := json.Unmarshal(data, &e); err != nil {
		os.Remove(path)
		return nil, false
	}

	if time.Now().After(e.ExpiresAt) {
		os.Remove(path)
		return nil, false
	}

	return e.Vulns, true
}

// Put stores vulnerability results in the cache.
func (c *Cache) Put(source string, packages []models.Package, vulns []models.Vulnerability) error {
	if c.dir == "" {
		return nil
	}

	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}

	k := key(source, packages)
	now := time.Now()
	e := entry{
		Vulns:     vulns,
		CachedAt:  now,
		ExpiresAt: now.Add(c.ttl),
	}

	data, err := json.Marshal(e)
	if err != nil {
		return err
	}

	path := filepath.Join(c.dir, k+".json")
	return os.WriteFile(path, data, 0o600)
}

// Clear removes all cache entries.
func (c *Cache) Clear() error {
	if c.dir == "" {
		return nil
	}
	return os.RemoveAll(c.dir)
}
