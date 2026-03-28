package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func testPackages() []models.Package {
	return []models.Package{
		{Name: "express", Version: "4.18.2", Ecosystem: models.EcosystemNpm},
		{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm},
	}
}

func testVulns() []models.Vulnerability {
	return []models.Vulnerability{
		{ID: "CVE-2024-0001", Summary: "Test vuln 1", Severity: models.SeverityHigh},
		{ID: "CVE-2024-0002", Summary: "Test vuln 2", Severity: models.SeverityMedium},
	}
}

func TestPutAndGet(t *testing.T) {
	dir := t.TempDir()
	c := New(dir, 1*time.Hour)

	pkgs := testPackages()
	vulns := testVulns()

	if err := c.Put("osv", pkgs, vulns); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	got, ok := c.Get("osv", pkgs)
	if !ok {
		t.Fatal("Get returned false after Put")
	}
	if len(got) != len(vulns) {
		t.Fatalf("expected %d vulns, got %d", len(vulns), len(got))
	}
	if got[0].ID != "CVE-2024-0001" {
		t.Errorf("expected CVE-2024-0001, got %s", got[0].ID)
	}
	if got[1].Summary != "Test vuln 2" {
		t.Errorf("expected 'Test vuln 2', got %s", got[1].Summary)
	}
}

func TestGet_Miss(t *testing.T) {
	dir := t.TempDir()
	c := New(dir, 1*time.Hour)

	_, ok := c.Get("osv", testPackages())
	if ok {
		t.Error("Get should return false for empty cache")
	}
}

func TestGet_Expired(t *testing.T) {
	dir := t.TempDir()
	c := New(dir, 1*time.Millisecond)

	pkgs := testPackages()
	if err := c.Put("osv", pkgs, testVulns()); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	_, ok := c.Get("osv", pkgs)
	if ok {
		t.Error("Get should return false for expired entry")
	}
}

func TestGet_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	c := New(dir, 1*time.Hour)

	// Write a corrupted file
	k := key("osv", testPackages())
	path := filepath.Join(dir, k+".json")
	if err := os.WriteFile(path, []byte("not valid json{{{"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, ok := c.Get("osv", testPackages())
	if ok {
		t.Error("Get should return false for corrupted cache")
	}

	// File should be cleaned up
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("corrupted cache file should have been removed")
	}
}

func TestPut_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deeply", "nested", "cache")
	c := New(dir, 1*time.Hour)

	err := c.Put("osv", testPackages(), testVulns())
	if err != nil {
		t.Fatalf("Put should create directory: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("cache directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}

func TestClear(t *testing.T) {
	dir := t.TempDir()
	c := New(dir, 1*time.Hour)

	if err := c.Put("osv", testPackages(), testVulns()); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := c.Clear(); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	_, ok := c.Get("osv", testPackages())
	if ok {
		t.Error("Get should return false after Clear")
	}
}

func TestNew_DefaultTTL(t *testing.T) {
	c := New(t.TempDir(), 0)
	if c.ttl != DefaultTTL {
		t.Errorf("expected DefaultTTL %v, got %v", DefaultTTL, c.ttl)
	}
}

func TestNew_NegativeTTL(t *testing.T) {
	c := New(t.TempDir(), -5*time.Minute)
	if c.ttl != DefaultTTL {
		t.Errorf("expected DefaultTTL for negative input, got %v", c.ttl)
	}
}

func TestKey_Deterministic(t *testing.T) {
	pkgs := testPackages()
	k1 := key("osv", pkgs)
	k2 := key("osv", pkgs)
	if k1 != k2 {
		t.Errorf("key should be deterministic: %s != %s", k1, k2)
	}
}

func TestKey_DifferentInputs(t *testing.T) {
	pkgs1 := []models.Package{{Name: "a", Version: "1.0", Ecosystem: "Go"}}
	pkgs2 := []models.Package{{Name: "a", Version: "2.0", Ecosystem: "Go"}}
	pkgs3 := []models.Package{{Name: "b", Version: "1.0", Ecosystem: "Go"}}

	k1 := key("osv", pkgs1)
	k2 := key("osv", pkgs2)
	k3 := key("osv", pkgs3)
	k4 := key("nvd", pkgs1)

	if k1 == k2 {
		t.Error("different versions should produce different keys")
	}
	if k1 == k3 {
		t.Error("different names should produce different keys")
	}
	if k1 == k4 {
		t.Error("different sources should produce different keys")
	}
}

func TestPut_EmptyDir(t *testing.T) {
	c := &Cache{dir: "", ttl: 1 * time.Hour}
	err := c.Put("osv", testPackages(), testVulns())
	if err != nil {
		t.Errorf("Put with empty dir should be no-op, got error: %v", err)
	}
}

func TestGet_EmptyDir(t *testing.T) {
	c := &Cache{dir: "", ttl: 1 * time.Hour}
	_, ok := c.Get("osv", testPackages())
	if ok {
		t.Error("Get with empty dir should return false")
	}
}

func TestClear_EmptyDir(t *testing.T) {
	c := &Cache{dir: "", ttl: 1 * time.Hour}
	err := c.Clear()
	if err != nil {
		t.Errorf("Clear with empty dir should be no-op, got error: %v", err)
	}
}

func TestPut_EmptyVulns(t *testing.T) {
	dir := t.TempDir()
	c := New(dir, 1*time.Hour)

	err := c.Put("osv", testPackages(), nil)
	if err != nil {
		t.Fatalf("Put nil vulns failed: %v", err)
	}

	got, ok := c.Get("osv", testPackages())
	if !ok {
		t.Fatal("Get should return true for cached nil vulns")
	}
	if len(got) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(got))
	}
}
