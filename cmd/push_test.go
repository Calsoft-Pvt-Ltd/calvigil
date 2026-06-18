package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnterpriseEndpoint(t *testing.T) {
	tests := map[string]struct {
		base  string
		route string
		want  string
	}{
		"origin": {
			base:  "https://calvigil.example.com",
			route: "/scans",
			want:  "https://calvigil.example.com/api/v1/scans",
		},
		"trailing slash": {
			base:  "https://calvigil.example.com/",
			route: "/scans:evaluate",
			want:  "https://calvigil.example.com/api/v1/scans:evaluate",
		},
		"api base": {
			base:  "https://calvigil.example.com/api/v1",
			route: "/scans",
			want:  "https://calvigil.example.com/api/v1/scans",
		},
		"subpath": {
			base:  "https://example.com/calvigil",
			route: "/scans",
			want:  "https://example.com/calvigil/api/v1/scans",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := enterpriseEndpoint(tc.base, tc.route)
			if err != nil {
				t.Fatalf("enterpriseEndpoint error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("enterpriseEndpoint = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPushCommandUploadsReportWithHeaders(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("CALVIGIL_SECRET_BACKEND", "file")
	t.Setenv("CALVIGIL_ENTERPRISE_URL", "")
	t.Setenv("CALVIGIL_API_KEY", "")
	t.Setenv("CALVIGIL_ENTERPRISE_API_KEY", "")
	t.Setenv("CALVIGIL_IDEMPOTENCY_KEY", "")
	resetPushOptionsForTest(t)

	reportPath := writePushReportFixture(t, dir)
	var sawEvaluate, sawIngest atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cvgk_test_abcdefghijklmnopqrstuvwxyz123456" {
			t.Errorf("Authorization header = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Calvigil-Project") != "payments-service" {
			t.Errorf("project header = %q", r.Header.Get("X-Calvigil-Project"))
		}
		if r.Header.Get("X-Calvigil-Ref") != "main" {
			t.Errorf("ref header = %q", r.Header.Get("X-Calvigil-Ref"))
		}
		if r.Header.Get("X-Calvigil-Commit") != "abc123" {
			t.Errorf("commit header = %q", r.Header.Get("X-Calvigil-Commit"))
		}
		if r.Header.Get("Idempotency-Key") != "build-42" {
			t.Errorf("idempotency header = %q", r.Header.Get("Idempotency-Key"))
		}
		switch r.URL.Path {
		case "/api/v1/scans:evaluate":
			sawEvaluate.Store(true)
			writeJSONFixture(w, map[string]any{
				"pass":           true,
				"policy_enabled": true,
				"summary":        map[string]any{"project": "payments-service"},
				"violations":     []any{},
			})
		case "/api/v1/scans":
			sawIngest.Store(true)
			writeJSONFixture(w, map[string]any{
				"scan_id": "scan-123",
				"url":     "https://calvigil.example.com/scans/scan-123",
				"replay":  false,
				"summary": map[string]any{
					"project": "payments-service", "critical": 0, "high": 1,
					"medium": 0, "low": 0, "unknown": 0, "kev": 0, "packages": 2,
				},
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)
	rootCmd.SetArgs([]string{
		"push", reportPath,
		"--server-url", ts.URL,
		"--api-key", "cvgk_test_abcdefghijklmnopqrstuvwxyz123456",
		"--project", "payments-service",
		"--ref", "main",
		"--commit", "abc123",
		"--idempotency-key", "build-42",
		"--fail-on-policy",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("push command error: %v\nstderr=%s", err, stderr.String())
	}
	if !sawEvaluate.Load() || !sawIngest.Load() {
		t.Fatalf("expected evaluate and ingest calls, saw evaluate=%v ingest=%v", sawEvaluate.Load(), sawIngest.Load())
	}
	out := stdout.String()
	if !strings.Contains(out, "Policy: pass") || !strings.Contains(out, "Scan pushed: scan-123") {
		t.Fatalf("unexpected stdout: %s", out)
	}
}

func TestPushCommandPolicyFailureDoesNotIngest(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("CALVIGIL_SECRET_BACKEND", "file")
	resetPushOptionsForTest(t)

	reportPath := writePushReportFixture(t, dir)
	var ingestCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/scans:evaluate":
			writeJSONFixture(w, map[string]any{
				"pass":           false,
				"policy_enabled": true,
				"summary":        map[string]any{"project": "payments-service"},
				"violations": []map[string]any{{
					"rule_id": "block-high",
					"message": "HIGH vulnerability CVE-1 violates severity gate HIGH",
				}},
			})
		case "/api/v1/scans":
			ingestCalls.Add(1)
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)
	rootCmd.SetArgs([]string{
		"push", reportPath,
		"--server-url", ts.URL,
		"--api-key", "cvgk_test_abcdefghijklmnopqrstuvwxyz123456",
		"--fail-on-policy",
	})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected policy failure")
	}
	if !strings.Contains(err.Error(), "policy gate failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if ingestCalls.Load() != 0 {
		t.Fatalf("ingest calls = %d, want 0", ingestCalls.Load())
	}
	if !strings.Contains(stdout.String(), "Policy: fail") {
		t.Fatalf("missing policy fail output: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "block-high") {
		t.Fatalf("missing violation details: %s", stderr.String())
	}
}

func TestPushCommandRequiresEnterpriseConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("CALVIGIL_SECRET_BACKEND", "file")
	t.Setenv("CALVIGIL_ENTERPRISE_URL", "")
	t.Setenv("CALVIGIL_API_KEY", "")
	t.Setenv("CALVIGIL_ENTERPRISE_API_KEY", "")
	resetPushOptionsForTest(t)

	reportPath := writePushReportFixture(t, dir)
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"push", reportPath})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "missing Enterprise URL") {
		t.Fatalf("error = %v, want missing Enterprise URL", err)
	}
}

func TestReadPushReportRejectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{nope"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := readPushReport(path); err == nil {
		t.Fatal("expected invalid JSON error")
	}
}

func TestReadPushReportRejectsOpenVEXExport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "calvigil.openvex.json")
	body := []byte(`{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "@id": "https://calvigil/vex/test",
	  "author": "calvigil",
	  "timestamp": "2026-06-18T10:00:00Z",
	  "version": 1,
	  "statements": []
	}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := readPushReport(path)
	if err == nil {
		t.Fatal("expected OpenVEX export rejection")
	}
	if !strings.Contains(err.Error(), "OpenVEX") || !strings.Contains(err.Error(), "--format json") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadPushReportRejectsEmptyReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-calvigil.json")
	body := []byte(`{
	  "project_path": "/tmp/empty",
	  "ecosystems": [],
	  "total_packages": 0,
	  "vulnerabilities": [],
	  "scanned_at": "2026-06-18T10:00:00Z",
	  "duration": 1
	}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := readPushReport(path); err == nil {
		t.Fatal("expected empty report rejection")
	}
}

func resetPushOptionsForTest(t *testing.T) {
	t.Helper()
	pushOpts = pushOptions{Timeout: 30 * time.Second}
	t.Cleanup(func() {
		pushOpts = pushOptions{Timeout: 30 * time.Second}
		rootCmd.SetOut(os.Stdout)
		rootCmd.SetErr(os.Stderr)
	})
}

func writePushReportFixture(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "calvigil.json")
	body := []byte(`{
  "project_path": "/work/payments-service",
  "ecosystems": ["Go"],
  "total_packages": 2,
  "packages": [],
  "vulnerabilities": [],
  "scanned_at": "2026-06-14T10:00:00Z",
  "duration": 1000000000
}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write report fixture: %v", err)
	}
	return path
}

func writeJSONFixture(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(err)
	}
}
