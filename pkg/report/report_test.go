package report

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// TestAliasCompatibility proves the public aliases are identical to the
// internal canonical model: a value built via the public API round-trips
// through JSON with the exact wire format the CLI emits.
func TestAliasCompatibility(t *testing.T) {
	in := ScanResult{
		ProjectPath:   "/src/app",
		Ecosystems:    []Ecosystem{"Go", "npm"},
		TotalPackages: 2,
		Vulnerabilities: []Vulnerability{
			{
				ID:       "CVE-2025-0001",
				Aliases:  []string{"GHSA-xxxx-yyyy-zzzz"},
				Summary:  "test finding",
				Severity: SeverityCritical,
				Score:    9.8,
				Package: Package{
					Name:      "example.com/lib",
					Version:   "1.2.3",
					Ecosystem: "Go",
					PURL:      "pkg:golang/example.com/lib@1.2.3",
				},
				FixedIn:        "1.2.4",
				Source:         SourceOSV,
				KnownExploited: true,
				PublishedAt:    time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC),
			},
		},
		ScannedAt: time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC),
	}

	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out ScanResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Vulnerabilities[0].ID != "CVE-2025-0001" {
		t.Errorf("vuln id = %q, want CVE-2025-0001", out.Vulnerabilities[0].ID)
	}
	if !out.Vulnerabilities[0].KnownExploited {
		t.Error("known_exploited flag lost in round-trip")
	}
	if out.Vulnerabilities[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want CRITICAL", out.Vulnerabilities[0].Severity)
	}

	// Wire-format spot checks: stable JSON keys the enterprise ingester relies on.
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal generic: %v", err)
	}
	for _, key := range []string{"project_path", "ecosystems", "total_packages", "vulnerabilities", "scanned_at"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("expected top-level JSON key %q missing", key)
		}
	}
}

func TestHelpers(t *testing.T) {
	if got := ParseSeverity("moderate"); got != SeverityMedium {
		t.Errorf("ParseSeverity(moderate) = %q, want MEDIUM", got)
	}
	if got := ScoreToSeverity(9.5); got != SeverityCritical {
		t.Errorf("ScoreToSeverity(9.5) = %q, want CRITICAL", got)
	}
}

func TestDecodeScanResultRejectsExportArtifacts(t *testing.T) {
	openVEX := []byte(`{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "@id": "https://calvigil/vex/test",
	  "author": "calvigil",
	  "timestamp": "2026-06-18T10:00:00Z",
	  "version": 1,
	  "statements": []
	}`)
	if _, err := DecodeScanResult(openVEX); err == nil {
		t.Fatal("expected OpenVEX export to be rejected")
	} else if !errors.Is(err, ErrInvalidScanReport) || !strings.Contains(err.Error(), "OpenVEX") {
		t.Fatalf("unexpected OpenVEX error: %v", err)
	}

	cycloneDX := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`)
	if _, err := DecodeScanResult(cycloneDX); err == nil {
		t.Fatal("expected CycloneDX export to be rejected")
	} else if !strings.Contains(err.Error(), "CycloneDX") {
		t.Fatalf("unexpected CycloneDX error: %v", err)
	}

	spdx := []byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`)
	if _, err := DecodeScanResult(spdx); err == nil {
		t.Fatal("expected SPDX export to be rejected")
	} else if !strings.Contains(err.Error(), "SPDX") {
		t.Fatalf("unexpected SPDX error: %v", err)
	}

	sarif := []byte(`{"version":"2.1.0","runs":[]}`)
	if _, err := DecodeScanResult(sarif); err == nil {
		t.Fatal("expected SARIF export to be rejected")
	} else if !strings.Contains(err.Error(), "SARIF") {
		t.Fatalf("unexpected SARIF error: %v", err)
	}

	openVEXWithoutContext := []byte(`{"statements":[]}`)
	if _, err := DecodeScanResult(openVEXWithoutContext); err == nil {
		t.Fatal("expected OpenVEX statements-only artifact to be rejected")
	} else if !strings.Contains(err.Error(), "OpenVEX") {
		t.Fatalf("unexpected statements-only OpenVEX error: %v", err)
	}
}

func TestDecodeScanResultRejectsEmptyReportShape(t *testing.T) {
	empty := []byte(`{
	  "project_path": "/tmp/empty",
	  "ecosystems": [],
	  "total_packages": 0,
	  "vulnerabilities": [],
	  "scanned_at": "2026-06-18T10:00:00Z",
	  "duration": 1
	}`)
	if _, err := DecodeScanResult(empty); err == nil {
		t.Fatal("expected empty report to be rejected")
	} else if !errors.Is(err, ErrInvalidScanReport) || !strings.Contains(err.Error(), "no packages") {
		t.Fatalf("unexpected empty report error: %v", err)
	}
}

func TestDecodeScanResultRejectsMalformedAndTrailingJSON(t *testing.T) {
	cases := map[string][]byte{
		"invalid":   []byte(`{`),
		"empty":     []byte(`{}`),
		"trailing":  []byte(`{"project_path":"/tmp/a"} {"project_path":"/tmp/b"}`),
		"bad_trail": []byte(`{"project_path":"/tmp/a"} [`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeScanResult(raw); err == nil {
				t.Fatal("expected invalid report error")
			} else if !errors.Is(err, ErrInvalidScanReport) {
				t.Fatalf("error = %v, want ErrInvalidScanReport", err)
			}
		})
	}
}

func TestDecodeScanResultRejectsMissingRequiredFields(t *testing.T) {
	raw := []byte(`{
	  "project_path": "/tmp/app",
	  "ecosystems": ["npm"],
	  "total_packages": 1,
	  "vulnerabilities": [],
	  "scanned_at": "2026-06-18T10:00:00Z"
	}`)
	if _, err := DecodeScanResult(raw); err == nil {
		t.Fatal("expected missing duration to be rejected")
	} else if !strings.Contains(err.Error(), `"duration"`) {
		t.Fatalf("error = %v, want duration field mention", err)
	}
}

func TestValidateScanResultRejectsInvalidDecodedValues(t *testing.T) {
	valid := ScanResult{
		ProjectPath:   "/tmp/app",
		TotalPackages: 1,
		ScannedAt:     time.Date(2026, 6, 18, 10, 0, 0, 0, time.UTC),
		Packages:      []Package{{Name: "react", Version: "19.0.0", Ecosystem: "npm"}},
	}

	cases := map[string]struct {
		mutate func(*ScanResult)
		want   string
	}{
		"project_path": {
			mutate: func(r *ScanResult) { r.ProjectPath = " " },
			want:   "project_path",
		},
		"scanned_at": {
			mutate: func(r *ScanResult) { r.ScannedAt = time.Time{} },
			want:   "scanned_at",
		},
		"negative_packages": {
			mutate: func(r *ScanResult) { r.TotalPackages = -1 },
			want:   "total_packages",
		},
		"negative_duration": {
			mutate: func(r *ScanResult) { r.Duration = -1 },
			want:   "duration",
		},
		"empty_vuln_id": {
			mutate: func(r *ScanResult) {
				r.Packages = nil
				r.Vulnerabilities = []Vulnerability{{ID: " "}}
			},
			want: "vulnerabilities[0].id",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := valid
			tc.mutate(&got)
			err := ValidateScanResult(got)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !errors.Is(err, ErrInvalidScanReport) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDecodeScanResultAcceptsCleanPackageInventory(t *testing.T) {
	raw := []byte(`{
	  "project_path": "/tmp/clean",
	  "ecosystems": ["npm"],
	  "total_packages": 1,
	  "packages": [{"name":"react","version":"19.0.0","ecosystem":"npm","file_path":"package-lock.json","purl":"pkg:npm/react@19.0.0","indirect":false}],
	  "vulnerabilities": [],
	  "scanned_at": "2026-06-18T10:00:00Z",
	  "duration": 1
	}`)
	got, err := DecodeScanResult(raw)
	if err != nil {
		t.Fatalf("DecodeScanResult clean inventory: %v", err)
	}
	if got.ProjectPath != "/tmp/clean" || got.TotalPackages != 1 || len(got.Packages) != 1 {
		t.Fatalf("decoded report mismatch: %+v", got)
	}
}

func TestSchemaFileDocumentsEnterpriseWireContract(t *testing.T) {
	raw, err := os.ReadFile("schema.json")
	if err != nil {
		t.Fatalf("read schema.json: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("schema.json is not valid JSON: %v", err)
	}
	if schema["$id"] != "https://calvigil.io/schemas/report/v5/schema.json" {
		t.Fatalf("unexpected schema id: %v", schema["$id"])
	}
	text := string(raw)
	for _, key := range []string{
		"project_path",
		"ecosystems",
		"total_packages",
		"vulnerabilities",
		"known_exploited",
		"license_issues",
		"integrity_issues",
		"consistency_issues",
		"ai_enrichment",
	} {
		if !strings.Contains(text, `"`+key+`"`) {
			t.Fatalf("schema.json does not document %q", key)
		}
	}
}
