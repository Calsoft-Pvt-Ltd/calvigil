package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

var ErrInvalidScanReport = errors.New("invalid calvigil scan report")

// DecodeScanResult decodes the canonical Calvigil JSON scan report accepted by
// Enterprise ingestion. It intentionally allows unknown top-level fields for
// forward compatibility, but rejects other Calvigil export artifacts such as
// OpenVEX, CycloneDX, SPDX, SARIF, or arbitrary empty JSON objects.
func DecodeScanResult(raw []byte) (ScanResult, error) {
	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return ScanResult{}, fmt.Errorf("%w: invalid JSON: %v", ErrInvalidScanReport, err)
	}
	if len(top) == 0 {
		return ScanResult{}, fmt.Errorf("%w: expected a JSON object", ErrInvalidScanReport)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return ScanResult{}, fmt.Errorf("%w: multiple JSON documents are not allowed", ErrInvalidScanReport)
		}
		return ScanResult{}, fmt.Errorf("%w: invalid trailing JSON: %v", ErrInvalidScanReport, err)
	}
	if kind := knownExportArtifact(top); kind != "" {
		return ScanResult{}, fmt.Errorf("%w: %s is an export artifact, not an ingestable scan report; push the file produced by --format json", ErrInvalidScanReport, kind)
	}
	for _, field := range []string{"project_path", "ecosystems", "total_packages", "vulnerabilities", "scanned_at", "duration"} {
		rawField, ok := top[field]
		if !ok || bytes.Equal(bytes.TrimSpace(rawField), []byte("null")) {
			return ScanResult{}, fmt.Errorf("%w: missing required field %q", ErrInvalidScanReport, field)
		}
	}

	var res ScanResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return ScanResult{}, fmt.Errorf("%w: schema decode failed: %v", ErrInvalidScanReport, err)
	}
	if err := ValidateScanResult(res); err != nil {
		return ScanResult{}, err
	}
	return res, nil
}

// ValidateScanResult validates decoded reports that are about to cross the OSS
// to Enterprise trust boundary.
func ValidateScanResult(res ScanResult) error {
	if strings.TrimSpace(res.ProjectPath) == "" {
		return fmt.Errorf("%w: project_path is required", ErrInvalidScanReport)
	}
	if res.ScannedAt.IsZero() {
		return fmt.Errorf("%w: scanned_at is required", ErrInvalidScanReport)
	}
	if res.TotalPackages < 0 {
		return fmt.Errorf("%w: total_packages cannot be negative", ErrInvalidScanReport)
	}
	if res.Duration < 0 {
		return fmt.Errorf("%w: duration cannot be negative", ErrInvalidScanReport)
	}
	if len(res.Vulnerabilities) == 0 &&
		len(res.Packages) == 0 &&
		res.TotalPackages == 0 &&
		len(res.LicenseIssues) == 0 &&
		len(res.IntegrityIssues) == 0 &&
		len(res.ConsistencyIssues) == 0 &&
		len(res.Errors) == 0 {
		return fmt.Errorf("%w: report contains no packages, findings, supply-chain issues, or scanner errors", ErrInvalidScanReport)
	}
	for i, vuln := range res.Vulnerabilities {
		if strings.TrimSpace(vuln.ID) == "" {
			return fmt.Errorf("%w: vulnerabilities[%d].id is required", ErrInvalidScanReport, i)
		}
	}
	return nil
}

func knownExportArtifact(top map[string]json.RawMessage) string {
	if _, hasContext := top["@context"]; hasContext {
		if _, hasStatements := top["statements"]; hasStatements {
			return "OpenVEX"
		}
	}
	if _, hasStatements := top["statements"]; hasStatements {
		if _, hasProjectPath := top["project_path"]; !hasProjectPath {
			return "OpenVEX"
		}
	}
	if hasStringValue(top, "bomFormat", "CycloneDX") {
		return "CycloneDX"
	}
	if _, ok := top["spdxVersion"]; ok {
		return "SPDX"
	}
	if hasStringValue(top, "version", "2.1.0") {
		if _, ok := top["runs"]; ok {
			return "SARIF"
		}
	}
	return ""
}

func hasStringValue(top map[string]json.RawMessage, field, want string) bool {
	raw, ok := top[field]
	if !ok {
		return false
	}
	var got string
	if err := json.Unmarshal(raw, &got); err != nil {
		return false
	}
	return strings.EqualFold(got, want)
}
