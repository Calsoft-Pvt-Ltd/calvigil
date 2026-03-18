package iac

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanTerraformSecurityGroup(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "main.tf", `resource "aws_security_group" "open" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 22
    to_port     = 22
  }
}
`)
	result, err := Scan(dir, false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(result.Findings))
	}
	foundIDs := make(map[string]bool)
	for _, f := range result.Findings {
		foundIDs[f.Rule.ID] = true
	}
	for _, id := range []string{"IAC-001", "IAC-007"} {
		if !foundIDs[id] {
			t.Errorf("expected to find %s", id)
		}
	}
}

func TestScanTerraformS3Public(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "s3.tf", `resource "aws_s3_bucket" "public" {
  acl = "public-read"
}
`)
	result, err := Scan(dir, false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Rule.ID == "IAC-002" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-002 (S3 public ACL)")
	}
}

func TestScanKubernetesPrivileged(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "deploy.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure
spec:
  template:
    spec:
      containers:
        - name: app
          securityContext:
            privileged: true
            runAsUser: 0
      hostNetwork: true
      hostPID: true
`)
	result, err := Scan(dir, false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	foundIDs := make(map[string]bool)
	for _, f := range result.Findings {
		foundIDs[f.Rule.ID] = true
	}
	for _, id := range []string{"IAC-008", "IAC-009", "IAC-011", "IAC-013"} {
		if !foundIDs[id] {
			t.Errorf("expected to find %s", id)
		}
	}
}

func TestScanDockerfile(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "Dockerfile", `FROM ubuntu:latest
ADD ./app /opt/app
RUN curl https://example.com/install.sh | bash
USER root
`)
	result, err := Scan(dir, false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	foundIDs := make(map[string]bool)
	for _, f := range result.Findings {
		foundIDs[f.Rule.ID] = true
	}
	for _, id := range []string{"IAC-014", "IAC-015", "IAC-016", "IAC-017"} {
		if !foundIDs[id] {
			t.Errorf("expected to find %s", id)
		}
	}
}

func TestScanEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	result, err := Scan(dir, false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings in empty dir, got %d", len(result.Findings))
	}
}

func TestScanSingleFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "main.tf", `resource "aws_db_instance" "db" {
  storage_encrypted = false
}
`)
	result, err := Scan(path, false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Error("expected at least 1 finding for encrypted=false")
	}
	found := false
	for _, f := range result.Findings {
		if f.Rule.ID == "IAC-005" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-005 (RDS storage not encrypted)")
	}
}

func TestToVulnerabilities(t *testing.T) {
	findings := []Finding{
		{
			Rule: IaCRule{
				ID:          "IAC-001",
				Name:        "Test Rule",
				Description: "Test description",
				Severity:    "HIGH",
				Category:    "Terraform",
			},
			FilePath: "/project/main.tf",
			Line:     10,
			Content:  "cidr_blocks = [\"0.0.0.0/0\"]",
		},
	}
	vulns := ToVulnerabilities(findings, "/project")
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	v := vulns[0]
	if v.ID != "IAC-001" {
		t.Errorf("expected IAC-001, got %s", v.ID)
	}
	if v.Source != "iac" {
		t.Errorf("expected source iac, got %s", v.Source)
	}
	if v.FilePath != "main.tf" {
		t.Errorf("expected main.tf, got %s", v.FilePath)
	}
	if v.StartLine != 10 {
		t.Errorf("expected line 10, got %d", v.StartLine)
	}
}

func TestIsIaCFile(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"main.tf", true},
		{"vars.tfvars", true},
		{"deploy.yaml", true},
		{"deploy.yml", true},
		{"Dockerfile", true},
		{"Dockerfile.prod", true},
		{"docker-compose.yml", true},
		{"docker-compose.yaml", true},
		{"app.go", false},
		{"README.md", false},
		{"config.json", false},
	}
	for _, tt := range tests {
		got := isIaCFile(tt.path)
		if got != tt.expect {
			t.Errorf("isIaCFile(%q) = %v, want %v", tt.path, got, tt.expect)
		}
	}
}

func TestCategories(t *testing.T) {
	files := []ScannedFile{
		{Category: "Terraform"},
		{Category: "Kubernetes"},
		{Category: "Terraform"},
		{Category: "Dockerfile"},
	}
	cats := Categories(files)
	if len(cats) != 3 {
		t.Errorf("expected 3 unique categories, got %d: %v", len(cats), cats)
	}
}

func TestRuleApplies(t *testing.T) {
	tfRule := IaCRule{FileTypes: []string{".tf"}}
	dfRule := IaCRule{FileTypes: []string{"Dockerfile"}}
	yamlRule := IaCRule{FileTypes: []string{".yaml", ".yml"}}

	if !ruleApplies(tfRule, "main.tf", ".tf") {
		t.Error("tf rule should apply to .tf")
	}
	if ruleApplies(tfRule, "deploy.yaml", ".yaml") {
		t.Error("tf rule should not apply to .yaml")
	}
	if !ruleApplies(dfRule, "Dockerfile", "") {
		t.Error("dockerfile rule should apply to Dockerfile")
	}
	if !ruleApplies(dfRule, "Dockerfile.prod", ".prod") {
		t.Error("dockerfile rule should apply to Dockerfile.prod")
	}
	if ruleApplies(dfRule, "main.tf", ".tf") {
		t.Error("dockerfile rule should not apply to .tf")
	}
	if !ruleApplies(yamlRule, "deploy.yaml", ".yaml") {
		t.Error("yaml rule should apply to .yaml")
	}
}
