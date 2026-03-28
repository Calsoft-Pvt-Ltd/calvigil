package iac

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// IaCRule defines a regex-based IaC misconfiguration detection rule.
type IaCRule struct {
	ID          string
	Name        string
	Description string
	Severity    models.Severity
	Pattern     *regexp.Regexp
	FileTypes   []string // e.g., ".tf", "Dockerfile", ".yaml"
	Category    string   // e.g., "Terraform", "Kubernetes", "Dockerfile"
}

// Finding represents a single IaC misconfiguration finding.
type Finding struct {
	Rule     IaCRule
	FilePath string
	Line     int
	Content  string
}

// ScanResult holds the output of an IaC scan.
type ScanResult struct {
	Findings []Finding
	Files    []ScannedFile
}

// ScannedFile records an IaC file that was scanned.
type ScannedFile struct {
	Path     string
	Category string
	Findings int
}

// iacRules defines all built-in IaC misconfiguration rules.
var iacRules = []IaCRule{
	{
		ID:          "IAC-001",
		Name:        "Security Group -- Unrestricted Ingress",
		Description: "Security group allows unrestricted inbound access (0.0.0.0/0 or ::/0). Restrict to known CIDR ranges.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)cidr_blocks\s*=\s*\[.*"0\.0\.0\.0/0".*\]`),
		FileTypes:   []string{".tf"},
		Category:    "Terraform",
	},
	{
		ID:          "IAC-002",
		Name:        "S3 Bucket -- Public ACL",
		Description: "S3 bucket uses a public ACL (public-read, public-read-write). Use private ACL and bucket policies.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)acl\s*=\s*"public-read`),
		FileTypes:   []string{".tf"},
		Category:    "Terraform",
	},
	{
		ID:          "IAC-003",
		Name:        "S3 Bucket -- Server-Side Encryption Disabled",
		Description: "S3 bucket does not have server-side encryption configured. Enable AES-256 or KMS encryption.",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)resource\s+"aws_s3_bucket"\s+"\w+"\s*\{`),
		FileTypes:   []string{".tf"},
		Category:    "Terraform",
	},
	{
		ID:          "IAC-004",
		Name:        "IAM Policy -- Wildcard Actions",
		Description: "IAM policy grants wildcard actions (\"*\"). Follow the principle of least privilege.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)"Action"\s*:\s*(?:\[\s*)?"?\*"?`),
		FileTypes:   []string{".tf", ".json"},
		Category:    "Terraform",
	},
	{
		ID:          "IAC-005",
		Name:        "RDS -- Storage Not Encrypted",
		Description: "RDS instance does not enable storage encryption. Set storage_encrypted = true.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)storage_encrypted\s*=\s*false`),
		FileTypes:   []string{".tf"},
		Category:    "Terraform",
	},
	{
		ID:          "IAC-006",
		Name:        "CloudTrail -- Logging Disabled",
		Description: "CloudTrail logging is explicitly disabled. Enable multi-region trail for audit compliance.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)is_multi_region_trail\s*=\s*false`),
		FileTypes:   []string{".tf"},
		Category:    "Terraform",
	},
	{
		ID:          "IAC-007",
		Name:        "Security Group -- Unrestricted SSH",
		Description: "Security group allows SSH (port 22) from 0.0.0.0/0. Restrict to known IP ranges or use a bastion host.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)(?:from_port|to_port)\s*=\s*22`),
		FileTypes:   []string{".tf"},
		Category:    "Terraform",
	},
	{
		ID:          "IAC-008",
		Name:        "Kubernetes -- Privileged Container",
		Description: "Container runs in privileged mode, granting full host access. Remove privileged: true.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)privileged\s*:\s*true`),
		FileTypes:   []string{".yaml", ".yml"},
		Category:    "Kubernetes",
	},
	{
		ID:          "IAC-009",
		Name:        "Kubernetes -- Run As Root",
		Description: "Container explicitly runs as root (UID 0). Set runAsNonRoot: true or use a non-root user.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)runAsUser\s*:\s*0\b`),
		FileTypes:   []string{".yaml", ".yml"},
		Category:    "Kubernetes",
	},
	{
		ID:          "IAC-010",
		Name:        "Kubernetes -- Missing Resource Limits",
		Description: "Container has no CPU/memory limits. Set resource limits to prevent noisy-neighbor issues.",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)containers\s*:\s*$`),
		FileTypes:   []string{".yaml", ".yml"},
		Category:    "Kubernetes",
	},
	{
		ID:          "IAC-011",
		Name:        "Kubernetes -- Host Network Enabled",
		Description: "Pod uses the host network namespace. This bypasses network policies and exposes host ports.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)hostNetwork\s*:\s*true`),
		FileTypes:   []string{".yaml", ".yml"},
		Category:    "Kubernetes",
	},
	{
		ID:          "IAC-012",
		Name:        "Kubernetes -- Default Namespace",
		Description: "Resource deployed to the default namespace. Use dedicated namespaces for isolation.",
		Severity:    models.SeverityLow,
		Pattern:     regexp.MustCompile(`(?i)namespace\s*:\s*["']?default["']?\s*$`),
		FileTypes:   []string{".yaml", ".yml"},
		Category:    "Kubernetes",
	},
	{
		ID:          "IAC-013",
		Name:        "Kubernetes -- Host PID Enabled",
		Description: "Pod shares the host PID namespace. Processes in the container can see and signal host processes.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)hostPID\s*:\s*true`),
		FileTypes:   []string{".yaml", ".yml"},
		Category:    "Kubernetes",
	},
	{
		ID:          "IAC-014",
		Name:        "Dockerfile -- Running as Root",
		Description: "No USER instruction found or container runs as root. Add a USER directive with a non-root user.",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?m)^USER\s+root\s*$`),
		FileTypes:   []string{"Dockerfile"},
		Category:    "Dockerfile",
	},
	{
		ID:          "IAC-015",
		Name:        "Dockerfile -- Using latest Tag",
		Description: "Base image uses the :latest tag which is not reproducible. Pin to a specific version.",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?m)^FROM\s+\S+:latest\b`),
		FileTypes:   []string{"Dockerfile"},
		Category:    "Dockerfile",
	},
	{
		ID:          "IAC-016",
		Name:        "Dockerfile -- ADD Instead of COPY",
		Description: "Using ADD instruction which can auto-extract archives and fetch URLs. Prefer COPY for local files.",
		Severity:    models.SeverityLow,
		Pattern:     regexp.MustCompile(`(?m)^ADD\s+`),
		FileTypes:   []string{"Dockerfile"},
		Category:    "Dockerfile",
	},
	{
		ID:          "IAC-017",
		Name:        "Dockerfile -- Curl Pipe to Shell",
		Description: "Piping curl output to a shell is risky. Verify checksums instead.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)curl\s.*\|\s*(?:ba)?sh`),
		FileTypes:   []string{"Dockerfile"},
		Category:    "Dockerfile",
	},
	{
		ID:          "IAC-018",
		Name:        "CloudFormation -- Public S3 Bucket",
		Description: "S3 bucket has public access in CloudFormation template. Set AccessControl to Private.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)AccessControl\s*:\s*["']?Public`),
		FileTypes:   []string{".yaml", ".yml", ".json"},
		Category:    "CloudFormation",
	},
	{
		ID:          "IAC-019",
		Name:        "CloudFormation -- Open Security Group Ingress",
		Description: "Security group allows ingress from 0.0.0.0/0 in CloudFormation. Restrict CidrIp to known ranges.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)CidrIp\s*:\s*["']?0\.0\.0\.0/0`),
		FileTypes:   []string{".yaml", ".yml", ".json"},
		Category:    "CloudFormation",
	},
	{
		ID:          "IAC-020",
		Name:        "Docker Compose -- Privileged Mode",
		Description: "Service runs in privileged mode in docker-compose. Remove privileged: true.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)privileged\s*:\s*true`),
		FileTypes:   []string{".yaml", ".yml"},
		Category:    "Docker Compose",
	},

	// ── Helm Chart Rules ────────────────────────────────────────────────────

	{
		ID:          "IAC-021",
		Name:        "Helm -- Tiller Enabled (Helm 2)",
		Description: "Tiller is enabled in Helm chart. Helm 2 Tiller has cluster-admin and is a known attack surface. Migrate to Helm 3.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)(?:tiller|tillerNamespace|TILLER_NAMESPACE)`),
		FileTypes:   []string{".yaml", ".yml", ".tpl"},
		Category:    "Helm",
	},
	{
		ID:          "IAC-022",
		Name:        "Helm -- Container Uses latest Tag",
		Description: "Container image uses :latest or no tag in Helm template. Pin images to a specific version for reproducibility.",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)image\s*:\s*["']?[a-zA-Z0-9._/-]+(?::latest)?["']?\s*$`),
		FileTypes:   []string{".yaml", ".yml", ".tpl"},
		Category:    "Helm",
	},
	{
		ID:          "IAC-023",
		Name:        "Helm -- No Resource Limits",
		Description: "Helm template container has no resource limits. Set resources.limits to prevent resource exhaustion.",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)containers\s*:\s*$`),
		FileTypes:   []string{".yaml", ".yml", ".tpl"},
		Category:    "Helm",
	},
	{
		ID:          "IAC-024",
		Name:        "Helm -- Host Network Enabled",
		Description: "Helm chart enables host networking. This bypasses network policies and exposes host network stack.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)hostNetwork\s*:\s*true`),
		FileTypes:   []string{".yaml", ".yml", ".tpl"},
		Category:    "Helm",
	},
	{
		ID:          "IAC-025",
		Name:        "Helm -- Privileged Container",
		Description: "Helm chart runs container in privileged mode. This grants full host access. Remove privileged: true.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)privileged\s*:\s*true`),
		FileTypes:   []string{".yaml", ".yml", ".tpl"},
		Category:    "Helm",
	},
}

// skipDirs contains directories to skip during IaC scanning.
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true, "__pycache__": true,
	".terraform": true, ".terragrunt-cache": true, ".venv": true, "venv": true,
	".cache": true, ".idea": true, ".vscode": true, "dist": true, "build": true,
}

// iacExtensions maps file extensions to IaC categories.
var iacExtensions = map[string]string{
	".tf":     "Terraform",
	".tfvars": "Terraform",
	".yaml":   "Kubernetes/CloudFormation",
	".yml":    "Kubernetes/CloudFormation",
	// Note: .tpl is handled separately in isIaCFile/fileCategory (only matches in templates/ dirs).
}

// maxFileSize is the maximum size of a file to scan (2 MB).
const maxFileSize = 2 * 1024 * 1024

// Scan walks the given path and scans IaC files for misconfigurations.
func Scan(root string, verbose bool) (*ScanResult, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("cannot stat %s: %w", root, err)
	}

	result := &ScanResult{}

	if !info.IsDir() {
		findings, sf := scanFile(root, verbose)
		result.Findings = findings
		if sf != nil {
			result.Files = append(result.Files, *sf)
		}
		return result, nil
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	fileCh := make(chan string, 100)

	// Worker pool
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileCh {
				findings, sf := scanFile(path, false)
				if len(findings) > 0 || sf != nil {
					mu.Lock()
					result.Findings = append(result.Findings, findings...)
					if sf != nil {
						result.Files = append(result.Files, *sf)
					}
					mu.Unlock()
				}
			}
		}()
	}

	err = filepath.Walk(root, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if fi.IsDir() {
			if skipDirs[fi.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if fi.Size() == 0 || fi.Size() > maxFileSize {
			return nil
		}
		if isIaCFile(path) {
			fileCh <- path
		}
		return nil
	})

	close(fileCh)
	wg.Wait()

	return result, err
}

// isIaCFile returns true if the file is a recognized IaC file.
func isIaCFile(path string) bool {
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(path))

	// Dockerfiles
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
		return true
	}
	if base == "docker-compose.yml" || base == "docker-compose.yaml" {
		return true
	}

	// Helm chart files
	if base == "Chart.yaml" || base == "Chart.yml" || base == "values.yaml" || base == "values.yml" {
		return true
	}
	if ext == ".tpl" && strings.Contains(path, "templates") {
		return true
	}

	_, ok := iacExtensions[ext]
	return ok
}

// fileCategory returns the IaC category for a file path.
func fileCategory(path string) string {
	base := filepath.Base(path)
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
		return "Dockerfile"
	}
	if base == "docker-compose.yml" || base == "docker-compose.yaml" {
		return "Docker Compose"
	}
	// Helm charts: Chart.yaml, values.yaml, or .tpl files in templates/
	if base == "Chart.yaml" || base == "Chart.yml" || base == "values.yaml" || base == "values.yml" {
		return "Helm"
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".tpl" && strings.Contains(path, "templates") {
		return "Helm"
	}
	if cat, ok := iacExtensions[ext]; ok {
		return cat
	}
	return "Unknown"
}

// scanFile scans a single IaC file against all applicable rules.
func scanFile(path string, verbose bool) ([]Finding, *ScannedFile) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(path))
	cat := fileCategory(path)

	var findings []Finding
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, rule := range iacRules {
			if !ruleApplies(rule, base, ext) {
				continue
			}
			if rule.Pattern.MatchString(line) {
				findings = append(findings, Finding{
					Rule:     rule,
					FilePath: path,
					Line:     lineNum,
					Content:  strings.TrimSpace(line),
				})
			}
		}
	}

	if verbose && len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "   %s (%s) -- %d findings\n", base, cat, len(findings))
	}

	sf := &ScannedFile{
		Path:     path,
		Category: cat,
		Findings: len(findings),
	}
	return findings, sf
}

// ruleApplies checks if a rule should be applied to a given file.
func ruleApplies(rule IaCRule, baseName, ext string) bool {
	isDockerfile := baseName == "Dockerfile" || strings.HasPrefix(baseName, "Dockerfile.")
	for _, ft := range rule.FileTypes {
		if ft == "Dockerfile" && isDockerfile {
			return true
		}
		if ft == ext {
			return true
		}
	}
	return false
}

// ToVulnerabilities converts IaC findings to the standard Vulnerability model.
func ToVulnerabilities(findings []Finding, projectPath string) []models.Vulnerability {
	var vulns []models.Vulnerability
	for _, f := range findings {
		relPath, err := filepath.Rel(projectPath, f.FilePath)
		if err != nil {
			relPath = f.FilePath
		}
		vulns = append(vulns, models.Vulnerability{
			ID:          f.Rule.ID,
			Summary:     f.Rule.Name,
			Details:     f.Rule.Description,
			Severity:    f.Rule.Severity,
			Source:      models.SourceIaC,
			FilePath:    relPath,
			StartLine:   f.Line,
			EndLine:     f.Line,
			Snippet:     f.Content,
			MatchedRule: f.Rule.Category + ": " + f.Rule.ID,
		})
	}
	return vulns
}

// Categories returns the distinct IaC categories found in results.
func Categories(files []ScannedFile) []string {
	seen := make(map[string]bool)
	var cats []string
	for _, f := range files {
		if !seen[f.Category] {
			seen[f.Category] = true
			cats = append(cats, f.Category)
		}
	}
	return cats
}
