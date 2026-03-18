package analyzer

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

// PatternRule defines a regex-based vulnerability detection rule.
type PatternRule struct {
	ID          string
	Name        string
	Description string
	Severity    models.Severity
	Pattern     *regexp.Regexp
	Languages   []string // file extensions this rule applies to (e.g., ".go", ".py")
}

// knownPatterns contains regex rules for common vulnerability patterns across languages.
var knownPatterns = []PatternRule{
	// SQL Injection
	// Requires SQL keywords to be followed by SQL-specific syntax to avoid false
	// positives on log messages like fmt.Sprintf("Failed to update alias...").
	{
		ID:          "SEC-001",
		Name:        "Potential SQL Injection",
		Description: "String concatenation or formatting used in SQL query construction. Use parameterized queries instead.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:fmt\.Sprintf|\.format\s*\(|String\.format|["'].*%[sdvq].*["']|["'].*\+.*["']).*(?:SELECT\s+(?:\*|\w+\s*,).+\bFROM\b|INSERT\s+INTO\b|UPDATE\s+\w+\s+SET\b|DELETE\s+FROM\b|DROP\s+(?:TABLE|DATABASE|INDEX)\b|ALTER\s+TABLE\b|CREATE\s+(?:TABLE|INDEX|DATABASE)\b)`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".rs"},
	},
	{
		ID:          "SEC-002",
		Name:        "Potential SQL Injection (string concat)",
		Description: "SQL query built with string concatenation. Use parameterized queries instead.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:query|sql|stmt)\s*(?:=|\+=)\s*["'].*(?:SELECT\s+(?:\*|\w+\s*,).+\bFROM\b|INSERT\s+INTO\b|UPDATE\s+\w+\s+SET\b|DELETE\s+FROM\b).*["']\s*\+`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php"},
	},

	// Command Injection
	{
		ID:          "SEC-003",
		Name:        "Potential Command Injection",
		Description: "User input may be passed to a system command execution function. Validate and sanitize all inputs.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)(?:exec\.Command|os\.system|subprocess\.(?:call|run|Popen)|child_process\.exec|Runtime\.getRuntime\(\)\.exec|system\s*\(|` + "`" + `.*\$|shell_exec\s*\(|passthru\s*\(|popen\s*\()\s*\(`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".c", ".cpp"},
	},

	// Path Traversal
	{
		ID:          "SEC-004",
		Name:        "Potential Path Traversal",
		Description: "File path constructed from user input without sanitization. Validate paths against a base directory.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:os\.(?:Open|ReadFile|Create)|open\(|new\s+File(?:Input|Output)Stream|fs\.(?:readFile|writeFile|createReadStream)|fopen\s*\(|File\.open\s*\()\s*\(\s*(?:.*\+|.*fmt\.Sprintf|.*format|.*path\.join.*req)`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".c", ".cpp"},
	},

	// Hardcoded Secrets
	{
		ID:          "SEC-005",
		Name:        "Hardcoded Secret or API Key",
		Description: "A secret, password, or API key appears to be hardcoded. Use environment variables or a secrets manager.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:password|passwd|secret|api[_-]?key|auth[_-]?token|private[_-]?key|access[_-]?key)\s*(?:=|:)\s*["\'][^"\']{8,}["\']`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".rs", ".yaml", ".yml", ".json", ".env", ".properties"},
	},
	{
		ID:          "SEC-006",
		Name:        "AWS Access Key",
		Description: "Potential AWS access key ID found in source code. Use IAM roles or environment variables.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".rs", ".yaml", ".yml", ".json", ".env", ".properties"},
	},

	// Insecure Cryptography
	{
		ID:          "SEC-007",
		Name:        "Weak Cryptographic Hash",
		Description: "MD5 or SHA1 used for security purposes. Use SHA-256 or stronger algorithms.",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(?:md5\.(?:New|Sum)|hashlib\.md5|MessageDigest\.getInstance\s*\(\s*["\']MD5["\']|crypto\.createHash\s*\(\s*["\']md5["\']|sha1\.(?:New|Sum)|hashlib\.sha1|MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']|crypto\.createHash\s*\(\s*["\']sha1["\']|Digest::MD5|Digest::SHA1|md5\s*\(|MD5_Init|SHA1_Init)`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".c", ".cpp", ".rs"},
	},

	// XSS
	{
		ID:          "SEC-008",
		Name:        "Potential Cross-Site Scripting (XSS)",
		Description: "User input rendered without escaping in HTML template. Use proper escaping or a templating engine with auto-escaping.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:innerHTML\s*=|\.html\s*\(|document\.write\s*\(|v-html\s*=|dangerouslySetInnerHTML|\{\{!\s*|template\.HTML\(|\.html_safe|raw\s*\(|echo\s+\$_)`),
		Languages:   []string{".go", ".js", ".ts", ".jsx", ".tsx", ".html", ".vue", ".rb", ".erb", ".php"},
	},

	// Insecure HTTP
	{
		ID:          "SEC-009",
		Name:        "Insecure HTTP URL",
		Description: "HTTP (not HTTPS) URL found. Use HTTPS for all external communications.",
		Severity:    models.SeverityLow,
		Pattern:     regexp.MustCompile(`http://[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".rs"},
	},

	// Insecure TLS
	{
		ID:          "SEC-010",
		Name:        "TLS Certificate Verification Disabled",
		Description: "TLS certificate verification is disabled. This allows man-in-the-middle attacks.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)(?:InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|CERT_NONE|rejectUnauthorized\s*:\s*false|setHostnameVerifier|verify_peer\s*=>\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0))`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php"},
	},

	// Deserialization
	{
		ID:          "SEC-011",
		Name:        "Potential Insecure Deserialization",
		Description: "Deserializing untrusted data can lead to remote code execution. Validate input before deserialization.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:pickle\.loads?|yaml\.(?:load|unsafe_load)\s*\(|ObjectInputStream|eval\s*\(|unserialize\s*\(|Marshal\.load)`),
		Languages:   []string{".py", ".java", ".js", ".ts", ".php", ".rb"},
	},

	// CORS Misconfiguration
	{
		ID:          "SEC-012",
		Name:        "Permissive CORS Configuration",
		Description: "Access-Control-Allow-Origin set to wildcard (*). Restrict to specific trusted origins.",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(?:Access-Control-Allow-Origin["\s:]*\*|cors\(\s*\)|AllowAllOrigins\s*:\s*true)`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php"},
	},

	// Rust-specific: unsafe blocks
	{
		ID:          "SEC-013",
		Name:        "Unsafe Rust Block",
		Description: "Unsafe block bypasses Rust's safety guarantees. Review carefully for memory safety issues.",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`\bunsafe\s*\{`),
		Languages:   []string{".rs"},
	},

	// C/C++: buffer overflow risk
	{
		ID:          "SEC-014",
		Name:        "Potential Buffer Overflow (C/C++)",
		Description: "Use of unsafe C functions that don't check buffer bounds. Use bounded alternatives (strncpy, snprintf, etc.).",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`\b(?:strcpy|strcat|sprintf|gets|scanf)\s*\(`),
		Languages:   []string{".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"},
	},

	// C/C++: format string vulnerability
	{
		ID:          "SEC-015",
		Name:        "Format String Vulnerability (C/C++)",
		Description: "User-controlled string passed directly to printf-family function. Always use a format specifier.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`\b(?:printf|fprintf|sprintf|snprintf|syslog)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)`),
		Languages:   []string{".c", ".cpp", ".cc", ".cxx"},
	},

	// PHP-specific: file include
	{
		ID:          "SEC-016",
		Name:        "PHP Remote File Inclusion",
		Description: "Dynamic file inclusion with user input can lead to code execution. Validate and whitelist allowed files.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)(?:include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`),
		Languages:   []string{".php"},
	},

	// Ruby-specific: mass assignment
	{
		ID:          "SEC-017",
		Name:        "Ruby Mass Assignment",
		Description: "Passing unsanitized params to create/update may allow mass assignment. Use strong parameters.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?:\.create|\.update|\.new)\s*\(\s*params(?:\b|[^_])`),
		Languages:   []string{".rb"},
	},
}

// sourceExtensions defines which file extensions to scan for source code analysis.
var sourceExtensions = map[string]bool{
	".go": true, ".py": true, ".java": true,
	".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".vue": true, ".html": true,
	".yaml": true, ".yml": true, ".json": true,
	".env": true, ".properties": true,
	// Rust
	".rs": true,
	// Ruby
	".rb": true, ".erb": true,
	// C/C++
	".c": true, ".h": true, ".cpp": true, ".cc": true, ".cxx": true, ".hpp": true,
	// PHP
	".php": true,
}

// skipDirs are directories to skip during source code scanning.
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true,
	"__pycache__": true, ".idea": true, ".vscode": true,
	"target": true, "build": true, "dist": true,
	".next": true, ".nuxt": true,
	// Python virtual environments
	".venv": true, "venv": true, ".env": true, "env": true,
	"site-packages": true, ".tox": true, ".nox": true,
	// Ruby, Rust, Go caches
	".bundle": true, ".cargo": true, ".cache": true,
	// Other build/output directories
	"out": true, "bin": true, "obj": true, "lib": true,
	".terraform": true, ".serverless": true,
}

// PatternMatch represents a match found by the pattern scanner.
type PatternMatch struct {
	Rule     PatternRule
	FilePath string
	Line     int
	Content  string
}

// ScanPatterns walks the project directory and runs all pattern rules against
// source files using a worker pool for concurrent file scanning.
func ScanPatterns(projectPath string) ([]PatternMatch, error) {
	const numWorkers = 8

	type fileJob struct {
		path string
		ext  string
	}

	jobs := make(chan fileJob, 64)
	results := make(chan []PatternMatch, 64)
	var wg sync.WaitGroup

	// Start worker goroutines.
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if m, err := scanFile(job.path, job.ext); err == nil && len(m) > 0 {
					results <- m
				}
			}
		}()
	}

	// Walk the tree and feed jobs.
	go func() {
		filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if skipDirs[info.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			ext := filepath.Ext(info.Name())
			if !sourceExtensions[ext] {
				return nil
			}
			if info.Size() > 1024*1024 {
				return nil
			}
			jobs <- fileJob{path: path, ext: ext}
			return nil
		})
		close(jobs)
	}()

	// Close results channel once all workers are done.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results.
	var matches []PatternMatch
	for batch := range results {
		matches = append(matches, batch...)
	}
	return matches, nil
}

func scanFile(filePath string, ext string) ([]PatternMatch, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var matches []PatternMatch
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, rule := range knownPatterns {
			// Check if this rule applies to this file extension
			if !ruleAppliesToExt(rule, ext) {
				continue
			}

			if rule.Pattern.MatchString(line) {
				matches = append(matches, PatternMatch{
					Rule:     rule,
					FilePath: filePath,
					Line:     lineNum,
					Content:  strings.TrimSpace(line),
				})
			}
		}
	}

	return matches, scanner.Err()
}

func ruleAppliesToExt(rule PatternRule, ext string) bool {
	for _, lang := range rule.Languages {
		if lang == ext {
			return true
		}
	}
	return false
}

// PatternMatchesToVulnerabilities converts pattern matches to vulnerability model objects.
func PatternMatchesToVulnerabilities(matches []PatternMatch) []models.Vulnerability {
	var vulns []models.Vulnerability
	for _, m := range matches {
		vulns = append(vulns, models.Vulnerability{
			ID:        m.Rule.ID,
			Summary:   m.Rule.Name,
			Details:   m.Rule.Description,
			Severity:  m.Rule.Severity,
			Source:    models.SourcePatternMatch,
			FilePath:  m.FilePath,
			StartLine: m.Line,
			EndLine:   m.Line,
			Snippet:   truncateSnippet(m.Content, 200),
		})
	}
	return vulns
}

func truncateSnippet(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return fmt.Sprintf("%s...", s[:maxLen])
}
