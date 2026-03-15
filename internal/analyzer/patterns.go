package analyzer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chavakula/calvigil/internal/models"
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
	{
		ID:          "SEC-001",
		Name:        "Potential SQL Injection",
		Description: "String concatenation or formatting used in SQL query construction. Use parameterized queries instead.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:fmt\.Sprintf|format|["\'].*%s.*["\']|["\'].*\+.*["\']).*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts"},
	},
	{
		ID:          "SEC-002",
		Name:        "Potential SQL Injection (string concat)",
		Description: "SQL query built with string concatenation. Use parameterized queries instead.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:query|sql|stmt)\s*(?:=|\+=)\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE)\b.*["\']\s*\+`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts"},
	},

	// Command Injection
	{
		ID:          "SEC-003",
		Name:        "Potential Command Injection",
		Description: "User input may be passed to a system command execution function. Validate and sanitize all inputs.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)(?:exec\.Command|os\.system|subprocess\.(?:call|run|Popen)|child_process\.exec|Runtime\.getRuntime\(\)\.exec)\s*\(`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts"},
	},

	// Path Traversal
	{
		ID:          "SEC-004",
		Name:        "Potential Path Traversal",
		Description: "File path constructed from user input without sanitization. Validate paths against a base directory.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:os\.(?:Open|ReadFile|Create)|open\(|new\s+File(?:Input|Output)Stream|fs\.(?:readFile|writeFile|createReadStream))\s*\(\s*(?:.*\+|.*fmt\.Sprintf|.*format|.*path\.join.*req)`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts"},
	},

	// Hardcoded Secrets
	{
		ID:          "SEC-005",
		Name:        "Hardcoded Secret or API Key",
		Description: "A secret, password, or API key appears to be hardcoded. Use environment variables or a secrets manager.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:password|passwd|secret|api[_-]?key|auth[_-]?token|private[_-]?key|access[_-]?key)\s*(?:=|:)\s*["\'][^"\']{8,}["\']`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".yaml", ".yml", ".json", ".env", ".properties"},
	},
	{
		ID:          "SEC-006",
		Name:        "AWS Access Key",
		Description: "Potential AWS access key ID found in source code. Use IAM roles or environment variables.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".yaml", ".yml", ".json", ".env", ".properties"},
	},

	// Insecure Cryptography
	{
		ID:          "SEC-007",
		Name:        "Weak Cryptographic Hash",
		Description: "MD5 or SHA1 used for security purposes. Use SHA-256 or stronger algorithms.",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(?:md5\.(?:New|Sum)|hashlib\.md5|MessageDigest\.getInstance\s*\(\s*["\']MD5["\']|crypto\.createHash\s*\(\s*["\']md5["\']|sha1\.(?:New|Sum)|hashlib\.sha1|MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']|crypto\.createHash\s*\(\s*["\']sha1["\'])`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts"},
	},

	// XSS
	{
		ID:          "SEC-008",
		Name:        "Potential Cross-Site Scripting (XSS)",
		Description: "User input rendered without escaping in HTML template. Use proper escaping or a templating engine with auto-escaping.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:innerHTML\s*=|\.html\s*\(|document\.write\s*\(|v-html\s*=|dangerouslySetInnerHTML|\{\{!\s*|template\.HTML\()`),
		Languages:   []string{".go", ".js", ".ts", ".jsx", ".tsx", ".html", ".vue"},
	},

	// Insecure HTTP
	{
		ID:          "SEC-009",
		Name:        "Insecure HTTP URL",
		Description: "HTTP (not HTTPS) URL found. Use HTTPS for all external communications.",
		Severity:    models.SeverityLow,
		Pattern:     regexp.MustCompile(`http://[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts"},
	},

	// Insecure TLS
	{
		ID:          "SEC-010",
		Name:        "TLS Certificate Verification Disabled",
		Description: "TLS certificate verification is disabled. This allows man-in-the-middle attacks.",
		Severity:    models.SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)(?:InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|CERT_NONE|rejectUnauthorized\s*:\s*false|setHostnameVerifier)`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts"},
	},

	// Deserialization
	{
		ID:          "SEC-011",
		Name:        "Potential Insecure Deserialization",
		Description: "Deserializing untrusted data can lead to remote code execution. Validate input before deserialization.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:pickle\.loads?|yaml\.(?:load|unsafe_load)\s*\(|ObjectInputStream|eval\s*\(|unserialize\s*\()`),
		Languages:   []string{".py", ".java", ".js", ".ts", ".php"},
	},

	// CORS Misconfiguration
	{
		ID:          "SEC-012",
		Name:        "Permissive CORS Configuration",
		Description: "Access-Control-Allow-Origin set to wildcard (*). Restrict to specific trusted origins.",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(?:Access-Control-Allow-Origin["\s:]*\*|cors\(\s*\)|AllowAllOrigins\s*:\s*true)`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts"},
	},
}

// sourceExtensions defines which file extensions to scan for source code analysis.
var sourceExtensions = map[string]bool{
	".go": true, ".py": true, ".java": true,
	".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".vue": true, ".html": true,
	".yaml": true, ".yml": true, ".json": true,
	".env": true, ".properties": true,
}

// skipDirs are directories to skip during source code scanning.
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true,
	"__pycache__": true, ".idea": true, ".vscode": true,
	"target": true, "build": true, "dist": true,
	".next": true, ".nuxt": true,
}

// PatternMatch represents a match found by the pattern scanner.
type PatternMatch struct {
	Rule     PatternRule
	FilePath string
	Line     int
	Content  string
}

// ScanPatterns walks the project directory and runs all pattern rules against source files.
func ScanPatterns(projectPath string) ([]PatternMatch, error) {
	var matches []PatternMatch

	err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
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

		// Skip files larger than 1MB
		if info.Size() > 1024*1024 {
			return nil
		}

		fileMatches, err := scanFile(path, ext)
		if err != nil {
			return nil // skip files that can't be read
		}
		matches = append(matches, fileMatches...)

		return nil
	})

	return matches, err
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
