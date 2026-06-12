package analyzer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/fsutil"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// PatternRule defines a regex-based vulnerability detection rule.
type PatternRule struct {
	ID          string
	Name        string
	Description string
	Severity    models.Severity
	Pattern     *regexp.Regexp
	Excludes    *regexp.Regexp // Optional: if the match also matches this, skip it (false-positive filter)
	Languages   []string       // file extensions this rule applies to (e.g., ".go", ".py")
}

// sqlSyntax is a shared set of SQL keyword patterns requiring follow-on SQL syntax
// to avoid matching natural language (e.g., "Failed to update" != "UPDATE users SET").
var sqlSyntax = `SELECT\s+(?:\*|\w+\s*,)[\s\w,*]*\bFROM\b` +
	`|INSERT\s+INTO\b` +
	`|UPDATE\s+\w+\s+SET\b` +
	`|DELETE\s+FROM\b` +
	`|DROP\s+(?:TABLE|DATABASE|INDEX)\b` +
	`|ALTER\s+TABLE\b` +
	`|CREATE\s+(?:TABLE|INDEX|DATABASE)\b`

// suppressionComment matches inline security suppression annotations commonly used
// by security linters: #nosec (gosec), nolint (golangci-lint), NOSONAR, nosemgrep.
var suppressionComment = regexp.MustCompile(`//\s*(?:#nosec|nolint|NOSONAR|nosemgrep)\b|#\s*(?:nosec|noqa)\b`)

// knownPatterns contains regex rules for common vulnerability patterns across languages.
var knownPatterns = []PatternRule{
	// SQL Injection
	// SQL keywords and interpolation markers (%s, %d, etc.) must appear in the
	// SAME string literal to avoid false positives when SQL-like words appear in
	// a separate argument (e.g., log.Infof("...%s...", "Create DATABASE")).
	{
		ID:          "SEC-001",
		Name:        "Potential SQL Injection",
		Description: "String concatenation or formatting used in SQL query construction. Use parameterized queries instead.",
		Severity:    models.SeverityHigh,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// SQL keyword before format specifier in double-quoted string
			`"[^"]*(?:` + sqlSyntax + `)[^"]*%[sdvq]` +
			// Format specifier before SQL keyword in double-quoted string
			`|"[^"]*%[sdvq][^"]*(?:` + sqlSyntax + `)` +
			// SQL keyword before format specifier in single-quoted string
			`|'[^']*(?:` + sqlSyntax + `)[^']*%[sdvq]` +
			// Format specifier before SQL keyword in single-quoted string
			`|'[^']*%[sdvq][^']*(?:` + sqlSyntax + `)` +
			// SQL keyword in double-quoted string being concatenated
			`|"[^"]*(?:` + sqlSyntax + `)[^"]*"\s*\+` +
			// SQL keyword in single-quoted string being concatenated
			`|'[^']*(?:` + sqlSyntax + `)[^']*'\s*\+` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".rs"},
	},
	{
		ID:          "SEC-002",
		Name:        "Potential SQL Injection (string concat)",
		Description: "SQL query built with string concatenation. Use parameterized queries instead.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:query|sql|stmt)\s*(?:=|\+=)\s*["'].*(?:` + sqlSyntax + `).*["']\s*\+`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php"},
	},

	// Command Injection
	// For Go's exec.Command, only flag shell invocations (sh/bash -c) or string
	// concatenation in arguments. Passing separate args is safe (no shell).
	{
		ID:          "SEC-003",
		Name:        "Potential Command Injection",
		Description: "User input may be passed to a system command execution function. Validate and sanitize all inputs.",
		Severity:    models.SeverityCritical,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// Go: exec.Command with shell invocation or string concat
			`exec\.Command\s*\(\s*"(?:sh|bash|cmd)"\s*,\s*"-c"` +
			`|exec\.Command\s*\(\s*(?:.*\+|.*fmt\.Sprintf)` +
			// Python
			`|os\.system\s*\(` +
			`|subprocess\.(?:call|run|Popen)\s*\(` +
			// JavaScript / Node.js
			`|child_process\.exec\s*\(` +
			// Java
			`|Runtime\.getRuntime\(\)\.exec\s*\(` +
			// C/C++/PHP shell execution
			`|(?:^|[^\w.])system\s*\(` +
			"|`" + `.*\$` +
			`|shell_exec\s*\(` +
			`|passthru\s*\(` +
			`|popen\s*\(` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".c", ".cpp"},
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

	// Hardcoded Secrets (SonarQube S6418 / CWE-798)
	{
		ID:          "SEC-005",
		Name:        "Hardcoded Secret or API Key",
		Description: "A secret, password, or API key appears to be hardcoded. Use environment variables or a secrets manager. (CWE-798)",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:password|passwd|secret|api[_-]?key|auth[_-]?token|private[_-]?key|access[_-]?key|client[_-]?secret|signing[_-]?key|encryption[_-]?key|database[_-]?password|db[_-]?password)\s*(?:=|:)\s*["\'][^"\']{8,}["\']`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".rs", ".yaml", ".yml", ".json", ".env", ".properties"},
	},
	{
		ID:          "SEC-006",
		Name:        "Cloud Provider Credential",
		Description: "Cloud provider credential or platform token found in source code. Use IAM roles, environment variables, or a secrets manager. (CWE-798)",
		Severity:    models.SeverityCritical,
		Pattern: regexp.MustCompile(`(?:` +
			// AWS access key
			`AKIA[0-9A-Z]{16}` +
			// GCP service account key
			`|"type"\s*:\s*"service_account"` +
			// Azure storage account key (base64, 88 chars)
			`|AccountKey\s*=\s*[A-Za-z0-9+/=]{44,}` +
			// GitHub personal access token
			`|ghp_[0-9a-zA-Z]{36}` +
			// GitLab personal/project access token
			`|glpat-[0-9a-zA-Z_-]{20,}` +
			// Slack bot/user token
			`|xox[bporas]-[0-9a-zA-Z-]+` +
			// Stripe secret key
			`|sk_live_[0-9a-zA-Z]{24,}` +
			// OpenAI API key
			`|sk-[0-9a-zA-Z]{20,}` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".rs", ".yaml", ".yml", ".json", ".env", ".properties"},
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
	// The raw() match uses [^\w.] prefix to avoid flagging ORM methods like
	// GORM's .Raw() or SQLAlchemy's .raw() — only standalone raw() (Rails).
	{
		ID:          "SEC-008",
		Name:        "Potential Cross-Site Scripting (XSS)",
		Description: "User input rendered without escaping in HTML template. Use proper escaping or a templating engine with auto-escaping.",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(?:innerHTML\s*=|\.html\s*\(|document\.write\s*\(|v-html\s*=|dangerouslySetInnerHTML|\{\{!\s*|template\.HTML\(|\.html_safe|(?:^|[^\w.])raw\s*\(|echo\s+\$_)`),
		Languages:   []string{".go", ".js", ".ts", ".jsx", ".tsx", ".html", ".vue", ".rb", ".erb", ".php"},
	},

	// Insecure HTTP (SonarQube S5332 / CWE-319)
	// Excludes localhost, 127.0.0.1, and well-known schema URIs to reduce false positives.
	{
		ID:          "SEC-009",
		Name:        "Insecure HTTP URL",
		Description: "HTTP (not HTTPS) URL found for external communication. Use HTTPS to prevent data interception. (CWE-319)",
		Severity:    models.SeverityLow,
		Pattern:     regexp.MustCompile(`http://[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.`),
		Excludes:    regexp.MustCompile(`(?i)http://(?:localhost[:/]|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|example\.com|example\.org|schemas\.|www\.w3\.org|xml\.org|xmlns\.)`),
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

	// Deserialization (SonarQube S5135 / CWE-502)
	{
		ID:          "SEC-011",
		Name:        "Potential Insecure Deserialization",
		Description: "Deserializing untrusted data can lead to remote code execution. Use safe alternatives (e.g., yaml.safe_load, JSON). (CWE-502)",
		Severity:    models.SeverityHigh,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// Python
			`pickle\.loads?\s*\(` +
			`|yaml\.(?:load|unsafe_load)\s*\(` +
			`|shelve\.open\s*\(` +
			// Java
			`|ObjectInputStream` +
			`|XMLDecoder\s*\(` +
			`|readObject\s*\(` +
			// JavaScript/Node.js
			`|eval\s*\(` +
			`|node-serialize` +
			`|serialize\.unserialize\s*\(` +
			// PHP
			`|unserialize\s*\(` +
			// Ruby
			`|Marshal\.load` +
			`|YAML\.load\s*\(` +
			// .NET
			`|BinaryFormatter\.Deserialize` +
			`|JsonConvert\.DeserializeObject\s*\(` +
			`)`),
		Languages: []string{".py", ".java", ".js", ".ts", ".php", ".rb", ".cs"},
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

	// ── SonarQube-aligned rules ─────────────────────────────────────────────

	// Insecure Random (SonarQube S2245 / CWE-330)
	{
		ID:          "SEC-018",
		Name:        "Insecure Random Number Generator",
		Description: "Non-cryptographic random generator used in a security context. Use crypto/rand (Go), secrets (Python), SecureRandom (Java), or crypto.getRandomValues (JS). (CWE-330)",
		Severity:    models.SeverityMedium,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// Go: math/rand functions (crypto/rand uses different names)
			`rand\.(?:Intn|Int31|Int63|Float32|Float64|Perm|Shuffle)\s*\(` +
			`|rand\.New\s*\(` +
			// Python: random module (not secrets)
			`|random\.(?:random|randint|choice|sample|uniform|randrange|shuffle)\s*\(` +
			// Java: java.util.Random (not SecureRandom)
			`|new\s+Random\s*\(` +
			`|Math\.random\s*\(` +
			// JavaScript: Math.random
			`|Math\.random\(\)` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php"},
	},

	// Weak Cipher Algorithm (SonarQube S5547 / CWE-327)
	{
		ID:          "SEC-019",
		Name:        "Weak Cipher Algorithm",
		Description: "DES, 3DES, RC4, or Blowfish are broken or insufficient. Use AES-256-GCM or ChaCha20-Poly1305. (CWE-327)",
		Severity:    models.SeverityHigh,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// Go
			`des\.NewCipher\s*\(` +
			`|des\.NewTripleDESCipher\s*\(` +
			`|rc4\.NewCipher\s*\(` +
			// Python (PyCryptodome)
			`|DES\.new\s*\(` +
			`|DES3\.new\s*\(` +
			`|ARC4\.new\s*\(` +
			`|Blowfish\.new\s*\(` +
			// Java
			`|Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|RC4|RC2|Blowfish|AES/ECB)` +
			// JavaScript/Node.js
			`|crypto\.create(?:Cipher|Decipher)(?:iv)?\s*\(\s*["'](?:des|des-ede3|rc4|bf|aes-\d+-ecb)` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".c", ".cpp", ".rs"},
	},

	// XML External Entity (XXE) (SonarQube S2755 / CWE-611)
	{
		ID:          "SEC-020",
		Name:        "XML External Entity (XXE) Processing",
		Description: "XML parser may process external entities, enabling XXE attacks. Disable external entity resolution. (CWE-611)",
		Severity:    models.SeverityHigh,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// Java: vulnerable XML parsers without feature flags
			`DocumentBuilderFactory\.newInstance\s*\(` +
			`|SAXParserFactory\.newInstance\s*\(` +
			`|XMLInputFactory\.newInstance\s*\(` +
			`|TransformerFactory\.newInstance\s*\(` +
			`|SchemaFactory\.newInstance\s*\(` +
			// Python: vulnerable parsers
			`|xml\.etree\.ElementTree\.parse\s*\(` +
			`|xml\.sax\.parse\s*\(` +
			`|lxml\.etree\.parse\s*\(` +
			`|pulldom\.parse\s*\(` +
			// Go: xml.NewDecoder without entity disabling
			`|xml\.NewDecoder\s*\(` +
			// PHP
			`|simplexml_load_string\s*\(` +
			`|simplexml_load_file\s*\(` +
			`|DOMDocument\s*\(` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".php", ".xml"},
	},

	// JWT Misconfiguration (SonarQube S3649 / CWE-345)
	{
		ID:          "SEC-021",
		Name:        "JWT Verification Disabled or Algorithm None",
		Description: "JWT decoded without signature verification or with algorithm 'none'. Always verify JWT signatures with a strong algorithm. (CWE-345)",
		Severity:    models.SeverityCritical,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// Python: jwt.decode without verification
			`jwt\.decode\s*\([^)]*verify\s*=\s*False` +
			`|jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*"verify_signature"\s*:\s*False` +
			// Algorithm none
			`|algorithms?\s*[:=]\s*\[?\s*["']none["']` +
			// JavaScript: jwt.decode (not jwt.verify)
			`|jwt\.decode\s*\(` +
			// Go: jwt.Parse without key function returning error
			`|jwt\.Parse\s*\([^,]+,\s*nil` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php"},
	},

	// Debug Mode in Production (SonarQube S4507 / CWE-489)
	{
		ID:          "SEC-022",
		Name:        "Debug Mode Enabled",
		Description: "Debug or development mode is enabled. This may expose stack traces, internal paths, or enable unsafe features in production. (CWE-489)",
		Severity:    models.SeverityMedium,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// Python Flask/Django
			`app\.run\s*\([^)]*debug\s*=\s*True` +
			`|DEBUG\s*=\s*True` +
			// Java Spring
			`|server\.error\.include-stacktrace\s*=\s*always` +
			// Node.js Express
			`|app\.use\s*\(\s*errorHandler\s*\(` +
			// PHP
			`|display_errors\s*=\s*(?:On|1|true)` +
			`|error_reporting\s*\(\s*E_ALL` +
			// Go Gin
			`|gin\.SetMode\s*\(\s*gin\.DebugMode` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".ini", ".properties"},
	},

	// Empty Catch Block (SonarQube S1166 / CWE-390)
	{
		ID:          "SEC-023",
		Name:        "Empty Error Handler",
		Description: "Catch/except block is empty, silently swallowing errors. Handle or log errors to avoid hidden failures. (CWE-390)",
		Severity:    models.SeverityLow,
		Pattern: regexp.MustCompile(`(?:` +
			// Java/JS/TS: catch (Exception e) {}
			`catch\s*\([^)]*\)\s*\{\s*\}` +
			// Python: except:\n    pass
			`|except[^:]*:\s*$` +
			// Go: if err != nil { return nil }
			`|if\s+err\s*!=\s*nil\s*\{\s*\}` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php"},
	},

	// Server-Side Request Forgery (SonarQube S5144 / CWE-918)
	{
		ID:          "SEC-024",
		Name:        "Potential Server-Side Request Forgery (SSRF)",
		Description: "HTTP request URL constructed from user input or variable. Validate and restrict allowed URLs/hosts. (CWE-918)",
		Severity:    models.SeverityHigh,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// Go: http.Get/Post with variable (not string literal)
			`http\.(?:Get|Post|Head)\s*\(\s*[a-zA-Z_]` +
			`|http\.NewRequest\s*\([^,]+,\s*[a-zA-Z_]` +
			// Python: requests with variable
			`|requests\.(?:get|post|put|delete|patch|head)\s*\(\s*[a-zA-Z_]` +
			`|urllib\.request\.urlopen\s*\(\s*[a-zA-Z_]` +
			// Java: URL from variable
			`|new\s+URL\s*\(\s*[a-zA-Z_]` +
			// JavaScript: fetch/axios with variable
			`|fetch\s*\(\s*[a-zA-Z_]` +
			`|axios\.(?:get|post|put|delete)\s*\(\s*[a-zA-Z_]` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php"},
	},

	// Open Redirect (SonarQube S5146 / CWE-601)
	{
		ID:          "SEC-025",
		Name:        "Potential Open Redirect",
		Description: "Redirect URL taken from user input without validation. Validate redirect targets against an allowlist. (CWE-601)",
		Severity:    models.SeverityMedium,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// Go: http.Redirect with request param
			`http\.Redirect\s*\([^,]+,[^,]+,\s*r\.` +
			`|http\.Redirect\s*\([^,]+,[^,]+,\s*req\.` +
			// Python: redirect with request param
			`|redirect\s*\(\s*request\.(?:GET|POST|args|form|params)` +
			// Java Spring
			`|redirect:\s*"\s*\+\s*` +
			// JavaScript/Express
			`|res(?:ponse)?\.redirect\s*\(\s*req\.` +
			// PHP
			`|header\s*\(\s*["']Location:\s*["']\s*\.\s*\$_` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php"},
	},

	// ── Enhanced Secret Scanning ────────────────────────────────────────────

	// Private Key in Source (CWE-321)
	{
		ID:          "SEC-026",
		Name:        "Private Key Detected",
		Description: "Private key (RSA, EC, PGP, or SSH) found in source. Store private keys in a secrets manager or encrypted vault, never in code. (CWE-321)",
		Severity:    models.SeverityCritical,
		Pattern: regexp.MustCompile(`(?:` +
			`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----` +
			`|-----BEGIN\s+EC\s+PRIVATE\s+KEY-----` +
			`|-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----` +
			`|-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----` +
			`|-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".rs", ".yaml", ".yml", ".json", ".env", ".properties", ".pem", ".key"},
	},

	// Database Connection String with Credentials (CWE-798)
	{
		ID:          "SEC-027",
		Name:        "Database Connection String with Credentials",
		Description: "Connection string with embedded credentials found. Use environment variables or a secrets manager for database credentials. (CWE-798)",
		Severity:    models.SeverityHigh,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// MongoDB
			`mongodb(?:\+srv)?://[^/\s]+:[^@\s]+@` +
			// PostgreSQL
			`|postgres(?:ql)?://[^/\s]+:[^@\s]+@` +
			// MySQL
			`|mysql://[^/\s]+:[^@\s]+@` +
			// Redis
			`|redis://:[^@\s]+@` +
			// MSSQL / SQL Server
			`|Server\s*=\s*[^;]+;\s*.*Password\s*=\s*[^;]+` +
			// AMQP (RabbitMQ)
			`|amqps?://[^/\s]+:[^@\s]+@` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".rs", ".yaml", ".yml", ".json", ".env", ".properties", ".xml", ".cs"},
	},

	// Bearer/Auth Token in Source (CWE-798)
	{
		ID:          "SEC-028",
		Name:        "Hardcoded Bearer or Auth Token",
		Description: "A bearer or authorization token appears to be hardcoded. Use environment variables or a secrets manager. (CWE-798)",
		Severity:    models.SeverityHigh,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// Authorization header with Bearer token
			`["']Authorization["']\s*[:=]\s*["']Bearer\s+[a-zA-Z0-9._~+/=-]{20,}` +
			// Generic token variable assignments
			`|(?:bearer_token|auth_token|access_token|refresh_token)\s*(?:=|:)\s*["'][a-zA-Z0-9._~+/=-]{20,}["']` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".rs"},
	},

	// Generic High-Entropy Secret (CWE-798)
	{
		ID:          "SEC-029",
		Name:        "Generic API Key or Secret",
		Description: "Variable named 'key', 'secret', or 'token' assigned a long string that may be a credential. Review and move to a secrets manager. (CWE-798)",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(?:api_key|api_secret|secret_key|token_secret|service_key|master_key)\s*(?:=|:)\s*["'][a-zA-Z0-9+/=_-]{20,}["']`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php", ".rs", ".yaml", ".yml", ".json", ".env", ".properties"},
	},

	// ── AI-Generated Code Anti-Patterns ─────────────────────────────────────
	// These rules detect common mistakes introduced by AI code generators
	// (Copilot, ChatGPT, Claude, etc.) that may compile but are insecure,
	// inefficient, or violate best practices.

	// Resource Leak: HTTP response body not closed (Go) (CWE-404)
	{
		ID:          "AI-SEC-001",
		Name:        "HTTP Response Body Not Closed (Go)",
		Description: "AI-generated code often forgets to close HTTP response bodies, causing resource leaks and connection pool exhaustion. Always defer resp.Body.Close() after checking err. (CWE-404)",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?:http\.(?:Get|Post|Head|Do)\s*\([^)]*\))\s*$`),
		Excludes:    regexp.MustCompile(`defer\s+.*\.Body\.Close|resp\.Body\.Close`),
		Languages:   []string{".go"},
	},

	// Resource Leak: File/connection opened in loop without close (CWE-404)
	{
		ID:          "AI-SEC-002",
		Name:        "Resource Opened in Loop Without Close",
		Description: "Opening files, connections, or handles inside a loop without closing them in the same iteration causes resource exhaustion. AI-generated code frequently misses this. (CWE-404)",
		Severity:    models.SeverityMedium,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// Go: os.Open/Create in loop context
			`for\s.*\{[^}]*os\.(?:Open|Create)\s*\(` +
			// Python: open() in loop
			`|for\s+\w+\s+in\s+.*:\s*\n\s*.*open\s*\(` +
			// Java: new FileInputStream/connection in loop
			`|for\s*\([^)]*\)\s*\{[^}]*new\s+(?:File(?:Input|Output)Stream|BufferedReader|Connection)` +
			`)`),
		Languages: []string{".go", ".py", ".java"},
	},

	// Race Condition: Shared map without mutex (Go) (CWE-362)
	{
		ID:          "AI-SEC-003",
		Name:        "Concurrent Map Access Without Synchronization (Go)",
		Description: "AI-generated Go code often uses maps in goroutines without sync.Mutex or sync.Map, causing fatal concurrent map writes. Use sync.Map or protect with a mutex. (CWE-362)",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`go\s+func\s*\([^)]*\)\s*\{[^}]*\w+\s*\[\s*\w+\s*\]\s*=`),
		Languages:   []string{".go"},
	},

	// Race Condition: Goroutine capturing loop variable (Go) (CWE-362)
	{
		ID:          "AI-SEC-004",
		Name:        "Goroutine Captures Loop Variable (Go)",
		Description: "AI-generated Go code frequently launches goroutines inside loops that capture the loop variable by reference. All goroutines end up using the last value. Pass the variable as a parameter. (CWE-362)",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile(`for\s+(?:_\s*,\s*)?(\w+)\s*(?::=|=)\s*range\b[^{]*\{[^}]*go\s+(?:func\s*\(|(\w+)\s*\()`),
		Languages:   []string{".go"},
	},

	// Inefficient Algorithm: Nested loop on same collection (CWE-407)
	{
		ID:          "AI-SEC-005",
		Name:        "Potential O(n²) Nested Loop",
		Description: "Nested iteration over the same or similar collections suggests O(n²) complexity. AI generators often produce brute-force approaches. Consider using a map/set for O(n) lookup. (CWE-407)",
		Severity:    models.SeverityLow,
		Pattern: regexp.MustCompile(`(?:` +
			// Go: two range loops close together (heuristic)
			`for\s+\w+\s*,?\s*\w*\s*:=\s*range\s+\w+\s*\{[^}]*for\s+\w+\s*,?\s*\w*\s*:=\s*range\s+\w+` +
			// Python: nested for-in loops
			`|for\s+\w+\s+in\s+\w+\s*:[^\n]*\n\s+for\s+\w+\s+in\s+\w+` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts"},
	},

	// Inefficient: String concatenation in loop (CWE-400)
	{
		ID:          "AI-SEC-006",
		Name:        "String Concatenation in Loop",
		Description: "Building strings with += in a loop creates O(n²) allocations. AI-generated code commonly does this. Use strings.Builder (Go), StringBuilder (Java), list join (Python), or array join (JS). (CWE-400)",
		Severity:    models.SeverityLow,
		Pattern: regexp.MustCompile(`(?:` +
			// Go: result += or result = result + inside loop
			`for\s[^{]*\{[^}]*\w+\s*\+=\s*(?:fmt\.Sprintf|string\(|"[^"]*"\s*\+)` +
			// Python: result += "..." in for loop
			`|for\s+\w+\s+in\s+[^:]*:\s*\n\s*\w+\s*\+=\s*["'f]` +
			// Java: str += inside for loop
			`|for\s*\([^)]*\)\s*\{[^}]*\w+\s*\+=\s*"` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts"},
	},

	// Error Handling: Ignored error return value (Go) (CWE-252)
	{
		ID:          "AI-SEC-007",
		Name:        "Ignored Error Return Value (Go)",
		Description: "AI-generated Go code often discards error return values with _ or by not capturing them. Unhandled errors hide bugs and can lead to security issues. (CWE-252)",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?:^|\s)(?:_\s*,\s*_\s*=|_\s*=)\s*\w+\.(?:Write|Read|Close|Flush|Exec|Query|Send|Seek|Remove|Mkdir|Chmod|Chown)\s*\(`),
		Languages:   []string{".go"},
	},

	// Error Handling: Overly broad exception catch (CWE-396)
	{
		ID:          "AI-SEC-008",
		Name:        "Overly Broad Exception Handler",
		Description: "Catching all exceptions (bare except, Exception, Throwable, Error) hides real bugs. AI generators often add catch-all handlers for convenience. Catch specific exception types. (CWE-396)",
		Severity:    models.SeverityMedium,
		Pattern: regexp.MustCompile(`(?:` +
			// Python: bare except or except Exception
			`except\s*:\s*$` +
			`|except\s+(?:Exception|BaseException)\s*(?:as\s+\w+)?:` +
			// Java: catch Throwable/Exception
			`|catch\s*\(\s*(?:Throwable|Exception)\s+\w+\s*\)` +
			// JavaScript: catch without specific error handling
			`|catch\s*\(\s*\w*\s*\)\s*\{\s*(?:console\.log|\/\/)` +
			`)`),
		Languages: []string{".py", ".java", ".js", ".ts"},
	},

	// Deprecated/Removed API Usage (CWE-477)
	{
		ID:          "AI-SEC-009",
		Name:        "Deprecated or Removed API Usage",
		Description: "AI models trained on older data often suggest deprecated or removed APIs. These may have known security issues or unexpected behavior in current versions. (CWE-477)",
		Severity:    models.SeverityMedium,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// Go deprecated APIs
			`io/ioutil` +
			`|ioutil\.(?:ReadAll|ReadFile|WriteFile|ReadDir|TempDir|TempFile|NopCloser|Discard)` +
			// Python deprecated
			`|from\s+distutils\b` +
			`|import\s+distutils` +
			`|from\s+imp\s+import` +
			`|import\s+imp\b` +
			`|from\s+optparse\s+import` +
			`|cgi\.escape\s*\(` +
			`|asyncio\.coroutine` +
			`|@asyncio\.coroutine` +
			// Node.js deprecated
			`|new\s+Buffer\s*\(` +
			`|require\s*\(\s*["'](?:domain|sys)["']\s*\)` +
			`|url\.parse\s*\(` +
			// Java deprecated
			`|new\s+Date\s*\(\s*["'][^"']+["']\s*\)` +
			`|Thread\.stop\s*\(` +
			`|Runtime\.runFinalizersOnExit` +
			`|System\.runFinalizersOnExit` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts"},
	},

	// Hardcoded IP/Port (common in AI-generated code) (CWE-547)
	{
		ID:          "AI-SEC-010",
		Name:        "Hardcoded Server Address",
		Description: "AI-generated code frequently hardcodes IP addresses and ports. Use configuration files or environment variables for deployment flexibility and security. (CWE-547)",
		Severity:    models.SeverityLow,
		Pattern:     regexp.MustCompile(`(?:Listen|Dial|connect|bind|serve)\s*\(\s*["'](?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|localhost):\d{2,5}["']`),
		Excludes:    regexp.MustCompile(`(?i)(?:test|spec|_test\.go|example|demo|localhost:0)`),
		Languages:   []string{".go", ".py", ".java", ".js", ".ts"},
	},

	// Unbounded allocation / missing pagination (CWE-770)
	{
		ID:          "AI-SEC-011",
		Name:        "Unbounded Data Loading",
		Description: "Loading all records without limit or pagination. AI-generated code often fetches unbounded data which causes OOM in production. Add LIMIT clauses or pagination. (CWE-770)",
		Severity:    models.SeverityMedium,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// SQL without LIMIT
			`SELECT\s+\*\s+FROM\s+\w+\s*["'\x60]\s*\)` +
			// Go: reading all into memory from unbounded source
			`|ioutil\.ReadAll\s*\(\s*(?:resp\.Body|r\.Body|req\.Body)` +
			`|io\.ReadAll\s*\(\s*(?:resp\.Body|r\.Body|req\.Body)` +
			// Python: fetchall without limit
			`|\.fetchall\s*\(\s*\)` +
			`)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts"},
	},

	// Insecure Default: Permissive file permissions (CWE-732)
	{
		ID:          "AI-SEC-012",
		Name:        "Overly Permissive File Permissions",
		Description: "AI-generated code often uses 0777 or 0666 file permissions. Use least-privilege: 0600 for secrets, 0644 for config, 0755 for executables. (CWE-732)",
		Severity:    models.SeverityMedium,
		Pattern: regexp.MustCompile(`(?:` +
			// Go: os.WriteFile/OpenFile/Mkdir with 0777/0666
			`(?:os\.WriteFile|os\.OpenFile|os\.Mkdir|os\.MkdirAll)\s*\([^,]+,\s*(?:[^,]+,\s*)?0o?(?:777|766|776|667|666)` +
			// Python: os.chmod with overly permissive
			`|os\.chmod\s*\([^,]+,\s*0o?(?:777|766|776|666)` +
			`)`),
		Languages: []string{".go", ".py"},
	},

	// Missing input validation on type conversion (CWE-20)
	{
		ID:          "AI-SEC-013",
		Name:        "Unchecked Type Conversion from User Input",
		Description: "AI-generated code often converts user input (string to int, etc.) without checking for errors, leading to panics or unexpected zero values. Always validate conversion results. (CWE-20)",
		Severity:    models.SeverityMedium,
		Pattern: regexp.MustCompile(`(?:` +
			// Go: strconv.Atoi without error check on same line
			`\w+\s*,\s*_\s*(?::=|=)\s*strconv\.(?:Atoi|ParseInt|ParseFloat|ParseBool|ParseUint)\s*\(` +
			// Python: int()/float() on request params without try
			`|(?:int|float)\s*\(\s*(?:request\.|req\.|params\[|args\[|form\[)` +
			// JS: parseInt without validation
			`|parseInt\s*\(\s*(?:req\.|request\.|params\.|query\.)` +
			`)`),
		Languages: []string{".go", ".py", ".js", ".ts"},
	},

	// Logging sensitive data (CWE-532)
	{
		ID:          "AI-SEC-014",
		Name:        "Sensitive Data in Log Output",
		Description: "AI-generated code may log passwords, tokens, or request bodies containing credentials. Sanitize sensitive fields before logging. (CWE-532)",
		Severity:    models.SeverityMedium,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			`(?:log|logger|console|fmt\.Print|fmt\.Fprintf|fmt\.Printf|logging)\s*[\.(]\s*[^)]*(?:password|passwd|secret|token|api[_-]?key|credit[_-]?card|ssn|authorization)\b` +
			`)`),
		Excludes:  regexp.MustCompile(`(?i)(?:mask|redact|sanitiz|censor|\*\*\*|xxx|FILTERED)`),
		Languages: []string{".go", ".py", ".java", ".js", ".ts", ".rb", ".php"},
	},

	// Missing context.Context timeout (Go) (CWE-400)
	{
		ID:          "AI-SEC-015",
		Name:        "HTTP/DB Call Without Timeout (Go)",
		Description: "AI-generated Go code often makes HTTP or database calls with context.Background() instead of a timeout context, risking indefinite hangs. Use context.WithTimeout. (CWE-400)",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?:http\.NewRequestWithContext|\.QueryContext|\.ExecContext)\s*\(\s*context\.Background\s*\(\s*\)`),
		Languages:   []string{".go"},
	},

	// Synchronous crypto in event loop (Node.js) (CWE-400)
	{
		ID:          "AI-SEC-016",
		Name:        "Synchronous Crypto in Event Loop (Node.js)",
		Description: "AI-generated Node.js code uses synchronous crypto functions (pbkdf2Sync, scryptSync, randomBytes) which block the event loop. Use async variants. (CWE-400)",
		Severity:    models.SeverityMedium,
		Pattern:     regexp.MustCompile(`crypto\.(?:pbkdf2Sync|scryptSync|randomFillSync|generateKeyPairSync)\s*\(`),
		Languages:   []string{".js", ".ts"},
	},

	// SQL query built with template literals without parameterization (CWE-89)
	{
		ID:          "AI-SEC-017",
		Name:        "Template Literal in SQL Query",
		Description: "AI-generated JavaScript/TypeScript often builds SQL with template literals instead of parameterized queries. This enables SQL injection. (CWE-89)",
		Severity:    models.SeverityHigh,
		Pattern:     regexp.MustCompile("(?:query|execute|exec)\\s*\\(\\s*`[^`]*\\$\\{"),
		Languages:   []string{".js", ".ts"},
	},

	// Missing CSRF protection on state-changing endpoints (CWE-352)
	{
		ID:          "AI-SEC-018",
		Name:        "State-Changing Endpoint Without CSRF Check",
		Description: "AI-generated API handlers for POST/PUT/DELETE often omit CSRF protection. Ensure state-changing endpoints validate CSRF tokens or use SameSite cookies. (CWE-352)",
		Severity:    models.SeverityMedium,
		Pattern: regexp.MustCompile(`(?i)(?:` +
			// Express: app.post/put/delete without csrf middleware nearby
			`app\.(?:post|put|delete|patch)\s*\(\s*["']/` +
			// Go: HandleFunc with POST without CSRF
			`|HandleFunc\s*\(\s*["'][^"']+["']\s*,\s*func` +
			`)`),
		Excludes:  regexp.MustCompile(`(?i)(?:csrf|csrfProtection|csrfToken|_csrf|xsrf)`),
		Languages: []string{".js", ".ts", ".go"},
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
	// XML (for XXE scanning)
	".xml": true,
	// .NET
	".cs": true,
	// Config files
	".ini": true,
	// Key files (for private key detection)
	".pem": true, ".key": true,
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
func ScanPatterns(projectPath string, skipTests ...bool) ([]PatternMatch, error) {
	skipTestFiles := len(skipTests) > 0 && skipTests[0]
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
				if path != projectPath && fsutil.ShouldSkipSubDir(info.Name()) {
					return filepath.SkipDir
				}
				if skipTestFiles && path != projectPath && fsutil.IsTestDir(info.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if skipTestFiles && fsutil.IsTestFile(path) {
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

		// Respect inline security suppression comments (#nosec, nolint, NOSONAR, nosemgrep)
		if suppressionComment.MatchString(line) {
			continue
		}

		for _, rule := range knownPatterns {
			// Check if this rule applies to this file extension
			if !ruleAppliesToExt(rule, ext) {
				continue
			}

			if rule.Pattern.MatchString(line) {
				// Apply exclusion filter if defined (false-positive reduction)
				if rule.Excludes != nil && rule.Excludes.MatchString(line) {
					continue
				}
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
