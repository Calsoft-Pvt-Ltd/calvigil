package analyzer

import (
	"testing"
)

func TestSEC001_NoFalsePositiveOnLogMessages(t *testing.T) {
	rule := knownPatterns[0] // SEC-001
	if rule.ID != "SEC-001" {
		t.Fatalf("expected SEC-001, got %s", rule.ID)
	}

	falsePositives := []string{
		// Log messages containing SQL keywords in natural language
		`errMsg := fmt.Sprintf("Failed to update external access alias for grantee %d in grantor org %d due to error %s", id, org, err.Error())`,
		`log.Errorf(fmt.Sprintf("Failed to update user %d: %s", uid, err))`,
		`msg := fmt.Sprintf("Could not delete the entry for %s", name)`,
		`log.Info(fmt.Sprintf("Select user %s for processing", name))`,
		`log.Infof("Created new entry for user %s", name)`,
		`fmt.Sprintf("Failed to insert record for %s due to %s", key, err)`,
		`fmt.Sprintf("Cannot alter configuration for %s", service)`,
		`log.Warnf(fmt.Sprintf("Dropping connection to %s", host))`,
		`msg := fmt.Sprintf("Execute retry for operation %s", op)`,
		// SQL keywords in a SEPARATE argument from the format specifier
		`log.Infof("------------ END: BeforeTest - %s ------------", "Create DATABASE")`,
		`log.Debugf("Step %d complete", steps, "DROP TABLE cleanup")`,
		`fmt.Sprintf("Processing %s", "INSERT INTO audit log")`,
	}

	for _, line := range falsePositives {
		if rule.Pattern.MatchString(line) {
			t.Errorf("SEC-001 false positive on log message:\n  %s", line)
		}
	}
}

func TestSEC001_CatchesRealSQLInjection(t *testing.T) {
	rule := knownPatterns[0] // SEC-001
	if rule.ID != "SEC-001" {
		t.Fatalf("expected SEC-001, got %s", rule.ID)
	}

	realInjections := []string{
		`q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput)`,
		`q := fmt.Sprintf("SELECT id, name FROM users WHERE name = '%s'", userInput)`,
		`q := fmt.Sprintf("INSERT INTO users (name) VALUES ('%s')", input)`,
		`q := fmt.Sprintf("UPDATE users SET name = '%s' WHERE id = %d", name, id)`,
		`q := fmt.Sprintf("DELETE FROM users WHERE id = %d", id)`,
		`q := fmt.Sprintf("DROP TABLE %s", tableName)`,
		`q := fmt.Sprintf("ALTER TABLE %s ADD COLUMN x", t)`,
		`q := fmt.Sprintf("CREATE TABLE %s (id INT)", t)`,
	}

	for _, line := range realInjections {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-001 failed to detect real SQL injection:\n  %s", line)
		}
	}
}

func TestSEC002_NoFalsePositiveOnLogMessages(t *testing.T) {
	rule := knownPatterns[1] // SEC-002
	if rule.ID != "SEC-002" {
		t.Fatalf("expected SEC-002, got %s", rule.ID)
	}

	falsePositives := []string{
		`query = "Failed to update the record for " + name`,
		`sql = "Could not select item from " + source`,
		`stmt = "Unable to delete entry for user " + user`,
		`query = "Please select your preferred option from " + list`,
	}

	for _, line := range falsePositives {
		if rule.Pattern.MatchString(line) {
			t.Errorf("SEC-002 false positive:\n  %s", line)
		}
	}
}

func TestSEC002_CatchesRealSQLInjection(t *testing.T) {
	rule := knownPatterns[1] // SEC-002
	if rule.ID != "SEC-002" {
		t.Fatalf("expected SEC-002, got %s", rule.ID)
	}

	realInjections := []string{
		`query = "SELECT * FROM users WHERE id = " + userId`,
		`sql = "INSERT INTO users (name) VALUES ('" + name + "')"`,
		`stmt = "UPDATE users SET name = '" + name + "'"`,
		`query = "DELETE FROM users WHERE id = " + id`,
		`query = "SELECT id, name FROM users WHERE id = " + id`,
	}

	for _, line := range realInjections {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-002 failed to detect:\n  %s", line)
		}
	}
}

func findRule(t *testing.T, id string) PatternRule {
	t.Helper()
	for _, r := range knownPatterns {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule not found: %s", id)
	return PatternRule{} // unreachable
}

func TestSEC003_NoFalsePositiveOnSafeExecCommand(t *testing.T) {
	rule := findRule(t, "SEC-003")

	falsePositives := []string{
		// exec.Command with separate arguments (no shell) — safe
		`descCmd := exec.Command("kubectl", "describe", "pod", podName, "-n", "common")`,
		`cmd := exec.Command("git", "log", "--oneline")`,
		`cmd := exec.Command("ls", "-la", dir)`,
	}

	for _, line := range falsePositives {
		if rule.Pattern.MatchString(line) {
			t.Errorf("SEC-003 false positive:\n  %s", line)
		}
	}
}

func TestSEC003_CatchesRealCommandInjection(t *testing.T) {
	rule := findRule(t, "SEC-003")

	realInjections := []string{
		// Go: shell invocation
		`cmd := exec.Command("sh", "-c", userInput)`,
		`cmd := exec.Command("bash", "-c", query)`,
		// Go: string concatenation in command
		`cmd := exec.Command("cmd " + userInput)`,
		`cmd := exec.Command(fmt.Sprintf("echo %s", input))`,
		// Python
		`os.system("rm -rf " + path)`,
		`subprocess.call(["sh", "-c", cmd])`,
		`subprocess.run(cmd, shell=True)`,
		// JavaScript
		`child_process.exec("ls " + dir)`,
		// Java
		`Runtime.getRuntime().exec("cmd /c " + input)`,
		// PHP
		`shell_exec("cat " . $file)`,
		`passthru($cmd)`,
		`system($input)`,
		`popen("cmd " . $arg)`,
	}

	for _, line := range realInjections {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-003 failed to detect:\n  %s", line)
		}
	}
}

func TestSuppressionComments(t *testing.T) {
	tests := []struct {
		line       string
		suppressed bool
	}{
		{`cmd := exec.Command("sh", "-c", x) // #nosec G204`, true},
		{`cmd := exec.Command("sh", "-c", x) //nolint:gosec`, true},
		{`cmd := exec.Command("sh", "-c", x) // NOSONAR`, true},
		{`cmd := exec.Command("sh", "-c", x) // nosemgrep`, true},
		{`os.system(user_input) # nosec`, true},
		{`os.system(user_input) # noqa: S605`, true},
		{`cmd := exec.Command("sh", "-c", x) // this is dangerous`, false},
	}

	for _, tt := range tests {
		got := suppressionComment.MatchString(tt.line)
		if got != tt.suppressed {
			t.Errorf("suppressionComment(%q) = %v, want %v", tt.line, got, tt.suppressed)
		}
	}
}

func TestSEC008_NoFalsePositiveOnORMRaw(t *testing.T) {
	rule := findRule(t, "SEC-008")

	falsePositives := []string{
		// GORM .Raw() — parameterized database query, not HTML rendering
		`result := dbhandlers.GetWorkingInstance().Instance.Raw(query, userId).Scan(&userSites)`,
		`db.Raw("SELECT * FROM users WHERE id = ?", id).Scan(&user)`,
		`session.Raw("UPDATE stats SET count = count + 1").Exec()`,
		// SQLAlchemy .raw()
		`cursor = connection.raw("SELECT 1")`,
	}

	for _, line := range falsePositives {
		if rule.Pattern.MatchString(line) {
			t.Errorf("SEC-008 false positive on ORM method:\n  %s", line)
		}
	}
}

func TestSEC008_CatchesRealXSS(t *testing.T) {
	rule := findRule(t, "SEC-008")

	realXSS := []string{
		`element.innerHTML = userInput`,
		`$(selector).html(userInput)`,
		`document.write(data)`,
		`<div v-html="userContent"></div>`,
		`dangerouslySetInnerHTML={{__html: data}}`,
		`template.HTML(userInput)`,
		`<%= raw(user_input) %>`,
		`echo $_GET["name"]`,
	}

	for _, line := range realXSS {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-008 failed to detect XSS:\n  %s", line)
		}
	}
}

// ── SEC-006: Cloud Provider Credential ────────────────────────────

func TestSEC006_DetectsCloudCredentials(t *testing.T) {
	rule := findRule(t, "SEC-006")

	positives := []string{
		`AWS_KEY = "AKIAIOSFODNN7EXAMPLE"`,
		`"type": "service_account"`,
		`AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR012345678901234567890123456789`,
		`token := "ghp_1234567890abcdefghijklmnopqrstuvwxyz"`,
		`access_token = "glpat-abcdefghijklmnopqrst"`,
		`SLACK_TOKEN="xoxb-123-456-abcdefg"`,
		"stripe_key = \"sk_live_" + "1234567890abcdefghijklmn\"",
		`OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwx"`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-006 failed to detect credential:\n  %s", line)
		}
	}
}

// ── SEC-009: Insecure HTTP (with exclusions) ──────────────────────

func TestSEC009_ExcludesLocalhost(t *testing.T) {
	rule := findRule(t, "SEC-009")

	excluded := []string{
		`url := "http://localhost:8080/api"`,
		`url := "http://127.0.0.1:3000/health"`,
		`url := "http://example.com/docs"`,
		`url := "http://www.w3.org/2001/XMLSchema"`,
		`url := "http://schemas.xmlsoap.org/soap/envelope/"`,
		`url := "http://xml.org/sax/features/namespaces"`,
	}

	for _, line := range excluded {
		if rule.Pattern.MatchString(line) && !rule.Excludes.MatchString(line) {
			t.Errorf("SEC-009 should exclude:\n  %s", line)
		}
	}
}

func TestSEC009_DetectsExternalHTTP(t *testing.T) {
	rule := findRule(t, "SEC-009")

	positives := []string{
		`url := "http://api.example-service.com/data"`,
		`endpoint := "http://external.host.io/endpoint"`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-009 failed to detect insecure HTTP:\n  %s", line)
		}
	}
}

// ── SEC-018: Insecure Random ──────────────────────────────────────

func TestSEC018_DetectsWeakRandom(t *testing.T) {
	rule := findRule(t, "SEC-018")

	positives := []string{
		`n := rand.Intn(100)`,
		`f := rand.Float64()`,
		`r := rand.New(rand.NewSource(42))`,
		`x = random.randint(1, 100)`,
		`item = random.choice(items)`,
		`Random rng = new Random()`,
		`val x = Math.random()`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-018 failed to detect weak random:\n  %s", line)
		}
	}
}

// ── SEC-019: Weak Cipher ──────────────────────────────────────────

func TestSEC019_DetectsWeakCipher(t *testing.T) {
	rule := findRule(t, "SEC-019")

	positives := []string{
		`block, _ := des.NewCipher(key)`,
		`block, _ := des.NewTripleDESCipher(key)`,
		`cipher, _ := rc4.NewCipher(key)`,
		`cipher = DES.new(key, DES.MODE_ECB)`,
		`cipher = ARC4.new(key)`,
		`cipher = Blowfish.new(key)`,
		`Cipher c = Cipher.getInstance("DES")`,
		`Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding")`,
		`const cipher = crypto.createCipher("des", key)`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-019 failed to detect weak cipher:\n  %s", line)
		}
	}
}

// ── SEC-020: XXE ──────────────────────────────────────────────────

func TestSEC020_DetectsXXE(t *testing.T) {
	rule := findRule(t, "SEC-020")

	positives := []string{
		`DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance()`,
		`SAXParserFactory spf = SAXParserFactory.newInstance()`,
		`XMLInputFactory factory = XMLInputFactory.newInstance()`,
		`tree = xml.etree.ElementTree.parse(user_file)`,
		`doc = lxml.etree.parse(input_file)`,
		`decoder := xml.NewDecoder(reader)`,
		`$doc = simplexml_load_string($xml)`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-020 failed to detect XXE risk:\n  %s", line)
		}
	}
}

// ── SEC-021: JWT Misconfiguration ─────────────────────────────────

func TestSEC021_DetectsJWTMisconfig(t *testing.T) {
	rule := findRule(t, "SEC-021")

	positives := []string{
		`payload = jwt.decode(token, verify=False)`,
		`jwt.decode(token, options={"verify_signature": False})`,
		`algorithms = ["none"]`,
		`data = jwt.decode(token)`,
		`claims, _ := jwt.Parse(token, nil)`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-021 failed to detect JWT misconfiguration:\n  %s", line)
		}
	}
}

// ── SEC-022: Debug Mode ───────────────────────────────────────────

func TestSEC022_DetectsDebugMode(t *testing.T) {
	rule := findRule(t, "SEC-022")

	positives := []string{
		`app.run(host="0.0.0.0", debug=True)`,
		`DEBUG = True`,
		`display_errors = On`,
		`error_reporting(E_ALL)`,
		`gin.SetMode(gin.DebugMode)`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-022 failed to detect debug mode:\n  %s", line)
		}
	}
}

// ── SEC-023: Empty Catch Block ────────────────────────────────────

func TestSEC023_DetectsEmptyCatch(t *testing.T) {
	rule := findRule(t, "SEC-023")

	positives := []string{
		`} catch (Exception e) {}`,
		`catch (err) {}`,
		`if err != nil {}`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-023 failed to detect empty error handler:\n  %s", line)
		}
	}
}

// ── SEC-024: SSRF ─────────────────────────────────────────────────

func TestSEC024_DetectsSSRF(t *testing.T) {
	rule := findRule(t, "SEC-024")

	positives := []string{
		`resp, err := http.Get(userURL)`,
		`resp, err := http.Post(targetURL, "application/json", body)`,
		`r = requests.get(url_from_user)`,
		`r = requests.post(user_url, data=payload)`,
		`urllib.request.urlopen(external_url)`,
		`new URL(userInput)`,
		`fetch(apiEndpoint)`,
		`axios.get(remoteURL)`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-024 failed to detect SSRF:\n  %s", line)
		}
	}
}

func TestSEC024_NoFalsePositiveOnLiterals(t *testing.T) {
	rule := findRule(t, "SEC-024")

	// String literals (hardcoded URLs) should NOT match since the pattern
	// requires a variable (starts with [a-zA-Z_]) after the function call.
	falsePositives := []string{
		`resp, err := http.Get("https://api.example.com/data")`,
		`r = requests.get("https://api.example.com/data")`,
	}

	for _, line := range falsePositives {
		if rule.Pattern.MatchString(line) {
			t.Errorf("SEC-024 false positive on literal URL:\n  %s", line)
		}
	}
}

// ── SEC-025: Open Redirect ────────────────────────────────────────

func TestSEC025_DetectsOpenRedirect(t *testing.T) {
	rule := findRule(t, "SEC-025")

	positives := []string{
		`http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)`,
		`http.Redirect(w, r, req.FormValue("redirect"), 302)`,
		`return redirect(request.GET.get("next"))`,
		`res.redirect(req.query.url)`,
		`header("Location: " . $_GET["url"])`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-025 failed to detect open redirect:\n  %s", line)
		}
	}
}

// ── Excludes field test ───────────────────────────────────────────

func TestExcludesFieldWorks(t *testing.T) {
	rule := findRule(t, "SEC-009")
	if rule.Excludes == nil {
		t.Fatal("SEC-009 should have an Excludes pattern")
	}

	// Should match Pattern AND Excludes (so scanFile skips it)
	line := `url := "http://schemas.xmlsoap.org/soap/envelope/"`
	if !rule.Pattern.MatchString(line) {
		t.Error("SEC-009 Pattern should match the URL")
	}
	if !rule.Excludes.MatchString(line) {
		t.Error("SEC-009 Excludes should match the URL to suppress it")
	}

	// Should match Pattern but NOT Excludes (real finding)
	realLine := `url := "http://api.production.com/data"`
	if !rule.Pattern.MatchString(realLine) {
		t.Error("SEC-009 Pattern should match external HTTP URL")
	}
	if rule.Excludes.MatchString(realLine) {
		t.Error("SEC-009 Excludes should NOT match external HTTP URL")
	}
}

// ── SEC-026: Private Key Detection ────────────────────────────────

func TestSEC026_DetectsPrivateKeys(t *testing.T) {
	rule := findRule(t, "SEC-026")

	positives := []string{
		`-----BEGIN RSA PRIVATE KEY-----`,
		`-----BEGIN PRIVATE KEY-----`,
		`-----BEGIN EC PRIVATE KEY-----`,
		`-----BEGIN PGP PRIVATE KEY BLOCK-----`,
		`-----BEGIN DSA PRIVATE KEY-----`,
		`-----BEGIN OPENSSH PRIVATE KEY-----`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-026 failed to detect private key:\n  %s", line)
		}
	}
}

func TestSEC026_NoFalsePositiveOnPublicKeys(t *testing.T) {
	rule := findRule(t, "SEC-026")

	negatives := []string{
		`-----BEGIN PUBLIC KEY-----`,
		`-----BEGIN RSA PUBLIC KEY-----`,
		`-----BEGIN CERTIFICATE-----`,
		`-----BEGIN SSH2 PUBLIC KEY-----`,
		`private_key_path = "/path/to/key"`,
	}

	for _, line := range negatives {
		if rule.Pattern.MatchString(line) {
			t.Errorf("SEC-026 false positive:\n  %s", line)
		}
	}
}

// ── SEC-027: Database Connection Strings ──────────────────────────

func TestSEC027_DetectsConnectionStrings(t *testing.T) {
	rule := findRule(t, "SEC-027")

	positives := []string{
		`dsn := "mongodb://admin:password123@cluster.mongodb.net/db"`,
		`dsn := "mongodb+srv://user:pass@host.net/db"`,
		`dsn := "postgres://admin:secret@localhost:5432/mydb"`,
		`dsn := "postgresql://admin:secret@localhost/mydb"`,
		`dsn := "mysql://root:password@localhost:3306/db"`,
		`dsn := "redis://:authpass@redis.example.com:6379"`,
		`dsn := "amqp://guest:guest@localhost:5672/"`,
		`dsn := "amqps://user:pass@rabbit.example.com/"`,
		`connStr := "Server=srv;Database=db;User Id=sa;Password=secret;"`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-027 failed to detect connection string:\n  %s", line)
		}
	}
}

func TestSEC027_NoFalsePositiveOnSafeStrings(t *testing.T) {
	rule := findRule(t, "SEC-027")

	negatives := []string{
		`dsn := "postgres://localhost:5432/db"`,
		`dsn := os.Getenv("DATABASE_URL")`,
		`// connect to mongodb cluster`,
		`host := "redis.example.com"`,
	}

	for _, line := range negatives {
		if rule.Pattern.MatchString(line) {
			t.Errorf("SEC-027 false positive:\n  %s", line)
		}
	}
}

// ── SEC-028: Bearer/Auth Token ────────────────────────────────────

func TestSEC028_DetectsBearerTokens(t *testing.T) {
	rule := findRule(t, "SEC-028")

	positives := []string{
		`"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0"`,
		`'Authorization' = 'Bearer abcdefghijklmnopqrstuvwxyz1234567890'`,
		`bearer_token = "abcdefghijklmnopqrstuvwxyz1234567890"`,
		`auth_token = "abcdefghijklmnopqrstuvwxyz1234567890"`,
		`access_token = "abcdefghijklmnopqrstuvwxyz1234567890"`,
		`refresh_token = "abcdefghijklmnopqrstuvwxyz1234567890"`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-028 failed to detect token:\n  %s", line)
		}
	}
}

func TestSEC028_NoFalsePositiveOnShortTokens(t *testing.T) {
	rule := findRule(t, "SEC-028")

	negatives := []string{
		`"Authorization": "Bearer short"`,
		`bearer_token = "abc"`,
		`auth_token = os.Getenv("TOKEN")`,
		`// refresh_token documentation`,
	}

	for _, line := range negatives {
		if rule.Pattern.MatchString(line) {
			t.Errorf("SEC-028 false positive:\n  %s", line)
		}
	}
}

// ── SEC-029: Generic API Key / Secret ─────────────────────────────

func TestSEC029_DetectsGenericSecrets(t *testing.T) {
	rule := findRule(t, "SEC-029")

	positives := []string{
		`api_key = "abcdefghijklmnopqrstuvwxyz1234567890"`,
		`api_secret = "abcdefghijklmnopqrstuvwxyz1234567890"`,
		`secret_key = "abcdefghijklmnopqrstuvwxyz1234567890"`,
		`token_secret = "aAbBcCdDeEfFgGhHiIjJ123456"`,
		`service_key = "01234567890123456789ABCD"`,
		`master_key: "XXXXXXXXXXXXXXXXXXXXXXXXX"`,
	}

	for _, line := range positives {
		if !rule.Pattern.MatchString(line) {
			t.Errorf("SEC-029 failed to detect generic secret:\n  %s", line)
		}
	}
}

func TestSEC029_NoFalsePositiveOnShortValues(t *testing.T) {
	rule := findRule(t, "SEC-029")

	negatives := []string{
		`api_key = "short"`,
		`api_key = os.Getenv("API_KEY")`,
		`secret_key = ""`,
		`// api_secret documentation`,
		`api_key = "12345678901234567"`, // only 17 chars, need 20+
	}

	for _, line := range negatives {
		if rule.Pattern.MatchString(line) {
			t.Errorf("SEC-029 false positive:\n  %s", line)
		}
	}
}
