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

func findRule(id string) PatternRule {
	for _, r := range knownPatterns {
		if r.ID == id {
			return r
		}
	}
	panic("rule not found: " + id)
}

func TestSEC003_NoFalsePositiveOnSafeExecCommand(t *testing.T) {
	rule := findRule("SEC-003")

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
	rule := findRule("SEC-003")

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
	rule := findRule("SEC-008")

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
	rule := findRule("SEC-008")

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
