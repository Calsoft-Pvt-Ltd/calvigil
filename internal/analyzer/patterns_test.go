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
