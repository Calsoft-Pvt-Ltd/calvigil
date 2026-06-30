package analyzer

import (
	"sort"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

const slopAuthorshipDisclaimer = "Slop code smells are quality and security symptoms, not proof that code was AI-generated."

type slopCategoryDef struct {
	id          string
	name        string
	description string
	guidance    string
}

var slopCategories = map[string]slopCategoryDef{
	"resource_leak": {
		id:          "resource_leak",
		name:        "Resource lifecycle",
		description: "Resources are opened or network responses are created without deterministic cleanup.",
		guidance:    "Close files, HTTP bodies, DB rows, streams, and sockets immediately after successful creation.",
	},
	"concurrency": {
		id:          "concurrency",
		name:        "Concurrency safety",
		description: "Shared mutable state or goroutine patterns can race under load.",
		guidance:    "Protect shared state with synchronization and pass loop values explicitly into goroutines.",
	},
	"error_handling": {
		id:          "error_handling",
		name:        "Error handling",
		description: "Errors are ignored, swallowed, or caught too broadly.",
		guidance:    "Handle errors explicitly, preserve context, and fail closed for security-sensitive paths.",
	},
	"stale_api": {
		id:          "stale_api",
		name:        "Stale or hallucinated APIs",
		description: "Deprecated or removed APIs suggest copied or stale implementation patterns.",
		guidance:    "Replace deprecated APIs with current platform recommendations and add tests around the migrated behavior.",
	},
	"unbounded_work": {
		id:          "unbounded_work",
		name:        "Unbounded work",
		description: "Code can load, allocate, query, or compute without production limits.",
		guidance:    "Add pagination, request-size limits, timeouts, cancellation, and algorithmic bounds.",
	},
	"insecure_defaults": {
		id:          "insecure_defaults",
		name:        "Insecure defaults",
		description: "Convenience defaults weaken production security posture.",
		guidance:    "Move deployment settings into configuration and default to least privilege, HTTPS, and verification on.",
	},
	"input_validation": {
		id:          "input_validation",
		name:        "Input validation",
		description: "User-controlled values reach dangerous operations without strong validation or parameterization.",
		guidance:    "Validate inputs at trust boundaries and use safe APIs such as parameterized SQL and allowlisted paths.",
	},
	"secret_exposure": {
		id:          "secret_exposure",
		name:        "Secret or data exposure",
		description: "Credentials, tokens, or sensitive data may leak through code or logs.",
		guidance:    "Move secrets to a manager, rotate exposed credentials, and redact sensitive fields before logging.",
	},
	"csrf_state_change": {
		id:          "csrf_state_change",
		name:        "State-changing web safety",
		description: "State-changing endpoints may be missing CSRF or equivalent request-origin controls.",
		guidance:    "Require CSRF tokens, SameSite cookies, or explicit API authentication for state-changing operations.",
	},
}

var aiSecRuleCategory = map[string]string{
	"AI-SEC-001": "resource_leak",
	"AI-SEC-002": "resource_leak",
	"AI-SEC-003": "concurrency",
	"AI-SEC-004": "concurrency",
	"AI-SEC-005": "unbounded_work",
	"AI-SEC-006": "unbounded_work",
	"AI-SEC-007": "error_handling",
	"AI-SEC-008": "error_handling",
	"AI-SEC-009": "stale_api",
	"AI-SEC-010": "insecure_defaults",
	"AI-SEC-011": "unbounded_work",
	"AI-SEC-012": "insecure_defaults",
	"AI-SEC-013": "input_validation",
	"AI-SEC-014": "secret_exposure",
	"AI-SEC-015": "unbounded_work",
	"AI-SEC-016": "unbounded_work",
	"AI-SEC-017": "input_validation",
	"AI-SEC-018": "csrf_state_change",
	"AI-SEC-019": "unbounded_work",
	"AI-SEC-020": "error_handling",
	"AI-SEC-021": "insecure_defaults",
	"AI-SEC-022": "unbounded_work",
	"AI-SEC-023": "unbounded_work",
}

var secRuleCategory = map[string]string{
	"SEC-001": "input_validation",
	"SEC-002": "input_validation",
	"SEC-003": "input_validation",
	"SEC-004": "input_validation",
	"SEC-005": "secret_exposure",
	"SEC-006": "secret_exposure",
	"SEC-007": "insecure_defaults",
	"SEC-008": "input_validation",
	"SEC-010": "insecure_defaults",
	"SEC-011": "input_validation",
	"SEC-012": "insecure_defaults",
	"SEC-018": "insecure_defaults",
	"SEC-019": "insecure_defaults",
	"SEC-020": "input_validation",
	"SEC-021": "insecure_defaults",
	"SEC-022": "insecure_defaults",
	"SEC-023": "error_handling",
	"SEC-024": "input_validation",
	"SEC-025": "input_validation",
	"SEC-026": "secret_exposure",
	"SEC-027": "secret_exposure",
	"SEC-028": "secret_exposure",
	"SEC-029": "secret_exposure",
}

// BuildSlopCodeSmellSummary aggregates concrete code-quality and security
// symptoms into an AI-slop smell score. It deliberately does not infer
// authorship; it scores symptoms that are common in low-trust generated or
// copy-pasted code.
func BuildSlopCodeSmellSummary(vulns []models.Vulnerability) *models.SlopCodeSmellSummary {
	signals := make([]models.SlopCodeSmellSignal, 0)
	categoryWeights := map[string]int{}
	categoryCounts := map[string]int{}
	likelyAI, possibleAI, unlikelyAI := 0, 0, 0

	for _, v := range vulns {
		signal, ok := slopSignalForFinding(v)
		if !ok {
			if v.AIEnrichment != nil {
				switch strings.ToUpper(v.AIEnrichment.AICodeIndicator) {
				case "LIKELY_AI":
					likelyAI++
				case "POSSIBLY_AI":
					possibleAI++
				case "UNLIKELY_AI":
					unlikelyAI++
				}
			}
			continue
		}
		signals = append(signals, signal)
		categoryWeights[signal.CategoryID] += signal.Weight
		categoryCounts[signal.CategoryID]++
		if v.AIEnrichment != nil {
			switch strings.ToUpper(v.AIEnrichment.AICodeIndicator) {
			case "LIKELY_AI":
				likelyAI++
			case "POSSIBLY_AI":
				possibleAI++
			case "UNLIKELY_AI":
				unlikelyAI++
			}
		}
	}

	if len(signals) == 0 {
		return nil
	}

	sort.Slice(signals, func(i, j int) bool {
		if signals[i].Weight == signals[j].Weight {
			return signals[i].Severity.Rank() > signals[j].Severity.Rank()
		}
		return signals[i].Weight > signals[j].Weight
	})

	categories := make([]models.SlopCodeSmellCategory, 0, len(categoryWeights))
	for categoryID, weight := range categoryWeights {
		def := slopCategories[categoryID]
		categories = append(categories, models.SlopCodeSmellCategory{
			ID:          def.id,
			Name:        def.name,
			Description: def.description,
			Count:       categoryCounts[categoryID],
			Weight:      weight,
		})
	}
	sort.Slice(categories, func(i, j int) bool {
		if categories[i].Weight == categories[j].Weight {
			return categories[i].Name < categories[j].Name
		}
		return categories[i].Weight > categories[j].Weight
	})

	totalWeight := 0
	for _, signal := range signals {
		totalWeight += signal.Weight
	}
	score := totalWeight
	if score > 100 {
		score = 100
	}

	topSignals := signals
	if len(topSignals) > 8 {
		topSignals = topSignals[:8]
	}

	return &models.SlopCodeSmellSummary{
		Score:                score,
		Level:                slopLevel(score),
		SignalCount:          len(signals),
		GeneratedCodeSignal:  aggregateGeneratedCodeSignal(likelyAI, possibleAI, unlikelyAI),
		Categories:           categories,
		TopSignals:           topSignals,
		Guidance:             slopGuidance(categories),
		Confidence:           slopConfidence(signals, likelyAI, possibleAI),
		AuthorshipDisclaimer: slopAuthorshipDisclaimer,
	}
}

func slopSignalForFinding(v models.Vulnerability) (models.SlopCodeSmellSignal, bool) {
	ruleID := primaryRuleID(v)
	categoryID, reason, confidence, ok := slopClassification(v, ruleID)
	if !ok {
		return models.SlopCodeSmellSignal{}, false
	}

	return models.SlopCodeSmellSignal{
		FindingID:  v.ID,
		RuleID:     ruleID,
		CategoryID: categoryID,
		Title:      v.Summary,
		Severity:   v.Severity,
		Source:     string(v.Source),
		FilePath:   v.FilePath,
		StartLine:  v.StartLine,
		Confidence: confidence,
		Reason:     reason,
		Weight:     slopSignalWeight(v, confidence),
	}, true
}

func primaryRuleID(v models.Vulnerability) string {
	if v.MatchedRule != "" {
		return v.MatchedRule
	}
	return strings.TrimPrefix(v.ID, "SG-")
}

func slopClassification(v models.Vulnerability, ruleID string) (string, string, string, bool) {
	normalizedRule := strings.ToUpper(ruleID)
	if categoryID, ok := aiSecRuleCategory[normalizedRule]; ok {
		return categoryID, "Matched built-in AI-SEC rule for generated-code anti-patterns.", "HIGH", true
	}

	if categoryID, ok := secRuleCategory[normalizedRule]; ok {
		return categoryID, "Matched security pattern commonly seen in low-trust generated or copied code.", "MEDIUM", true
	}

	semgrepRule := strings.ToLower(ruleID)
	if strings.HasPrefix(semgrepRule, "ai-") || strings.Contains(semgrepRule, "ai-code") {
		return semgrepCategory(semgrepRule), "Matched Semgrep AI code-quality rule pack.", "HIGH", true
	}

	if v.AIEnrichment != nil {
		switch strings.ToUpper(v.AIEnrichment.AICodeIndicator) {
		case "LIKELY_AI":
			return categoryFromText(v.Summary + " " + v.Details), "AI enrichment marked this finding as likely AI-generated code.", "MEDIUM", true
		case "POSSIBLY_AI":
			return categoryFromText(v.Summary + " " + v.Details), "AI enrichment marked this finding as possibly AI-generated code.", "LOW", true
		}
	}

	return "", "", "", false
}

func semgrepCategory(ruleID string) string {
	switch {
	case strings.Contains(ruleID, "body-leak"), strings.Contains(ruleID, "file-open"), strings.Contains(ruleID, "context-manager"), strings.Contains(ruleID, "stream"), strings.Contains(ruleID, "resource"):
		return "resource_leak"
	case strings.Contains(ruleID, "goroutine"), strings.Contains(ruleID, "mutex"), strings.Contains(ruleID, "race"), strings.Contains(ruleID, "mutable"):
		return "concurrency"
	case strings.Contains(ruleID, "error"), strings.Contains(ruleID, "catch"), strings.Contains(ruleID, "except"), strings.Contains(ruleID, "swallow"):
		return "error_handling"
	case strings.Contains(ruleID, "deprecated"), strings.Contains(ruleID, "buffer"), strings.Contains(ruleID, "distutils"):
		return "stale_api"
	case strings.Contains(ruleID, "sql"), strings.Contains(ruleID, "csrf"), strings.Contains(ruleID, "validation"), strings.Contains(ruleID, "input"):
		return "input_validation"
	case strings.Contains(ruleID, "secret"), strings.Contains(ruleID, "token"), strings.Contains(ruleID, "log-sensitive"):
		return "secret_exposure"
	case strings.Contains(ruleID, "timeout"), strings.Contains(ruleID, "unbounded"), strings.Contains(ruleID, "sync-crypto"), strings.Contains(ruleID, "nested"), strings.Contains(ruleID, "concat"):
		return "unbounded_work"
	case strings.Contains(ruleID, "cors"), strings.Contains(ruleID, "tls"), strings.Contains(ruleID, "permissive"), strings.Contains(ruleID, "debug"):
		return "insecure_defaults"
	default:
		return "insecure_defaults"
	}
}

func categoryFromText(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "close"), strings.Contains(lower, "leak"), strings.Contains(lower, "resource"):
		return "resource_leak"
	case strings.Contains(lower, "race"), strings.Contains(lower, "goroutine"), strings.Contains(lower, "concurrent"):
		return "concurrency"
	case strings.Contains(lower, "error"), strings.Contains(lower, "exception"), strings.Contains(lower, "catch"):
		return "error_handling"
	case strings.Contains(lower, "deprecated"), strings.Contains(lower, "removed api"):
		return "stale_api"
	case strings.Contains(lower, "secret"), strings.Contains(lower, "token"), strings.Contains(lower, "password"), strings.Contains(lower, "log"):
		return "secret_exposure"
	case strings.Contains(lower, "sql"), strings.Contains(lower, "csrf"), strings.Contains(lower, "input"), strings.Contains(lower, "validation"):
		return "input_validation"
	case strings.Contains(lower, "timeout"), strings.Contains(lower, "unbounded"), strings.Contains(lower, "limit"), strings.Contains(lower, "pagination"):
		return "unbounded_work"
	default:
		return "insecure_defaults"
	}
}

func slopSignalWeight(v models.Vulnerability, confidence string) int {
	weight := 4
	switch v.Severity {
	case models.SeverityCritical:
		weight = 20
	case models.SeverityHigh:
		weight = 15
	case models.SeverityMedium:
		weight = 9
	case models.SeverityLow:
		weight = 5
	}

	switch confidence {
	case "HIGH":
		weight += 4
	case "MEDIUM":
		weight += 2
	}
	if v.KnownExploited {
		weight += 8
	}
	if v.AIEnrichment != nil {
		switch strings.ToUpper(v.AIEnrichment.AICodeIndicator) {
		case "LIKELY_AI":
			weight += 5
		case "POSSIBLY_AI":
			weight += 2
		}
	}
	return weight
}

func slopLevel(score int) string {
	switch {
	case score >= 85:
		return "CRITICAL"
	case score >= 65:
		return "HIGH"
	case score >= 35:
		return "MODERATE"
	case score > 0:
		return "LOW"
	default:
		return "CLEAN"
	}
}

func aggregateGeneratedCodeSignal(likely, possible, unlikely int) string {
	switch {
	case likely > 0:
		return "LIKELY_AI"
	case possible > 0:
		return "POSSIBLY_AI"
	case unlikely > 0:
		return "UNLIKELY_AI"
	default:
		return ""
	}
}

func slopConfidence(signals []models.SlopCodeSmellSignal, likelyAI, possibleAI int) string {
	highConfidenceSignals := 0
	for _, signal := range signals {
		if signal.Confidence == "HIGH" {
			highConfidenceSignals++
		}
	}
	switch {
	case highConfidenceSignals >= 2 || likelyAI > 0:
		return "HIGH"
	case highConfidenceSignals == 1 || possibleAI > 0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func slopGuidance(categories []models.SlopCodeSmellCategory) []string {
	if len(categories) == 0 {
		return nil
	}
	limit := len(categories)
	if limit > 4 {
		limit = 4
	}
	guidance := make([]string, 0, limit+1)
	for _, category := range categories[:limit] {
		if def, ok := slopCategories[category.ID]; ok && def.guidance != "" {
			guidance = append(guidance, def.guidance)
		}
	}
	guidance = append(guidance, "Treat this as a review-prioritization signal; confirm intent, tests, and production fit before release.")
	return guidance
}
