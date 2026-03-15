package analyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	openai "github.com/sashabaranov/go-openai"

	"github.com/chavakula/calvigil/internal/models"
)

// OpenAIAnalyzer uses the OpenAI API to perform AI-powered code analysis.
type OpenAIAnalyzer struct {
	client *openai.Client
	model  string
}

// NewOpenAIAnalyzer creates a new AI analyzer with the given API key and model.
func NewOpenAIAnalyzer(apiKey, model string) *OpenAIAnalyzer {
	return &OpenAIAnalyzer{
		client: openai.NewClient(apiKey),
		model:  model,
	}
}

// flexInt handles JSON values that may be either a number or a string containing a number.
// Local LLMs (Ollama) often return "line": "42" instead of "line": 42.
type flexInt int

func (fi *flexInt) UnmarshalJSON(b []byte) error {
	// Try as int first
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*fi = flexInt(n)
		return nil
	}
	// Try as quoted string
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s == "" {
			*fi = 0
			return nil
		}
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			*fi = 0
			return nil
		}
		*fi = flexInt(n)
		return nil
	}
	*fi = 0
	return nil
}

// aiVulnResult represents a vulnerability found by the AI.
type aiVulnResult struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Description    string  `json:"description"`
	Severity       string  `json:"severity"`
	File           string  `json:"file"`
	Line           flexInt `json:"line"`
	Recommendation string  `json:"recommendation"`
}

// extractJSONArray finds the first JSON array in text, handling cases where the
// LLM wraps the JSON in markdown fences or explanatory prose.
func extractJSONArray(text string) string {
	text = strings.TrimSpace(text)

	// Strip markdown code fences (```json ... ``` or ``` ... ```)
	if idx := strings.Index(text, "```json"); idx != -1 {
		text = text[idx+7:]
		if end := strings.Index(text, "```"); end != -1 {
			text = text[:end]
		}
		return strings.TrimSpace(text)
	}
	if idx := strings.Index(text, "```"); idx != -1 {
		inner := text[idx+3:]
		if end := strings.Index(inner, "```"); end != -1 {
			inner = inner[:end]
			// If the content inside fences starts with [ or {, use it
			trimmed := strings.TrimSpace(inner)
			if len(trimmed) > 0 && (trimmed[0] == '[' || trimmed[0] == '{') {
				return trimmed
			}
		}
	}

	// Find the outermost [ ... ] bracket pair
	start := strings.Index(text, "[")
	if start != -1 {
		depth := 0
		for i := start; i < len(text); i++ {
			switch text[i] {
			case '[':
				depth++
			case ']':
				depth--
				if depth == 0 {
					return text[start : i+1]
				}
			}
		}
	}

	// Already clean
	return strings.TrimSpace(text)
}

func (a *OpenAIAnalyzer) Analyze(ctx context.Context, projectPath string, verbose bool) ([]models.Vulnerability, error) {
	// Step 1: Run pattern matching first (fast, no API cost)
	patternMatches, err := ScanPatterns(projectPath)
	if err != nil {
		return nil, fmt.Errorf("pattern scan failed: %w", err)
	}

	// Convert pattern matches to vulnerabilities (these are always reported)
	patternVulns := PatternMatchesToVulnerabilities(patternMatches)

	// Step 2: If we have pattern matches, send them to AI for confirmation/deep analysis
	if len(patternMatches) > 0 {
		aiVulns, err := a.analyzePatternMatches(ctx, projectPath, patternMatches, verbose)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "AI analysis warning: %v (falling back to pattern-only results)\n", err)
			}
			return patternVulns, nil
		}
		// AI results replace pattern matches when available (AI confirms/dismisses)
		if len(aiVulns) > 0 {
			return aiVulns, nil
		}
	}

	// Step 3: Also scan key source files that weren't flagged by patterns
	aiVulns, err := a.analyzeSourceFiles(ctx, projectPath, verbose)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "AI source analysis warning: %v\n", err)
		}
		return patternVulns, nil
	}

	// Combine pattern and AI results
	return append(patternVulns, aiVulns...), nil
}

// analyzePatternMatches sends flagged code snippets to GPT-4 for deep analysis.
func (a *OpenAIAnalyzer) analyzePatternMatches(ctx context.Context, projectPath string, matches []PatternMatch, verbose bool) ([]models.Vulnerability, error) {
	// Build snippets for the prompt — include surrounding context
	var snippetParts []string
	for _, m := range matches {
		context, err := getCodeContext(m.FilePath, m.Line, 5)
		if err != nil {
			context = m.Content
		}

		relPath, _ := filepath.Rel(projectPath, m.FilePath)
		if relPath == "" {
			relPath = m.FilePath
		}

		ext := filepath.Ext(m.FilePath)
		snippetParts = append(snippetParts, fmt.Sprintf(
			snippetTemplate,
			relPath, m.Line, ext, m.Rule.Name, context,
		))

		// Limit token usage — max 20 snippets per batch
		if len(snippetParts) >= 20 {
			break
		}
	}

	prompt := fmt.Sprintf(batchAnalysisPromptTemplate, strings.Join(snippetParts, "\n"))

	return a.callOpenAI(ctx, prompt, projectPath, verbose)
}

// analyzeSourceFiles scans important source files for additional vulnerabilities.
func (a *OpenAIAnalyzer) analyzeSourceFiles(ctx context.Context, projectPath string, verbose bool) ([]models.Vulnerability, error) {
	// Find entry point files and important source files
	importantFiles := findImportantFiles(projectPath)
	if len(importantFiles) == 0 {
		return nil, nil
	}

	var allVulns []models.Vulnerability
	for _, filePath := range importantFiles {
		content, err := readFileContent(filePath, 500) // max 500 lines
		if err != nil {
			continue
		}

		relPath, _ := filepath.Rel(projectPath, filePath)
		if relPath == "" {
			relPath = filePath
		}

		ext := filepath.Ext(filePath)
		lang := extToLanguage(ext)

		prompt := fmt.Sprintf(analysisPromptTemplate, lang, relPath, content)

		vulns, err := a.callOpenAI(ctx, prompt, projectPath, verbose)
		if err != nil {
			continue
		}
		allVulns = append(allVulns, vulns...)
	}

	return allVulns, nil
}

func (a *OpenAIAnalyzer) callOpenAI(ctx context.Context, userPrompt, projectPath string, verbose bool) ([]models.Vulnerability, error) {
	if verbose {
		fmt.Fprintf(os.Stderr, "  Sending code to %s for analysis...\n", a.model)
	}

	resp, err := a.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: a.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: userPrompt},
		},
		Temperature: 0.1, // Low temperature for consistent, precise results
	})
	if err != nil {
		return nil, fmt.Errorf("openai api call failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("openai returned no choices")
	}

	content := resp.Choices[0].Message.Content
	content = extractJSONArray(content)

	var results []aiVulnResult
	if err := json.Unmarshal([]byte(content), &results); err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "  Warning: could not parse AI response as JSON: %v\n", err)
		}
		return nil, nil
	}

	var vulns []models.Vulnerability
	for _, r := range results {
		filePath := r.File
		if !filepath.IsAbs(filePath) {
			filePath = filepath.Join(projectPath, filePath)
		}

		vulns = append(vulns, models.Vulnerability{
			ID:        r.ID,
			Summary:   r.Name,
			Details:   r.Description + "\n\nRecommendation: " + r.Recommendation,
			Severity:  models.Severity(strings.ToUpper(r.Severity)),
			Source:    models.SourceAIAnalysis,
			FilePath:  filePath,
			StartLine: int(r.Line),
			EndLine:   int(r.Line),
		})
	}

	return vulns, nil
}

// aiEnrichmentResult represents the AI's enrichment output for a single vulnerability.
type aiEnrichmentResult struct {
	VulnID               string `json:"vuln_id"`
	Summary              string `json:"summary"`
	LikelyImpact         string `json:"likely_impact"`
	Confidence           string `json:"confidence"`
	MinimalRemediation   string `json:"minimal_remediation"`
	SuppressionRationale string `json:"suppression_rationale"`
}

// EnrichVulnerabilities sends existing vulnerabilities through the AI enrichment layer.
// It builds structured evidence for each vuln, sends them to the model, and attaches
// the resulting AIEnrichment to each vulnerability.
func (a *OpenAIAnalyzer) EnrichVulnerabilities(ctx context.Context, vulns []models.Vulnerability, projectPath string, verbose bool) []models.Vulnerability {
	if len(vulns) == 0 {
		return vulns
	}

	// Build evidence blocks
	var evidenceBlocks []string
	for i := range vulns {
		ev := BuildEvidence(vulns[i], projectPath)
		evidenceBlocks = append(evidenceBlocks, FormatEvidenceForPrompt(ev, i+1))
	}

	// Batch in groups of 20 to stay within token limits
	const batchSize = 20
	enrichmentMap := make(map[string]*models.AIEnrichment)

	for start := 0; start < len(evidenceBlocks); start += batchSize {
		end := start + batchSize
		if end > len(evidenceBlocks) {
			end = len(evidenceBlocks)
		}
		batch := evidenceBlocks[start:end]

		prompt := fmt.Sprintf(enrichmentPromptTemplate, len(batch), strings.Join(batch, "\n\n"))

		results, err := a.callEnrichment(ctx, prompt, verbose)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "  AI enrichment warning (batch %d-%d): %v\n", start, end-1, err)
			}
			continue
		}

		for _, r := range results {
			enrichmentMap[r.VulnID] = &models.AIEnrichment{
				Summary:              r.Summary,
				LikelyImpact:         r.LikelyImpact,
				Confidence:           strings.ToUpper(r.Confidence),
				MinimalRemediation:   r.MinimalRemediation,
				SuppressionRationale: r.SuppressionRationale,
			}
		}
	}

	// Attach enrichment to vulnerabilities
	for i := range vulns {
		if enrichment, ok := enrichmentMap[vulns[i].ID]; ok {
			vulns[i].AIEnrichment = enrichment
		}
	}

	return vulns
}

// callEnrichment sends the enrichment prompt to the AI and parses the structured response.
func (a *OpenAIAnalyzer) callEnrichment(ctx context.Context, userPrompt string, verbose bool) ([]aiEnrichmentResult, error) {
	if verbose {
		fmt.Fprintf(os.Stderr, "  Sending findings to %s for enrichment...\n", a.model)
	}

	resp, err := a.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: a.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: enrichmentSystemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: userPrompt},
		},
		Temperature: 0.1,
	})
	if err != nil {
		return nil, fmt.Errorf("openai enrichment call failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("openai returned no choices for enrichment")
	}

	content := resp.Choices[0].Message.Content
	content = extractJSONArray(content)

	var results []aiEnrichmentResult
	if err := json.Unmarshal([]byte(content), &results); err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "  Warning: could not parse AI enrichment response: %v\n", err)
		}
		return nil, nil
	}

	return results, nil
}

// getCodeContext reads lines around a target line number for context.
func getCodeContext(filePath string, targetLine, contextLines int) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	startLine := targetLine - contextLines
	if startLine < 1 {
		startLine = 1
	}
	endLine := targetLine + contextLines

	var lines []string
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum >= startLine && lineNum <= endLine {
			lines = append(lines, fmt.Sprintf("%d: %s", lineNum, scanner.Text()))
		}
		if lineNum > endLine {
			break
		}
	}

	return strings.Join(lines, "\n"), scanner.Err()
}

// findImportantFiles identifies key source files to analyze (entry points, config, auth).
func findImportantFiles(projectPath string) []string {
	importantPatterns := []string{
		"main.go", "app.go", "server.go", "handler*.go", "auth*.go", "middleware*.go",
		"app.py", "main.py", "server.py", "views.py", "auth*.py", "settings.py",
		"App.java", "Main.java", "*Controller.java", "*Service.java", "*Auth*.java",
		"app.js", "server.js", "index.js", "app.ts", "server.ts", "index.ts",
		"routes/*.go", "routes/*.py", "routes/*.js", "routes/*.ts",
	}

	var files []string
	for _, pattern := range importantPatterns {
		fullPattern := filepath.Join(projectPath, pattern)
		matches, err := filepath.Glob(fullPattern)
		if err == nil {
			files = append(files, matches...)
		}
		// Also check one level deep
		fullPattern = filepath.Join(projectPath, "*", pattern)
		matches, err = filepath.Glob(fullPattern)
		if err == nil {
			files = append(files, matches...)
		}
	}

	// Limit to 10 files to control API costs
	if len(files) > 10 {
		files = files[:10]
	}

	return files
}

// readFileContent reads up to maxLines from a file.
func readFileContent(filePath string, maxLines int) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) >= maxLines {
			break
		}
	}

	return strings.Join(lines, "\n"), scanner.Err()
}

func extToLanguage(ext string) string {
	switch ext {
	case ".go":
		return "Go"
	case ".py":
		return "Python"
	case ".java":
		return "Java"
	case ".js", ".jsx":
		return "JavaScript"
	case ".ts", ".tsx":
		return "TypeScript"
	default:
		return "source"
	}
}
