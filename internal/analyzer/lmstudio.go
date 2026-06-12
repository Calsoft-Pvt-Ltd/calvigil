package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// LMStudioAnalyzer uses a local LM Studio instance for AI-powered code analysis.
// LM Studio exposes an OpenAI-compatible API at /v1/chat/completions.
type LMStudioAnalyzer struct {
	baseURL   string // e.g. "http://localhost:1234"
	model     string // e.g. "lmstudio-community/Meta-Llama-3-8B-Instruct-GGUF"
	client    *http.Client
	SkipTests bool // Skip test files during scanning
}

// lmstudioTimeout is the maximum time to wait for a single LM Studio API call.
const lmstudioTimeout = 5 * time.Minute

// NewLMStudioAnalyzer creates a new analyzer targeting a local LM Studio instance.
func NewLMStudioAnalyzer(baseURL, model string) *LMStudioAnalyzer {
	if baseURL == "" {
		baseURL = "http://localhost:1234"
	}
	return &LMStudioAnalyzer{
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		client:  &http.Client{Timeout: lmstudioTimeout},
	}
}

// Available checks if the LM Studio instance is reachable.
func (l *LMStudioAnalyzer) Available() bool {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(l.baseURL + "/v1/models")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Analyze runs pattern matching and then sends flagged code to LM Studio for deep analysis.
func (l *LMStudioAnalyzer) Analyze(ctx context.Context, projectPath string, verbose bool) ([]models.Vulnerability, error) {
	// Step 1: Run pattern matching first (fast, no API cost)
	patternMatches, err := ScanPatterns(projectPath, l.SkipTests)
	if err != nil {
		return nil, fmt.Errorf("pattern scan failed: %w", err)
	}

	patternVulns := PatternMatchesToVulnerabilities(patternMatches)

	// Step 2: Send pattern matches to LM Studio for confirmation
	if len(patternMatches) > 0 {
		aiVulns, err := l.analyzePatternMatches(ctx, projectPath, patternMatches, verbose)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "  LM Studio analysis warning: %v (falling back to pattern-only results)\n", err)
			}
			return patternVulns, nil
		}
		if len(aiVulns) > 0 {
			return aiVulns, nil
		}
	}

	// Step 3: Scan key source files
	aiVulns, err := l.analyzeSourceFiles(ctx, projectPath, verbose)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "  LM Studio source analysis warning: %v\n", err)
		}
		return patternVulns, nil
	}

	return append(patternVulns, aiVulns...), nil
}

func (l *LMStudioAnalyzer) analyzePatternMatches(ctx context.Context, projectPath string, matches []PatternMatch, verbose bool) ([]models.Vulnerability, error) {
	var snippetParts []string
	for _, m := range matches {
		codeCtx, err := getCodeContext(m.FilePath, m.Line, 5)
		if err != nil {
			codeCtx = m.Content
		}
		relPath, _ := filepath.Rel(projectPath, m.FilePath)
		if relPath == "" {
			relPath = m.FilePath
		}
		ext := filepath.Ext(m.FilePath)
		snippetParts = append(snippetParts, fmt.Sprintf(snippetTemplate, relPath, m.Line, ext, m.Rule.Name, codeCtx))
		if len(snippetParts) >= 15 {
			break
		}
	}
	prompt := fmt.Sprintf(batchAnalysisPromptTemplate, strings.Join(snippetParts, "\n"))
	return l.callLMStudio(ctx, systemPrompt, prompt, projectPath, verbose)
}

func (l *LMStudioAnalyzer) analyzeSourceFiles(ctx context.Context, projectPath string, verbose bool) ([]models.Vulnerability, error) {
	importantFiles := findImportantFiles(projectPath)
	if len(importantFiles) == 0 {
		return nil, nil
	}

	var allVulns []models.Vulnerability
	for _, filePath := range importantFiles {
		content, err := readFileContent(filePath, 300)
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
		vulns, err := l.callLMStudio(ctx, systemPrompt, prompt, projectPath, verbose)
		if err != nil {
			continue
		}
		allVulns = append(allVulns, vulns...)
	}
	return allVulns, nil
}

// callLMStudio sends a chat completion request to LM Studio and parses the response.
func (l *LMStudioAnalyzer) callLMStudio(ctx context.Context, sysPrompt, userPrompt, projectPath string, verbose bool) ([]models.Vulnerability, error) {
	if verbose {
		fmt.Fprintf(os.Stderr, "  Sending code to LM Studio (%s) for analysis...\n", l.model)
		fmt.Fprintf(os.Stderr, "    Prompt size: %d chars (system: %d, user: %d)\n", len(sysPrompt)+len(userPrompt), len(sysPrompt), len(userPrompt))
	}

	start := time.Now()
	content, err := l.chatCompletion(ctx, sysPrompt, userPrompt)
	elapsed := time.Since(start)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "    Failed after %s: %v\n", elapsed.Round(time.Millisecond), err)
		}
		return nil, err
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "    Response received in %s (%d chars)\n", elapsed.Round(time.Millisecond), len(content))
		preview := content
		if len(preview) > 300 {
			preview = preview[:300] + "..."
		}
		fmt.Fprintf(os.Stderr, "    Response preview: %s\n", strings.ReplaceAll(preview, "\n", " "))
	}

	content = extractJSONArray(content)

	var results []aiVulnResult
	if err := json.Unmarshal([]byte(content), &results); err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "    JSON parse failed: %v\n", err)
			if len(content) > 200 {
				fmt.Fprintf(os.Stderr, "    Extracted JSON (first 200 chars): %s\n", content[:200])
			} else {
				fmt.Fprintf(os.Stderr, "    Extracted JSON: %s\n", content)
			}
		}
		return nil, nil
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "    Parsed %d vulnerability findings from AI response\n", len(results))
	}

	var vulns []models.Vulnerability
	for _, r := range results {
		filePath := r.File
		if !filepath.IsAbs(filePath) && projectPath != "" {
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

// EnrichVulnerabilities sends existing vulnerabilities through the AI enrichment layer using LM Studio.
func (l *LMStudioAnalyzer) EnrichVulnerabilities(ctx context.Context, vulns []models.Vulnerability, projectPath string, verbose bool) []models.Vulnerability {
	if len(vulns) == 0 {
		return vulns
	}

	var evidenceBlocks []string
	for i := range vulns {
		ev := BuildEvidence(vulns[i], projectPath)
		evidenceBlocks = append(evidenceBlocks, FormatEvidenceForPrompt(ev, i+1))
	}

	const batchSize = 10
	enrichmentMap := make(map[string]*models.AIEnrichment)

	for start := 0; start < len(evidenceBlocks); start += batchSize {
		end := start + batchSize
		if end > len(evidenceBlocks) {
			end = len(evidenceBlocks)
		}
		batch := evidenceBlocks[start:end]

		if verbose {
			fmt.Fprintf(os.Stderr, "  Enrichment batch %d/%d (findings %d-%d of %d)\n",
				(start/batchSize)+1, (len(evidenceBlocks)+batchSize-1)/batchSize, start+1, end, len(evidenceBlocks))
		}

		prompt := fmt.Sprintf(enrichmentPromptTemplate, len(batch), strings.Join(batch, "\n\n"))

		results, err := l.callEnrichment(ctx, prompt, verbose)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "  LM Studio enrichment warning (batch %d-%d): %v\n", start, end-1, err)
			}
			continue
		}

		for _, r := range results {
			enrichmentMap[r.VulnID] = &models.AIEnrichment{
				Summary:              r.Summary,
				LikelyImpact:         r.LikelyImpact,
				Confidence:           strings.ToUpper(r.Confidence),
				AICodeIndicator:      strings.ToUpper(r.AICodeIndicator),
				MinimalRemediation:   r.MinimalRemediation,
				SuppressionRationale: r.SuppressionRationale,
			}
		}
	}

	for i := range vulns {
		if enrichment, ok := enrichmentMap[vulns[i].ID]; ok {
			vulns[i].AIEnrichment = enrichment
		}
	}

	return vulns
}

func (l *LMStudioAnalyzer) callEnrichment(ctx context.Context, userPrompt string, verbose bool) ([]aiEnrichmentResult, error) {
	if verbose {
		fmt.Fprintf(os.Stderr, "  Sending findings to LM Studio (%s) for enrichment...\n", l.model)
		fmt.Fprintf(os.Stderr, "    Prompt size: %d chars\n", len(enrichmentSystemPrompt)+len(userPrompt))
	}

	start := time.Now()
	content, err := l.chatCompletion(ctx, enrichmentSystemPrompt, userPrompt)
	elapsed := time.Since(start)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "    Failed after %s: %v\n", elapsed.Round(time.Millisecond), err)
		}
		return nil, fmt.Errorf("lmstudio enrichment call failed: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "    Response received in %s (%d chars)\n", elapsed.Round(time.Millisecond), len(content))
	}

	content = extractJSONArray(content)

	var results []aiEnrichmentResult
	if err := json.Unmarshal([]byte(content), &results); err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "    JSON parse failed: %v\n", err)
		}
		return nil, nil
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "    Parsed %d enrichment results\n", len(results))
	}

	return results, nil
}

// chatCompletion sends a request to LM Studio's OpenAI-compatible chat endpoint.
func (l *LMStudioAnalyzer) chatCompletion(ctx context.Context, sysPrompt, userPrompt string) (string, error) {
	reqBody := ollamaChatRequest{
		Model: l.model,
		Messages: []ollamaChatMessage{
			{Role: "system", Content: sysPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.1,
		Stream:      false,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("cannot marshal request: %w", err)
	}

	url := l.baseURL + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", fmt.Errorf("cannot create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := l.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("lmstudio request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf := make([]byte, 512)
		n, _ := resp.Body.Read(buf)
		return "", fmt.Errorf("lmstudio returned status %d: %s", resp.StatusCode, string(buf[:n]))
	}

	var chatResp ollamaChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", fmt.Errorf("cannot decode lmstudio response: %w", err)
	}

	if len(chatResp.Choices) > 0 {
		return chatResp.Choices[0].Message.Content, nil
	}

	return "", fmt.Errorf("lmstudio returned empty response")
}
