package analyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/chavakula/calvigil/internal/models"
)

// OllamaAnalyzer uses a local Ollama instance for AI-powered code analysis.
// It communicates via Ollama's OpenAI-compatible /v1/chat/completions endpoint.
type OllamaAnalyzer struct {
	baseURL string // e.g. "http://localhost:11434"
	model   string // e.g. "llama3", "codellama", "mistral"
}

// NewOllamaAnalyzer creates a new analyzer targeting a local Ollama instance.
func NewOllamaAnalyzer(baseURL, model string) *OllamaAnalyzer {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return &OllamaAnalyzer{
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
	}
}

// ollamaChatRequest is the request body for Ollama's OpenAI-compatible chat endpoint.
type ollamaChatRequest struct {
	Model       string              `json:"model"`
	Messages    []ollamaChatMessage `json:"messages"`
	Temperature float64             `json:"temperature"`
	Stream      bool                `json:"stream"`
}

type ollamaChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ollamaChatResponse is the response from Ollama's chat endpoint.
type ollamaChatResponse struct {
	Choices []ollamaChatChoice `json:"choices"`
	// Non-OpenAI compat field (direct Ollama response)
	Message *ollamaChatMessage `json:"message,omitempty"`
}

type ollamaChatChoice struct {
	Message ollamaChatMessage `json:"message"`
}

// Available checks if the Ollama instance is reachable.
func (o *OllamaAnalyzer) Available() bool {
	resp, err := http.Get(o.baseURL + "/api/tags")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Analyze runs pattern matching and then sends flagged code to Ollama for deep analysis.
func (o *OllamaAnalyzer) Analyze(ctx context.Context, projectPath string, verbose bool) ([]models.Vulnerability, error) {
	// Step 1: Run pattern matching first (fast, no API cost)
	patternMatches, err := ScanPatterns(projectPath)
	if err != nil {
		return nil, fmt.Errorf("pattern scan failed: %w", err)
	}

	patternVulns := PatternMatchesToVulnerabilities(patternMatches)

	// Step 2: Send pattern matches to Ollama for confirmation
	if len(patternMatches) > 0 {
		aiVulns, err := o.analyzePatternMatches(ctx, projectPath, patternMatches, verbose)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "  Ollama analysis warning: %v (falling back to pattern-only results)\n", err)
			}
			return patternVulns, nil
		}
		if len(aiVulns) > 0 {
			return aiVulns, nil
		}
	}

	// Step 3: Scan key source files
	aiVulns, err := o.analyzeSourceFiles(ctx, projectPath, verbose)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "  Ollama source analysis warning: %v\n", err)
		}
		return patternVulns, nil
	}

	return append(patternVulns, aiVulns...), nil
}

func (o *OllamaAnalyzer) analyzePatternMatches(ctx context.Context, projectPath string, matches []PatternMatch, verbose bool) ([]models.Vulnerability, error) {
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
		if len(snippetParts) >= 15 { // smaller batch for local models (less context window)
			break
		}
	}
	prompt := fmt.Sprintf(batchAnalysisPromptTemplate, strings.Join(snippetParts, "\n"))
	return o.callOllama(ctx, systemPrompt, prompt, projectPath, verbose)
}

func (o *OllamaAnalyzer) analyzeSourceFiles(ctx context.Context, projectPath string, verbose bool) ([]models.Vulnerability, error) {
	importantFiles := findImportantFiles(projectPath)
	if len(importantFiles) == 0 {
		return nil, nil
	}

	var allVulns []models.Vulnerability
	for _, filePath := range importantFiles {
		content, err := readFileContent(filePath, 300) // smaller for local models
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
		vulns, err := o.callOllama(ctx, systemPrompt, prompt, projectPath, verbose)
		if err != nil {
			continue
		}
		allVulns = append(allVulns, vulns...)
	}
	return allVulns, nil
}

// callOllama sends a chat completion request to the Ollama API and parses the response.
func (o *OllamaAnalyzer) callOllama(ctx context.Context, sysPrompt, userPrompt, projectPath string, verbose bool) ([]models.Vulnerability, error) {
	if verbose {
		fmt.Fprintf(os.Stderr, "  Sending code to Ollama (%s) for analysis...\n", o.model)
	}

	content, err := o.chatCompletion(ctx, sysPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	// Use robust JSON extraction — local LLMs often wrap JSON in prose or markdown
	content = extractJSONArray(content)

	var results []aiVulnResult
	if err := json.Unmarshal([]byte(content), &results); err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "  Warning: could not parse Ollama response as JSON: %v\n", err)
		}
		return nil, nil
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

// EnrichVulnerabilities sends existing vulnerabilities through the AI enrichment layer using Ollama.
func (o *OllamaAnalyzer) EnrichVulnerabilities(ctx context.Context, vulns []models.Vulnerability, projectPath string, verbose bool) []models.Vulnerability {
	if len(vulns) == 0 {
		return vulns
	}

	var evidenceBlocks []string
	for i := range vulns {
		ev := BuildEvidence(vulns[i], projectPath)
		evidenceBlocks = append(evidenceBlocks, FormatEvidenceForPrompt(ev, i+1))
	}

	// Smaller batches for local models (less context window than GPT-4)
	const batchSize = 10
	enrichmentMap := make(map[string]*models.AIEnrichment)

	for start := 0; start < len(evidenceBlocks); start += batchSize {
		end := start + batchSize
		if end > len(evidenceBlocks) {
			end = len(evidenceBlocks)
		}
		batch := evidenceBlocks[start:end]

		prompt := fmt.Sprintf(enrichmentPromptTemplate, len(batch), strings.Join(batch, "\n\n"))

		results, err := o.callEnrichment(ctx, prompt, verbose)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "  Ollama enrichment warning (batch %d-%d): %v\n", start, end-1, err)
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

	for i := range vulns {
		if enrichment, ok := enrichmentMap[vulns[i].ID]; ok {
			vulns[i].AIEnrichment = enrichment
		}
	}

	return vulns
}

func (o *OllamaAnalyzer) callEnrichment(ctx context.Context, userPrompt string, verbose bool) ([]aiEnrichmentResult, error) {
	if verbose {
		fmt.Fprintf(os.Stderr, "  Sending findings to Ollama (%s) for enrichment...\n", o.model)
	}

	content, err := o.chatCompletion(ctx, enrichmentSystemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("ollama enrichment call failed: %w", err)
	}

	// Use robust JSON extraction — local LLMs often wrap JSON in prose or markdown
	content = extractJSONArray(content)

	var results []aiEnrichmentResult
	if err := json.Unmarshal([]byte(content), &results); err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "  Warning: could not parse Ollama enrichment response: %v\n", err)
		}
		return nil, nil
	}

	return results, nil
}

// chatCompletion sends a request to Ollama's OpenAI-compatible chat endpoint.
func (o *OllamaAnalyzer) chatCompletion(ctx context.Context, sysPrompt, userPrompt string) (string, error) {
	reqBody := ollamaChatRequest{
		Model: o.model,
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

	// Try OpenAI-compatible endpoint first, fall back to Ollama native
	url := o.baseURL + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", fmt.Errorf("cannot create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Fall back to native Ollama /api/chat endpoint
		return o.chatCompletionNative(ctx, sysPrompt, userPrompt)
	}

	var chatResp ollamaChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", fmt.Errorf("cannot decode ollama response: %w", err)
	}

	// OpenAI-compatible format
	if len(chatResp.Choices) > 0 {
		return chatResp.Choices[0].Message.Content, nil
	}

	// Ollama native format
	if chatResp.Message != nil {
		return chatResp.Message.Content, nil
	}

	return "", fmt.Errorf("ollama returned empty response")
}

// chatCompletionNative uses Ollama's native /api/chat endpoint as fallback.
func (o *OllamaAnalyzer) chatCompletionNative(ctx context.Context, sysPrompt, userPrompt string) (string, error) {
	type nativeRequest struct {
		Model    string              `json:"model"`
		Messages []ollamaChatMessage `json:"messages"`
		Stream   bool                `json:"stream"`
		Options  map[string]float64  `json:"options,omitempty"`
	}

	reqBody := nativeRequest{
		Model: o.model,
		Messages: []ollamaChatMessage{
			{Role: "system", Content: sysPrompt},
			{Role: "user", Content: userPrompt},
		},
		Stream:  false,
		Options: map[string]float64{"temperature": 0.1},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("cannot marshal request: %w", err)
	}

	url := o.baseURL + "/api/chat"
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", fmt.Errorf("cannot create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama native request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read a bit of the error body
		buf := make([]byte, 512)
		n, _ := resp.Body.Read(buf)
		return "", fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(buf[:n]))
	}

	// Response may be JSON lines (streaming) or single JSON object
	var fullContent strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer for large responses
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var chunk struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Done bool `json:"done"`
		}
		if err := json.Unmarshal([]byte(line), &chunk); err != nil {
			continue
		}
		fullContent.WriteString(chunk.Message.Content)
		if chunk.Done {
			break
		}
	}

	result := fullContent.String()
	if result == "" {
		return "", fmt.Errorf("ollama returned empty response")
	}
	return result, nil
}
