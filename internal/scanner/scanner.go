package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chavakula/calvigil/internal/analyzer"
	"github.com/chavakula/calvigil/internal/config"
	"github.com/chavakula/calvigil/internal/detector"
	"github.com/chavakula/calvigil/internal/matcher"
	"github.com/chavakula/calvigil/internal/models"
	"github.com/chavakula/calvigil/internal/parser"
	"github.com/chavakula/calvigil/internal/reporter"
)

// Scanner orchestrates the full vulnerability scanning pipeline.
type Scanner struct {
	opts     models.ScanOptions
	cfg      *config.Config
	reporter reporter.Reporter
}

// New creates a new Scanner from the given options.
func New(opts models.ScanOptions) (*Scanner, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return &Scanner{
		opts:     opts,
		cfg:      cfg,
		reporter: reporter.ForFormat(opts.Format),
	}, nil
}

// Run executes the full scan pipeline: detect -> parse -> match -> analyze -> report.
func (s *Scanner) Run(ctx context.Context) error {
	start := time.Now()

	result := &models.ScanResult{
		ProjectPath: s.opts.Path,
		ScannedAt:   start,
	}

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "Scanning %s ...\n\n", s.opts.Path)
	}

	// Step 1: Detect ecosystems
	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "Detecting project ecosystems...\n")
	}

	files, ecosystems, err := detector.Detect(s.opts.Path)
	if err != nil {
		return fmt.Errorf("ecosystem detection failed: %w", err)
	}
	result.Ecosystems = ecosystems

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Found %d manifest files across %d ecosystems\n", len(files), len(ecosystems))
		for _, f := range files {
			fmt.Fprintf(os.Stderr, "   - %s (%s)\n", f.Filename, f.Ecosystem)
		}
		fmt.Fprintln(os.Stderr)
	}

	var allVulns []models.Vulnerability

	// Step 2: Parse dependencies and match against CVE databases
	if !s.opts.SkipDeps {
		depVulns, totalPkgs, errs := s.scanDependencies(ctx, files)
		result.TotalPackages = totalPkgs
		allVulns = append(allVulns, depVulns...)
		result.Errors = append(result.Errors, errs...)
	}

	// Step 3: AI-powered source code analysis
	if !s.opts.SkipAI {
		aiVulns, errs := s.scanSourceCode(ctx)
		allVulns = append(allVulns, aiVulns...)
		result.Errors = append(result.Errors, errs...)
	}

	// Step 3a: Semgrep SAST analysis
	if !s.opts.SkipSemgrep {
		sgVulns, errs := s.scanSemgrep(ctx)
		allVulns = append(allVulns, sgVulns...)
		result.Errors = append(result.Errors, errs...)
	}

	// Step 3b: Populate dependency paths and reachability evidence
	if len(allVulns) > 0 {
		populateDepPaths(allVulns, s.opts.Path)
		populateReachability(allVulns, s.opts.Path, s.opts.Verbose)
	}

	// Step 3.5: AI enrichment layer — enrich ALL vulnerabilities with structured analysis
	if !s.opts.SkipAI && len(allVulns) > 0 {
		enricher := s.getAIEnricher()
		if enricher != nil {
			if s.opts.Verbose {
				fmt.Fprintf(os.Stderr, "Running AI enrichment on %d findings...\n", len(allVulns))
			}
			allVulns = enricher.EnrichVulnerabilities(ctx, allVulns, s.opts.Path, s.opts.Verbose)
			if s.opts.Verbose {
				enriched := 0
				for _, v := range allVulns {
					if v.AIEnrichment != nil {
						enriched++
					}
				}
				fmt.Fprintf(os.Stderr, "   Enriched %d/%d findings\n\n", enriched, len(allVulns))
			}
		}
	}

	// Step 4: Filter by severity if specified
	if s.opts.SeverityFilter != "" {
		allVulns = filterBySeverity(allVulns, s.opts.SeverityFilter)
	}

	result.Vulnerabilities = allVulns
	result.Duration = time.Since(start)

	// Step 5: Report results
	return s.writeReport(result)
}

// scanDependencies parses manifest files and queries vulnerability databases.
func (s *Scanner) scanDependencies(ctx context.Context, files []detector.DetectedFile) ([]models.Vulnerability, int, []string) {
	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "Parsing dependencies...\n")
	}

	// Parse all dependency files
	var allPackages []models.Package
	var errs []string

	for _, f := range files {
		p := parser.ForFile(f.Filename)
		if p == nil {
			continue
		}

		file, err := os.Open(f.Path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("cannot open %s: %v", f.Path, err))
			continue
		}

		pkgs, err := p.Parse(file, f.Path)
		file.Close()
		if err != nil {
			errs = append(errs, fmt.Sprintf("cannot parse %s: %v", f.Path, err))
			continue
		}

		allPackages = append(allPackages, pkgs...)

		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "   Parsed %d packages from %s\n", len(pkgs), f.Filename)
		}
	}

	// Generate PURLs for all packages
	for i := range allPackages {
		allPackages[i].EnsurePURL()
	}

	if len(allPackages) == 0 {
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "   No packages found to scan\n\n")
		}
		return nil, 0, errs
	}

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Total: %d packages\n\n", len(allPackages))
		fmt.Fprintf(os.Stderr, "Querying vulnerability databases...\n")
	}

	// Build matchers
	matchers := []matcher.Matcher{
		matcher.NewOSVMatcher(),
	}

	if s.cfg.NVDKey != "" {
		matchers = append(matchers, matcher.NewNVDMatcher(s.cfg.NVDKey))
	} else if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Skipping NVD (no API key configured)\n")
	}

	if s.cfg.GitHubToken != "" {
		matchers = append(matchers, matcher.NewGitHubAdvisoryMatcher(s.cfg.GitHubToken))
	} else if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Skipping GitHub Advisory (no token configured)\n")
	}

	aggregated := matcher.NewAggregatedMatcher(matchers...)
	vulns, err := aggregated.Match(ctx, allPackages)
	if err != nil {
		errs = append(errs, fmt.Sprintf("vulnerability matching error: %v", err))
	}

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Found %d dependency vulnerabilities\n\n", len(vulns))
	}

	return vulns, len(allPackages), errs
}

// scanSourceCode runs pattern matching and AI analysis on source files.
func (s *Scanner) scanSourceCode(ctx context.Context) ([]models.Vulnerability, []string) {
	var errs []string

	provider := s.resolveAIProvider()
	if provider == "" {
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "Running pattern-based code analysis (no AI provider available)...\n")
		}

		// Run pattern matching only
		matches, err := analyzer.ScanPatterns(s.opts.Path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("pattern scan error: %v", err))
			return nil, errs
		}

		vulns := analyzer.PatternMatchesToVulnerabilities(matches)
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "   Found %d potential issues via pattern matching\n\n", len(vulns))
		}

		return vulns, errs
	}

	switch provider {
	case "ollama":
		url, model := s.ollamaSettings()
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "Running AI-powered code analysis (Ollama: %s @ %s)...\n", model, url)
		}
		ai := analyzer.NewOllamaAnalyzer(url, model)
		vulns, err := ai.Analyze(ctx, s.opts.Path, s.opts.Verbose)
		if err != nil {
			errs = append(errs, fmt.Sprintf("Ollama analysis error: %v", err))
		}
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "   Found %d issues via code analysis\n\n", len(vulns))
		}
		return vulns, errs

	default: // openai
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "Running AI-powered code analysis (model: %s)...\n", s.cfg.OpenAIModel)
		}
		ai := analyzer.NewOpenAIAnalyzer(s.cfg.OpenAIKey, s.cfg.OpenAIModel)
		vulns, err := ai.Analyze(ctx, s.opts.Path, s.opts.Verbose)
		if err != nil {
			errs = append(errs, fmt.Sprintf("AI analysis error: %v", err))
		}
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "   Found %d issues via code analysis\n\n", len(vulns))
		}
		return vulns, errs
	}
}

// scanSemgrep runs Semgrep CE SAST analysis on source files.
func (s *Scanner) scanSemgrep(ctx context.Context) ([]models.Vulnerability, []string) {
	var errs []string

	sg := analyzer.NewSemgrepAnalyzer(s.opts.SemgrepRules, s.opts.Verbose)
	if !sg.Available() {
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "Skipping Semgrep analysis (semgrep not installed)\n")
		}
		return nil, nil
	}

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "Running Semgrep SAST analysis...\n")
	}

	vulns, err := sg.Analyze(ctx, s.opts.Path, s.opts.Verbose)
	if err != nil {
		errs = append(errs, fmt.Sprintf("semgrep analysis error: %v", err))
		return nil, errs
	}

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Found %d issues via Semgrep\n\n", len(vulns))
	}

	return vulns, errs
}

// writeReport sends the scan result to the appropriate output.
func (s *Scanner) writeReport(result *models.ScanResult) error {
	var w io.Writer = os.Stdout

	if s.opts.OutputFile != "" {
		f, err := os.Create(s.opts.OutputFile)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	return s.reporter.Report(result, w)
}

// filterBySeverity filters vulnerabilities to only include those at or above the minimum severity.
func filterBySeverity(vulns []models.Vulnerability, minSeverity models.Severity) []models.Vulnerability {
	minRank := minSeverity.Rank()
	if minRank == 0 {
		// For string matching, try case-insensitive
		switch strings.ToUpper(string(minSeverity)) {
		case "CRITICAL":
			minRank = models.SeverityCritical.Rank()
		case "HIGH":
			minRank = models.SeverityHigh.Rank()
		case "MEDIUM":
			minRank = models.SeverityMedium.Rank()
		case "LOW":
			minRank = models.SeverityLow.Rank()
		default:
			return vulns
		}
	}

	var filtered []models.Vulnerability
	for _, v := range vulns {
		if v.Severity.Rank() >= minRank {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// populateDepPaths sets the DepPath field on dependency vulnerabilities
// to show the path from the project through the manifest to the vulnerable package.
func populateDepPaths(vulns []models.Vulnerability, projectPath string) {
	projectName := filepath.Base(projectPath)
	for i := range vulns {
		if vulns[i].DepPath != "" {
			continue
		}
		pkg := vulns[i].Package
		if pkg.Name == "" {
			continue
		}
		manifest := filepath.Base(pkg.FilePath)
		if manifest == "" || manifest == "." {
			manifest = string(pkg.Ecosystem)
		}
		vulns[i].DepPath = projectName + " → " + manifest + " → " + pkg.Name + "@" + pkg.Version
	}
}

// populateReachability does a lightweight check to determine if vulnerable packages
// are actually imported/referenced in source code. Code-analysis and Semgrep findings
// are marked as directly reachable since they matched actual source code.
func populateReachability(vulns []models.Vulnerability, projectPath string, verbose bool) {
	// Build a set of package names from dependency vulns that need reachability checks
	needCheck := make(map[string]bool)
	for i := range vulns {
		if vulns[i].Reachable != "" {
			continue
		}
		switch vulns[i].Source {
		case models.SourcePatternMatch, models.SourceAIAnalysis, models.SourceSemgrep:
			vulns[i].Reachable = "direct — code pattern matched in source"
		case models.SourceOSV, models.SourceNVD, models.SourceGitHubAdv:
			if vulns[i].Package.Name != "" {
				needCheck[vulns[i].Package.Name] = false
			}
		}
	}

	if len(needCheck) == 0 {
		return
	}

	// Walk source files and look for import/require/from statements referencing the packages
	importPatterns := buildImportPatterns(needCheck)
	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := info.Name()
			if base == "node_modules" || base == ".git" || base == "vendor" ||
				base == "__pycache__" || base == "target" || base == "build" || base == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".go" && ext != ".py" && ext != ".js" && ext != ".ts" &&
			ext != ".jsx" && ext != ".tsx" && ext != ".java" {
			return nil
		}
		scanFileForImports(path, importPatterns)
		return nil
	})

	// Apply reachability results back to vulnerabilities
	for i := range vulns {
		if vulns[i].Reachable != "" {
			continue
		}
		pkgName := vulns[i].Package.Name
		if pkgName == "" {
			continue
		}
		if found, ok := importPatterns[pkgName]; ok && found {
			vulns[i].Reachable = "imported — package is referenced in source code"
		} else {
			vulns[i].Reachable = "unknown — no direct import found in scanned source files"
		}
	}
}

// buildImportPatterns creates a map of package names to check, initially all false.
func buildImportPatterns(needCheck map[string]bool) map[string]bool {
	result := make(map[string]bool, len(needCheck))
	for pkg := range needCheck {
		result[pkg] = false
	}
	return result
}

// scanFileForImports reads a source file line by line and marks packages as found
// if they appear in import/require/from statements.
func scanFileForImports(filePath string, patterns map[string]bool) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for pkg := range patterns {
			if patterns[pkg] {
				continue // already found
			}
			if strings.Contains(line, pkg) {
				patterns[pkg] = true
			}
		}
	}
}

// enricher is the interface both OpenAI and Ollama analyzers satisfy for enrichment.
type enricher interface {
	EnrichVulnerabilities(ctx context.Context, vulns []models.Vulnerability, projectPath string, verbose bool) []models.Vulnerability
}

// resolveAIProvider determines which AI provider to use.
// Returns "openai", "ollama", or "" (none available).
func (s *Scanner) resolveAIProvider() string {
	provider := strings.ToLower(s.opts.AIProvider)
	if provider == "" {
		provider = "auto"
	}

	switch provider {
	case "ollama":
		return "ollama"
	case "openai":
		if s.cfg.OpenAIKey != "" {
			return "openai"
		}
		return ""
	default: // auto
		// Prefer Ollama if configured and reachable
		url, model := s.ollamaSettings()
		if model != "" {
			ol := analyzer.NewOllamaAnalyzer(url, model)
			if ol.Available() {
				return "ollama"
			}
		}
		// Fall back to OpenAI if key is available
		if s.cfg.OpenAIKey != "" {
			return "openai"
		}
		return ""
	}
}

// ollamaSettings returns the effective Ollama URL and model from CLI flags or config.
func (s *Scanner) ollamaSettings() (string, string) {
	url := s.opts.OllamaURL
	if url == "" {
		url = s.cfg.OllamaURL
	}
	model := s.opts.OllamaModel
	if model == "" {
		model = s.cfg.OllamaModel
	}
	return url, model
}

// getAIEnricher returns the appropriate AI enricher based on provider selection, or nil.
func (s *Scanner) getAIEnricher() enricher {
	provider := s.resolveAIProvider()
	switch provider {
	case "ollama":
		url, model := s.ollamaSettings()
		return analyzer.NewOllamaAnalyzer(url, model)
	case "openai":
		return analyzer.NewOpenAIAnalyzer(s.cfg.OpenAIKey, s.cfg.OpenAIModel)
	default:
		return nil
	}
}
