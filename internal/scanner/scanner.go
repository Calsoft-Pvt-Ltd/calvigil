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

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/analyzer"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/cache"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/config"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/detector"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/fsutil"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/license"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/matcher"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/parser"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/reporter"
)

const dependencyCacheSource = "aggregated-v3"

// Scanner orchestrates the full vulnerability scanning pipeline.
type Scanner struct {
	opts     models.ScanOptions
	cfg      *config.Config
	reporter reporter.Reporter
	cache    *cache.Cache
}

// New creates a new Scanner from the given options.
func New(opts models.ScanOptions) (*Scanner, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	s := &Scanner{
		opts:     opts,
		cfg:      cfg,
		reporter: reporter.ForFormat(opts.Format),
	}

	// Initialize vulnerability cache unless disabled
	if !opts.NoCache {
		ttl := cache.DefaultTTL
		if opts.CacheTTL != "" {
			if parsed, err := time.ParseDuration(opts.CacheTTL); err == nil {
				ttl = parsed
			}
		}
		s.cache = cache.New("", ttl)
	}

	return s, nil
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
		depVulns, allPackages, errs := s.scanDependencies(ctx, files)
		result.TotalPackages = len(allPackages)
		if len(allPackages) > 0 && !s.opts.Offline {
			license.ResolvePackages(ctx, allPackages, s.opts.Verbose)
		}
		result.Packages = allPackages
		allVulns = append(allVulns, depVulns...)
		result.Errors = append(result.Errors, errs...)

		// License compliance checking
		if s.opts.CheckLicenses && len(allPackages) > 0 {
			if s.opts.Verbose {
				fmt.Fprintf(os.Stderr, "Checking license compliance...\n")
			}

			issues := license.CheckPackages(allPackages)
			result.LicenseIssues = issues
			if s.opts.Verbose {
				fmt.Fprintf(os.Stderr, "   Found %d license issues\n\n", len(issues))
			}
		}
	} else if s.opts.VerifyIntegrity {
		// Even with --skip-deps, parse manifests for integrity verification
		allPackages, errs := s.parsePackages(files)
		result.TotalPackages = len(allPackages)
		result.Packages = allPackages
		result.Errors = append(result.Errors, errs...)
	}

	// Step 2a: Supply chain checks (run regardless of --skip-deps)
	if len(result.Packages) > 0 {
		// Lockfile integrity verification
		if s.opts.VerifyIntegrity {
			if s.opts.Offline {
				if s.opts.Verbose {
					fmt.Fprintf(os.Stderr, "Skipping lockfile integrity verification (--offline)\n")
				}
			} else if s.opts.Verbose {
				fmt.Fprintf(os.Stderr, "Verifying lockfile integrity hashes...\n")
			}
			if !s.opts.Offline {
				integrityIssues := parser.VerifyIntegrity(ctx, result.Packages, s.opts.Verbose)
				result.IntegrityIssues = integrityIssues
				if s.opts.Verbose {
					fmt.Fprintf(os.Stderr, "   Found %d integrity issues\n\n", len(integrityIssues))
				}
			}
		}

		// Phantom dependency detection (lockfile vs manifest consistency)
		consistencyIssues := parser.CheckConsistency(s.opts.Path, result.Packages)
		result.ConsistencyIssues = consistencyIssues
		if s.opts.Verbose && len(consistencyIssues) > 0 {
			fmt.Fprintf(os.Stderr, "   Found %d phantom/undeclared dependencies\n\n", len(consistencyIssues))
		}
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
		populateReachability(allVulns, s.opts.Path, s.opts.Verbose, s.opts.SkipTests)
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

// parsePackages parses all manifest files and returns the discovered packages.
func (s *Scanner) parsePackages(files []detector.DetectedFile) ([]models.Package, []string) {
	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "Parsing dependencies...\n")
	}

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
		return nil, errs
	}

	if s.opts.Verbose {
		direct, transitive := 0, 0
		for _, p := range allPackages {
			if p.Indirect {
				transitive++
			} else {
				direct++
			}
		}
		fmt.Fprintf(os.Stderr, "   Total: %d packages (%d direct, %d transitive)\n\n", len(allPackages), direct, transitive)
	}

	return allPackages, errs
}

// scanDependencies parses manifest files and queries vulnerability databases.
func (s *Scanner) scanDependencies(ctx context.Context, files []detector.DetectedFile) ([]models.Vulnerability, []models.Package, []string) {
	allPackages, errs := s.parsePackages(files)

	if len(allPackages) == 0 {
		return nil, nil, errs
	}

	if s.opts.Offline {
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "Skipping vulnerability databases and registry enrichment (--offline)\n\n")
		}
		return nil, allPackages, errs
	}

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "Querying vulnerability databases...\n")
	}

	matchers := s.dependencyMatchers()

	aggregated := matcher.NewAggregatedMatcher(matchers...)
	aggregated.SetVerbose(s.opts.Verbose)

	// Check cache before querying
	if s.cache != nil {
		if cached, ok := s.cache.Get(dependencyCacheSource, allPackages); ok {
			enrichment := s.enrichDependencyCVSS(ctx, cached)
			if enrichment.Enriched > 0 {
				if cacheErr := s.cache.Put(dependencyCacheSource, allPackages, cached); cacheErr != nil && s.opts.Verbose {
					fmt.Fprintf(os.Stderr, "   Cache write warning: %v\n", cacheErr)
				}
			}
			if s.opts.Verbose {
				fmt.Fprintf(os.Stderr, "   Using cached results (%d vulnerabilities)\n\n", len(cached))
			}
			return cached, allPackages, errs
		}
	}

	vulns, err := aggregated.Match(ctx, allPackages)
	if err != nil {
		errs = append(errs, fmt.Sprintf("vulnerability matching error: %v", err))
	}

	if len(vulns) > 0 {
		s.enrichDependencyCVSS(ctx, vulns)
	}

	// Enrich with the CISA Known Exploited Vulnerabilities catalog. This is
	// best-effort: failures never alter or remove findings.
	if len(vulns) > 0 {
		kev := matcher.NewKEVEnricher()
		if kevErr := kev.Enrich(ctx, vulns); kevErr != nil {
			if s.opts.Verbose {
				fmt.Fprintf(os.Stderr, "   KEV enrichment skipped: %v\n", kevErr)
			}
		} else if s.opts.Verbose {
			exploited := 0
			for i := range vulns {
				if vulns[i].KnownExploited {
					exploited++
				}
			}
			if exploited > 0 {
				fmt.Fprintf(os.Stderr, "   CISA KEV: %d finding(s) are known to be actively exploited\n", exploited)
			}
		}
	}

	// Store in cache
	if s.cache != nil && len(vulns) > 0 {
		if cacheErr := s.cache.Put(dependencyCacheSource, allPackages, vulns); cacheErr != nil && s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "   Cache write warning: %v\n", cacheErr)
		}
	}

	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Found %d dependency vulnerabilities\n\n", len(vulns))
	}

	return vulns, allPackages, errs
}

func (s *Scanner) enrichDependencyCVSS(ctx context.Context, vulns []models.Vulnerability) matcher.NVDEnrichmentResult {
	nvd := matcher.NewNVDMatcher(s.cfg.NVDKey)
	nvd.SetCacheEnabled(!s.opts.NoCache)
	result, err := nvd.EnrichCVSSByCVE(ctx, vulns)
	if err != nil {
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "   NVD CVSS enrichment skipped: %v\n", err)
		}
		return result
	}
	if s.opts.Verbose {
		switch {
		case result.Enriched > 0:
			if result.Batches > 1 {
				fmt.Fprintf(os.Stderr, "   NVD CVSS enrichment: filled %d finding(s) across %d batch request(s)\n",
					result.Enriched, result.Batches)
			} else {
				fmt.Fprintf(os.Stderr, "   NVD CVSS enrichment: filled %d finding(s)\n", result.Enriched)
			}
			if result.CacheHits > 0 || result.Retries > 0 || result.Failed > 0 {
				fmt.Fprintf(os.Stderr, "   NVD CVSS enrichment detail: cache_hits=%d retries=%d unavailable=%d\n",
					result.CacheHits, result.Retries, result.Failed)
			}
		case result.Requested > 0:
			if result.CacheHits > 0 || result.Failed > 0 || result.Retries > 0 {
				fmt.Fprintf(os.Stderr, "   NVD CVSS enrichment: no additional scores found (cache_hits=%d retries=%d unavailable=%d)\n",
					result.CacheHits, result.Retries, result.Failed)
			} else {
				fmt.Fprintf(os.Stderr, "   NVD CVSS enrichment: no additional scores found\n")
			}
		}
	}
	return result
}

func (s *Scanner) dependencyMatchers() []matcher.Matcher {
	matchers := []matcher.Matcher{
		matcher.NewOSVMatcher(),
	}

	if s.cfg.OSSIndexUser != "" && s.cfg.OSSIndexToken != "" {
		matchers = append(matchers, matcher.NewOSSIndexMatcher(s.cfg.OSSIndexUser, s.cfg.OSSIndexToken))
	} else if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Skipping OSS Index (credentials not configured)\n")
	}

	matchers = append(matchers, matcher.NewNVDMatcher(s.cfg.NVDKey))

	if s.cfg.GitHubToken != "" {
		matchers = append(matchers, matcher.NewGitHubAdvisoryMatcher(s.cfg.GitHubToken))
	} else if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "   Skipping GitHub Advisory (no token configured)\n")
	}

	return matchers
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
		matches, err := analyzer.ScanPatterns(s.opts.Path, s.opts.SkipTests)
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
		ai.SkipTests = s.opts.SkipTests
		vulns, err := ai.Analyze(ctx, s.opts.Path, s.opts.Verbose)
		if err != nil {
			errs = append(errs, fmt.Sprintf("Ollama analysis error: %v", err))
		}
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "   Found %d issues via code analysis\n\n", len(vulns))
		}
		return vulns, errs

	case "lmstudio":
		url, model := s.lmstudioSettings()
		if s.opts.Verbose {
			fmt.Fprintf(os.Stderr, "Running AI-powered code analysis (LM Studio: %s @ %s)...\n", model, url)
		}
		ai := analyzer.NewLMStudioAnalyzer(url, model)
		ai.SkipTests = s.opts.SkipTests
		vulns, err := ai.Analyze(ctx, s.opts.Path, s.opts.Verbose)
		if err != nil {
			errs = append(errs, fmt.Sprintf("LM Studio analysis error: %v", err))
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
		ai.SkipTests = s.opts.SkipTests
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
	sg.TrustProjectRules = s.opts.TrustProjectRules
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
		return vulns // UNKNOWN or empty — no filtering
	}

	filtered := make([]models.Vulnerability, 0, len(vulns))
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
		depLabel := pkg.Name + "@" + pkg.Version
		if pkg.Indirect {
			depLabel += " [transitive]"
		}
		vulns[i].DepPath = projectName + " → " + manifest + " → " + depLabel
	}
}

// populateReachability does a lightweight check to determine if vulnerable packages
// are actually imported/referenced in source code. Code-analysis and Semgrep findings
// are marked as directly reachable since they matched actual source code.
func populateReachability(vulns []models.Vulnerability, projectPath string, verbose bool, skipTests bool) {
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
			if path != projectPath && fsutil.ShouldSkipSubDir(info.Name()) {
				return filepath.SkipDir
			}
			if skipTests && path != projectPath && fsutil.IsTestDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if skipTests && fsutil.IsTestFile(path) {
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
	// Count how many packages still need finding; skip file if all found.
	remaining := 0
	for _, found := range patterns {
		if !found {
			remaining++
		}
	}
	if remaining == 0 {
		return
	}

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
				remaining--
				if remaining == 0 {
					return // all packages found — stop early
				}
			}
		}
	}
}

// enricher is the interface OpenAI, Ollama, and LM Studio analyzers satisfy for enrichment.
type enricher interface {
	EnrichVulnerabilities(ctx context.Context, vulns []models.Vulnerability, projectPath string, verbose bool) []models.Vulnerability
}

// resolveAIProvider determines which AI provider to use.
// Returns "openai", "ollama", "lmstudio", or "" (none available).
func (s *Scanner) resolveAIProvider() string {
	provider := strings.ToLower(s.opts.AIProvider)
	if provider == "" {
		provider = "auto"
	}

	switch provider {
	case "ollama":
		return "ollama"
	case "lmstudio":
		return "lmstudio"
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
		// Try LM Studio if configured and reachable
		lmsURL, lmsModel := s.lmstudioSettings()
		if lmsModel != "" {
			lms := analyzer.NewLMStudioAnalyzer(lmsURL, lmsModel)
			if lms.Available() {
				return "lmstudio"
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

// lmstudioSettings returns the effective LM Studio URL and model from CLI flags or config.
func (s *Scanner) lmstudioSettings() (string, string) {
	url := s.opts.LMStudioURL
	if url == "" {
		url = s.cfg.LMStudioURL
	}
	model := s.opts.LMStudioModel
	if model == "" {
		model = s.cfg.LMStudioModel
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
	case "lmstudio":
		url, model := s.lmstudioSettings()
		return analyzer.NewLMStudioAnalyzer(url, model)
	case "openai":
		return analyzer.NewOpenAIAnalyzer(s.cfg.OpenAIKey, s.cfg.OpenAIModel)
	default:
		return nil
	}
}
