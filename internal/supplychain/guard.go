package supplychain

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/fsutil"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

const (
	DecisionAllow             = "allow"
	DecisionReviewBeforeMerge = "review_before_merge"
	DecisionBlockRelease      = "block_release"
	DecisionVerifyProvenance  = "verify_provenance"
)

// Options controls supply-chain guard analysis.
type Options struct {
	ProjectPath string
	Baseline    *models.ScanResult
	Offline     bool
}

// Analyze evaluates a scan result for supply-chain trust drift and suspicious
// local package behavior. The current implementation is intentionally
// deterministic and local-first; registry intelligence can be layered in later
// without changing the report model.
func Analyze(ctx context.Context, target *models.ScanResult, opts Options) *models.SupplyChainRisk {
	if target == nil {
		return nil
	}
	projectPath := opts.ProjectPath
	if projectPath == "" {
		projectPath = target.ProjectPath
	}

	findings := make([]models.SupplyChainFinding, 0)
	if opts.Baseline != nil {
		findings = append(findings, diffFindings(opts.Baseline, target)...)
	}
	findings = append(findings, consistencyFindings(target.ConsistencyIssues)...)
	findings = append(findings, localPackageFindings(ctx, projectPath, target.Packages)...)

	if len(findings) == 0 {
		return &models.SupplyChainRisk{
			Score:    0,
			Level:    "CLEAN",
			Decision: DecisionAllow,
			Guidance: []string{"No supply-chain guard signals were detected from local dependency metadata."},
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() == findings[j].Severity.Rank() {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].Severity.Rank() > findings[j].Severity.Rank()
	})

	risk := &models.SupplyChainRisk{
		Findings:     findings,
		FindingCount: len(findings),
	}
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			risk.CriticalCount++
		case models.SeverityHigh:
			risk.HighCount++
		case models.SeverityMedium:
			risk.MediumCount++
		case models.SeverityLow:
			risk.LowCount++
		}
		switch f.ID {
		case "SCM-101":
			risk.NewDependencies++
		case "SCM-301":
			risk.InstallScripts++
		}
		if f.ID == "SCM-104" {
			risk.PhantomDependencies++
		}
	}
	risk.Score = score(findings)
	risk.Level = levelForScore(risk.Score)
	risk.Decision = decisionFor(risk)
	risk.Guidance = guidanceFor(risk)
	risk.Metadata = map[string]interface{}{
		"mode":       "local-deterministic",
		"m1":         "dependency trust diff",
		"m2":         "package metadata suspicion signals",
		"m3":         "install-time behavior scanner",
		"network_io": false,
		"offline":    opts.Offline,
	}
	return risk
}

// DiffReports compares two already-generated JSON reports.
func DiffReports(ctx context.Context, baseline, target *models.ScanResult) *models.SupplyChainRisk {
	return Analyze(ctx, target, Options{ProjectPath: target.ProjectPath, Baseline: baseline, Offline: true})
}

// LoadReport reads a Calvigil JSON report from disk.
func LoadReport(path string) (*models.ScanResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open report %q: %w", path, err)
	}
	defer file.Close()
	return DecodeReport(file)
}

// DecodeReport decodes a Calvigil JSON report.
func DecodeReport(r io.Reader) (*models.ScanResult, error) {
	var report models.ScanResult
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}
	return &report, nil
}

func diffFindings(baseline, target *models.ScanResult) []models.SupplyChainFinding {
	basePkgs := packageIndex(baseline.Packages)
	targetPkgs := packageIndex(target.Packages)
	var findings []models.SupplyChainFinding

	for key, targetPkg := range targetPkgs {
		basePkg, ok := basePkgs[key]
		if !ok {
			if !targetPkg.Indirect {
				findings = append(findings, models.SupplyChainFinding{
					ID:             "SCM-101",
					Category:       "dependency-diff",
					Title:          "New direct dependency introduced",
					Description:    fmt.Sprintf("%s exists in the target report but was not present in the baseline report.", packageRef(targetPkg)),
					Severity:       models.SeverityMedium,
					Confidence:     "HIGH",
					Package:        targetPkg,
					FilePath:       targetPkg.FilePath,
					TargetVersion:  targetPkg.Version,
					Evidence:       fmt.Sprintf("%s@%s is new in %s", targetPkg.Name, targetPkg.Version, filepath.Base(targetPkg.FilePath)),
					Recommendation: fmt.Sprintf("Review %s source, maintainer, license, and install behavior before merging or releasing.", packageRef(targetPkg)),
				})
			}
			continue
		}

		if versionCompare(targetPkg.Version, basePkg.Version) < 0 {
			findings = append(findings, models.SupplyChainFinding{
				ID:              "SCM-102",
				Category:        "dependency-diff",
				Title:           "Dependency version downgraded",
				Description:     fmt.Sprintf("%s uses an older version than the baseline report.", packageRef(targetPkg)),
				Severity:        models.SeverityHigh,
				Confidence:      "MEDIUM",
				Package:         targetPkg,
				FilePath:        targetPkg.FilePath,
				BaselineVersion: basePkg.Version,
				TargetVersion:   targetPkg.Version,
				Evidence:        fmt.Sprintf("%s changed from %s to %s", targetPkg.Name, basePkg.Version, targetPkg.Version),
				Recommendation:  fmt.Sprintf("Confirm the %s downgrade is intentional and does not reintroduce patched vulnerabilities.", packageRef(targetPkg)),
			})
		}
	}

	findings = append(findings, typosquatFindings(basePkgs, targetPkgs)...)
	return findings
}

func consistencyFindings(issues []models.ConsistencyIssue) []models.SupplyChainFinding {
	findings := make([]models.SupplyChainFinding, 0, len(issues))
	for _, issue := range issues {
		findings = append(findings, models.SupplyChainFinding{
			ID:             "SCM-104",
			Category:       "lockfile-consistency",
			Title:          "Lockfile package is not declared in manifest",
			Description:    fmt.Sprintf("%s appears in a lockfile without a matching manifest declaration.", packageRef(issue.Package)),
			Severity:       models.SeverityHigh,
			Confidence:     "HIGH",
			Package:        issue.Package,
			FilePath:       issue.LockFile,
			Evidence:       issue.Reason,
			Recommendation: fmt.Sprintf("Regenerate the lockfile from a trusted manifest or remove the undeclared %s entry.", packageRef(issue.Package)),
		})
	}
	return findings
}

func packageIndex(pkgs []models.Package) map[string]models.Package {
	index := make(map[string]models.Package, len(pkgs))
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			continue
		}
		key := packageKey(pkg)
		if existing, ok := index[key]; ok && !existing.Indirect {
			continue
		}
		index[key] = pkg
	}
	return index
}

func packageKey(pkg models.Package) string {
	return strings.ToLower(string(pkg.Ecosystem)) + "/" + strings.ToLower(pkg.Name)
}

func packageRef(pkg models.Package) string {
	name := strings.TrimSpace(pkg.Name)
	if name == "" {
		return "this package"
	}
	if pkg.Version != "" {
		name += "@" + pkg.Version
	}
	if pkg.Ecosystem != "" {
		return fmt.Sprintf("%s package %s", pkg.Ecosystem, name)
	}
	return name
}

func typosquatFindings(basePkgs, targetPkgs map[string]models.Package) []models.SupplyChainFinding {
	var baselineNames []models.Package
	for _, pkg := range basePkgs {
		if pkg.Indirect || len(normalizeName(pkg.Name)) < 5 {
			continue
		}
		baselineNames = append(baselineNames, pkg)
	}
	if len(baselineNames) == 0 {
		return nil
	}

	var findings []models.SupplyChainFinding
	for key, targetPkg := range targetPkgs {
		if _, existed := basePkgs[key]; existed || targetPkg.Indirect {
			continue
		}
		targetName := normalizeName(targetPkg.Name)
		if len(targetName) < 5 {
			continue
		}
		for _, basePkg := range baselineNames {
			if basePkg.Ecosystem != targetPkg.Ecosystem {
				continue
			}
			baseName := normalizeName(basePkg.Name)
			if baseName == targetName {
				continue
			}
			dist := levenshtein(baseName, targetName)
			if dist > 0 && dist <= 2 {
				findings = append(findings, models.SupplyChainFinding{
					ID:             "SCM-105",
					Category:       "dependency-diff",
					Title:          "New dependency name resembles an existing package",
					Description:    fmt.Sprintf("%s is very similar to existing dependency %s, which may indicate typosquatting or dependency confusion.", packageRef(targetPkg), packageRef(basePkg)),
					Severity:       models.SeverityMedium,
					Confidence:     "MEDIUM",
					Package:        targetPkg,
					FilePath:       targetPkg.FilePath,
					Evidence:       fmt.Sprintf("%s resembles existing dependency %s", targetPkg.Name, basePkg.Name),
					Recommendation: fmt.Sprintf("Verify %s identity, publisher, repository, and reason for introducing it.", packageRef(targetPkg)),
				})
				break
			}
		}
	}
	return findings
}

func normalizeName(name string) string {
	name = strings.ToLower(name)
	replacer := strings.NewReplacer("@", "", "/", "", "-", "", "_", "", ".", "")
	return replacer.Replace(name)
}

func versionCompare(a, b string) int {
	aa := versionParts(a)
	bb := versionParts(b)
	max := len(aa)
	if len(bb) > max {
		max = len(bb)
	}
	for i := 0; i < max; i++ {
		av, bv := 0, 0
		if i < len(aa) {
			av = aa[i]
		}
		if i < len(bb) {
			bv = bb[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func versionParts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	fields := regexp.MustCompile(`[^0-9]+`).Split(v, -1)
	parts := make([]int, 0, len(fields))
	for _, f := range fields {
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			continue
		}
		parts = append(parts, n)
	}
	return parts
}

type npmProjectMetadata struct {
	ManifestSpecs map[string]string
	LockPackages  map[string]npmLockPackage
	RootScripts   map[string]string
	RootPackage   models.Package
	PackageJSON   string
	PackageLock   string
}

type npmLockPackage struct {
	Name             string
	Version          string
	Resolved         string
	HasInstallScript bool
	Scripts          map[string]string
	RawPath          string
}

func localPackageFindings(ctx context.Context, projectPath string, pkgs []models.Package) []models.SupplyChainFinding {
	if projectPath == "" {
		return nil
	}
	var findings []models.SupplyChainFinding
	npmMeta := collectNPMMetadata(projectPath)

	for _, pkg := range pkgs {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		if pkg.Name == "" {
			continue
		}
		if !pkg.Indirect && isUnknownLicense(pkg.License) {
			findings = append(findings, models.SupplyChainFinding{
				ID:             "SCM-201",
				Category:       "package-metadata",
				Title:          "Direct dependency has unknown license",
				Description:    fmt.Sprintf("%s does not expose a normalized license in local package metadata.", packageRef(pkg)),
				Severity:       models.SeverityMedium,
				Confidence:     "MEDIUM",
				Package:        pkg,
				FilePath:       pkg.FilePath,
				Evidence:       fmt.Sprintf("%s license is empty or unknown in %s", packageRef(pkg), filepath.Base(pkg.FilePath)),
				Recommendation: fmt.Sprintf("Resolve the license for %s from a trusted registry or review the package before distribution.", packageRef(pkg)),
			})
		}

		if pkg.Ecosystem == models.EcosystemNpm {
			meta, ok := npmMeta.LockPackages[pkg.Name]
			if ok && isNonRegistrySource(meta.Resolved) {
				findings = append(findings, models.SupplyChainFinding{
					ID:             "SCM-202",
					Category:       "package-metadata",
					Title:          "Dependency resolved from non-registry source",
					Description:    fmt.Sprintf("%s is resolved from a Git, HTTP, file, or non-standard tarball source.", packageRef(pkg)),
					Severity:       models.SeverityHigh,
					Confidence:     "HIGH",
					Package:        pkg,
					FilePath:       pkg.FilePath,
					TargetSource:   meta.Resolved,
					Evidence:       fmt.Sprintf("%s resolved source: %s", packageRef(pkg), meta.Resolved),
					Recommendation: fmt.Sprintf("Move %s to a trusted package registry or pin and verify the source digest explicitly.", packageRef(pkg)),
				})
			}
			if !pkg.Indirect {
				if spec := npmMeta.ManifestSpecs[pkg.Name]; isRiskyVersionSpec(spec) {
					findings = append(findings, models.SupplyChainFinding{
						ID:             "SCM-203",
						Category:       "package-metadata",
						Title:          "Direct dependency is not tightly pinned",
						Description:    fmt.Sprintf("%s uses a manifest range that lets the resolver select newer versions without manifest review.", packageRef(pkg)),
						Severity:       models.SeverityMedium,
						Confidence:     "MEDIUM",
						Package:        pkg,
						FilePath:       npmMeta.PackageJSON,
						Evidence:       fmt.Sprintf("%s manifest spec: %s", packageRef(pkg), spec),
						Recommendation: fmt.Sprintf("Pin %s for release branches or require lockfile review in CI.", packageRef(pkg)),
					})
				}
			}
			if ok && meta.HasInstallScript {
				findings = append(findings, models.SupplyChainFinding{
					ID:             "SCM-301",
					Category:       "install-behavior",
					Title:          "Dependency declares install-time script",
					Description:    fmt.Sprintf("%s declares an install-time script, which executes during package installation.", packageRef(pkg)),
					Severity:       models.SeverityHigh,
					Confidence:     "HIGH",
					Package:        pkg,
					FilePath:       pkg.FilePath,
					Evidence:       fmt.Sprintf("%s has hasInstallScript=true", packageRef(pkg)),
					Recommendation: fmt.Sprintf("Review %s install script, pin the package, and consider disabling lifecycle scripts in CI.", packageRef(pkg)),
				})
			}
		}
	}

	findings = append(findings, npmScriptFindings(npmMeta)...)
	findings = append(findings, pythonInstallFindings(projectPath)...)
	return findings
}

func collectNPMMetadata(projectPath string) npmProjectMetadata {
	meta := npmProjectMetadata{
		ManifestSpecs: make(map[string]string),
		LockPackages:  make(map[string]npmLockPackage),
		RootScripts:   make(map[string]string),
	}
	_ = filepath.WalkDir(projectPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != projectPath && fsutil.ShouldSkipSubDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Base(path) {
		case "package.json":
			readPackageJSON(path, &meta)
		case "package-lock.json":
			readPackageLock(path, &meta)
		}
		return nil
	})
	return meta
}

type packageJSONMetadata struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Scripts              map[string]string `json:"scripts"`
}

func readPackageJSON(path string, meta *npmProjectMetadata) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var pkg packageJSONMetadata
	if err := json.Unmarshal(data, &pkg); err != nil {
		return
	}
	meta.PackageJSON = path
	rootName := strings.TrimSpace(pkg.Name)
	if rootName == "" {
		rootName = filepath.Base(filepath.Dir(path))
	}
	meta.RootPackage = models.Package{
		Name:      rootName,
		Version:   strings.TrimSpace(pkg.Version),
		Ecosystem: models.EcosystemNpm,
		FilePath:  path,
	}
	mergeSpecs(meta.ManifestSpecs, pkg.Dependencies)
	mergeSpecs(meta.ManifestSpecs, pkg.DevDependencies)
	mergeSpecs(meta.ManifestSpecs, pkg.PeerDependencies)
	mergeSpecs(meta.ManifestSpecs, pkg.OptionalDependencies)
	for name, script := range pkg.Scripts {
		meta.RootScripts[name] = script
	}
}

func mergeSpecs(dst map[string]string, src map[string]string) {
	for k, v := range src {
		dst[k] = strings.TrimSpace(v)
	}
}

type packageLockMetadata struct {
	Packages map[string]struct {
		Name             string            `json:"name"`
		Version          string            `json:"version"`
		Resolved         string            `json:"resolved"`
		HasInstallScript bool              `json:"hasInstallScript"`
		Scripts          map[string]string `json:"scripts"`
	} `json:"packages"`
}

func readPackageLock(path string, meta *npmProjectMetadata) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var lock packageLockMetadata
	if err := json.Unmarshal(data, &lock); err != nil {
		return
	}
	meta.PackageLock = path
	for rawPath, p := range lock.Packages {
		if rawPath == "" {
			continue
		}
		name := p.Name
		if name == "" {
			name = npmNameFromLockPath(rawPath)
		}
		if name == "" {
			continue
		}
		meta.LockPackages[name] = npmLockPackage{
			Name:             name,
			Version:          p.Version,
			Resolved:         p.Resolved,
			HasInstallScript: p.HasInstallScript,
			Scripts:          p.Scripts,
			RawPath:          rawPath,
		}
	}
}

func npmNameFromLockPath(path string) string {
	idx := strings.LastIndex(path, "node_modules/")
	if idx < 0 {
		return ""
	}
	name := path[idx+len("node_modules/"):]
	parts := strings.Split(name, "/")
	if len(parts) == 0 {
		return ""
	}
	if strings.HasPrefix(parts[0], "@") && len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func isUnknownLicense(license string) bool {
	license = strings.TrimSpace(strings.ToLower(license))
	return license == "" || license == "unknown" || license == "unknown license" || license == "unlicensed"
}

func isRiskyVersionSpec(spec string) bool {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" {
		return false
	}
	if isNonRegistrySource(spec) {
		return true
	}
	return strings.ContainsAny(spec, "^~*x") || strings.HasPrefix(spec, ">") || strings.Contains(spec, "||") || strings.Contains(spec, " - ")
}

func isNonRegistrySource(source string) bool {
	source = strings.TrimSpace(strings.ToLower(source))
	if source == "" {
		return false
	}
	if strings.HasPrefix(source, "git+") || strings.HasPrefix(source, "git://") || strings.HasPrefix(source, "github:") ||
		strings.HasPrefix(source, "file:") || strings.HasPrefix(source, "link:") || strings.HasPrefix(source, "workspace:") {
		return true
	}
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return !strings.Contains(source, "registry.npmjs.org/") && !strings.Contains(source, "registry.yarnpkg.com/")
	}
	return false
}

func npmScriptFindings(meta npmProjectMetadata) []models.SupplyChainFinding {
	var findings []models.SupplyChainFinding
	for scriptName, script := range meta.RootScripts {
		if isDangerousInstallCommand(script) {
			findings = append(findings, models.SupplyChainFinding{
				ID:             "SCM-302",
				Category:       "install-behavior",
				Title:          "Project lifecycle script downloads or executes remote content",
				Description:    fmt.Sprintf("%s lifecycle script downloads or executes remote content and can expose CI credentials during dependency installation.", packageRef(meta.RootPackage)),
				Severity:       models.SeverityHigh,
				Confidence:     "MEDIUM",
				Package:        meta.RootPackage,
				FilePath:       meta.PackageJSON,
				Evidence:       fmt.Sprintf("%s: %s", scriptName, script),
				Recommendation: fmt.Sprintf("Remove the remote execution pattern from %s script %q; vendor or verify artifacts instead.", packageRef(meta.RootPackage), scriptName),
			})
		}
		if hasObfuscatedExecution(script) {
			findings = append(findings, models.SupplyChainFinding{
				ID:             "SCM-304",
				Category:       "install-behavior",
				Title:          "Lifecycle script contains obfuscated execution pattern",
				Description:    fmt.Sprintf("%s lifecycle script contains an encoded or opaque execution pattern.", packageRef(meta.RootPackage)),
				Severity:       models.SeverityMedium,
				Confidence:     "MEDIUM",
				Package:        meta.RootPackage,
				FilePath:       meta.PackageJSON,
				Evidence:       fmt.Sprintf("%s: %s", scriptName, script),
				Recommendation: fmt.Sprintf("Replace %s script %q opaque execution with reviewed, source-controlled build steps.", packageRef(meta.RootPackage), scriptName),
			})
		}
	}
	return findings
}

func pythonInstallFindings(projectPath string) []models.SupplyChainFinding {
	var findings []models.SupplyChainFinding
	_ = filepath.WalkDir(projectPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != projectPath && fsutil.ShouldSkipSubDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Base(path) != "setup.py" {
			return nil
		}
		findings = append(findings, scanSetupPy(path)...)
		return nil
	})
	return findings
}

func scanSetupPy(path string) []models.SupplyChainFinding {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	projectPkg := models.Package{
		Name:      filepath.Base(filepath.Dir(path)),
		Ecosystem: models.EcosystemPyPI,
		FilePath:  path,
	}
	var findings []models.SupplyChainFinding
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isPythonInstallExecution(line) {
			findings = append(findings, models.SupplyChainFinding{
				ID:             "SCM-303",
				Category:       "install-behavior",
				Title:          "Python setup script executes process or network command",
				Description:    fmt.Sprintf("%s setup.py executes a process or network command during package installation.", packageRef(projectPkg)),
				Severity:       models.SeverityHigh,
				Confidence:     "MEDIUM",
				Package:        projectPkg,
				FilePath:       path,
				StartLine:      lineNo,
				Evidence:       line,
				Recommendation: fmt.Sprintf("Move install-time execution out of %s setup.py and review whether installation can access credentials.", packageRef(projectPkg)),
			})
		}
	}
	return findings
}

func isDangerousInstallCommand(s string) bool {
	lower := strings.ToLower(s)
	return (strings.Contains(lower, "curl ") || strings.Contains(lower, "wget ")) &&
		(strings.Contains(lower, "| sh") || strings.Contains(lower, "| bash") || strings.Contains(lower, "sh -c") || strings.Contains(lower, "bash -c"))
}

func hasObfuscatedExecution(s string) bool {
	lower := strings.ToLower(s)
	return (strings.Contains(lower, "base64") && (strings.Contains(lower, "eval") || strings.Contains(lower, "| sh") || strings.Contains(lower, "node -e"))) ||
		strings.Contains(lower, "new function(") ||
		strings.Contains(lower, "eval(")
}

func isPythonInstallExecution(line string) bool {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "subprocess.") || strings.Contains(lower, "os.system(") || strings.Contains(lower, "popen(") {
		return true
	}
	return strings.Contains(lower, "urllib.request") || strings.Contains(lower, "requests.get(") || strings.Contains(lower, "http.client")
}

func score(findings []models.SupplyChainFinding) int {
	total := 0
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			total += 40
		case models.SeverityHigh:
			total += 25
		case models.SeverityMedium:
			total += 12
		case models.SeverityLow:
			total += 5
		default:
			total += 3
		}
	}
	if total > 100 {
		return 100
	}
	return total
}

func levelForScore(score int) string {
	switch {
	case score >= 90:
		return "CRITICAL"
	case score >= 70:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "CLEAN"
	}
}

func decisionFor(risk *models.SupplyChainRisk) string {
	if risk.CriticalCount > 0 || risk.Score >= 90 {
		return DecisionBlockRelease
	}
	if risk.HighCount > 0 || risk.Score >= 70 {
		return DecisionReviewBeforeMerge
	}
	if risk.MediumCount > 0 {
		return DecisionVerifyProvenance
	}
	return DecisionAllow
}

func guidanceFor(risk *models.SupplyChainRisk) []string {
	switch risk.Decision {
	case DecisionBlockRelease:
		return []string{
			"Block release until the highlighted dependency or install-time behavior is reviewed and remediated.",
			"Rotate CI or registry credentials if an install script may have executed in a privileged environment.",
		}
	case DecisionReviewBeforeMerge:
		return []string{
			"Require package identity, maintainer, source, and lockfile review before merging.",
			"Prefer pinned dependencies and trusted registry sources for release branches.",
		}
	case DecisionVerifyProvenance:
		return []string{
			"Verify package provenance, license, and resolver behavior before release.",
		}
	default:
		return []string{"No immediate supply-chain review gate is required based on local signals."}
	}
}

func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}
