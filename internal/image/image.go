package image

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/chavakula/calvigil/internal/matcher"
	"github.com/chavakula/calvigil/internal/models"
)

// Scanner scans container images for vulnerabilities by generating an SBOM
// with syft and then matching packages against vulnerability databases.
type Scanner struct {
	imageRef string
	verbose  bool
	matchers []matcher.Matcher
}

// NewScanner creates a new container image scanner.
func NewScanner(imageRef string, verbose bool, matchers []matcher.Matcher) *Scanner {
	return &Scanner{
		imageRef: imageRef,
		verbose:  verbose,
		matchers: matchers,
	}
}

// SyftAvailable checks whether syft is installed and accessible.
func SyftAvailable() bool {
	_, err := exec.LookPath("syft")
	return err == nil
}

// Scan runs the full image scan pipeline: pull SBOM, parse packages, match vulns.
func (s *Scanner) Scan(ctx context.Context) (*models.ScanResult, error) {
	start := time.Now()

	if s.verbose {
		fmt.Fprintf(os.Stderr, "Scanning container image: %s\n", s.imageRef)
	}

	// Step 1: Generate SBOM with syft
	pkgs, err := s.extractPackages(ctx)
	if err != nil {
		return nil, fmt.Errorf("SBOM extraction failed: %w", err)
	}

	if s.verbose {
		fmt.Fprintf(os.Stderr, "   Extracted %d packages from image SBOM\n", len(pkgs))
	}

	// Generate PURLs
	for i := range pkgs {
		pkgs[i].EnsurePURL()
	}

	// Step 2: Match against vulnerability databases
	if s.verbose {
		fmt.Fprintf(os.Stderr, "Querying vulnerability databases...\n")
	}

	aggregated := matcher.NewAggregatedMatcher(s.matchers...)
	vulns, err := aggregated.Match(ctx, pkgs)
	if err != nil {
		return nil, fmt.Errorf("vulnerability matching failed: %w", err)
	}

	if s.verbose {
		fmt.Fprintf(os.Stderr, "   Found %d vulnerabilities in %d packages\n\n", len(vulns), len(pkgs))
	}

	// Collect unique ecosystems
	ecoSet := make(map[models.Ecosystem]bool)
	for _, p := range pkgs {
		ecoSet[p.Ecosystem] = true
	}
	var ecosystems []models.Ecosystem
	for e := range ecoSet {
		ecosystems = append(ecosystems, e)
	}

	return &models.ScanResult{
		ProjectPath:     "image:" + s.imageRef,
		Ecosystems:      ecosystems,
		TotalPackages:   len(pkgs),
		Vulnerabilities: vulns,
		ScannedAt:       start,
		Duration:        time.Since(start),
	}, nil
}

// syftJSON represents the relevant portion of syft JSON output.
type syftJSON struct {
	Artifacts []syftArtifact `json:"artifacts"`
}

type syftArtifact struct {
	Name      string       `json:"name"`
	Version   string       `json:"version"`
	Type      string       `json:"type"`
	Language  string       `json:"language"`
	PURL      string       `json:"purl"`
	Locations []syftLoc    `json:"locations"`
	Metadata  syftMetadata `json:"metadata,omitempty"`
}

type syftLoc struct {
	Path string `json:"path"`
}

type syftMetadata struct {
	ManifestName string `json:"manifest-name,omitempty"`
}

// extractPackages runs syft against the image and parses the JSON output.
func (s *Scanner) extractPackages(ctx context.Context) ([]models.Package, error) {
	if !SyftAvailable() {
		return nil, fmt.Errorf("syft is not installed; install from https://github.com/anchore/syft")
	}

	args := []string{s.imageRef, "-o", "json", "--quiet"}
	cmd := exec.CommandContext(ctx, "syft", args...)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("syft failed: %w", err)
	}

	var sbom syftJSON
	if err := json.Unmarshal(out, &sbom); err != nil {
		return nil, fmt.Errorf("cannot parse syft output: %w", err)
	}

	var pkgs []models.Package
	for _, a := range sbom.Artifacts {
		if a.Name == "" || a.Version == "" {
			continue
		}

		eco := mapSyftType(a.Type, a.Language)
		if eco == "" {
			continue
		}

		filePath := ""
		if len(a.Locations) > 0 {
			filePath = a.Locations[0].Path
		}

		pkg := models.Package{
			Name:      a.Name,
			Version:   a.Version,
			Ecosystem: eco,
			FilePath:  filePath,
		}
		if a.PURL != "" {
			pkg.PURL = a.PURL
		}

		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

// mapSyftType converts syft artifact type/language to our Ecosystem.
func mapSyftType(typ, language string) models.Ecosystem {
	typ = strings.ToLower(typ)
	language = strings.ToLower(language)

	switch {
	case typ == "npm" || language == "javascript" || language == "typescript":
		return models.EcosystemNpm
	case typ == "python" || language == "python" || typ == "pip" || typ == "wheel" || typ == "egg":
		return models.EcosystemPyPI
	case typ == "go-module" || language == "go":
		return models.EcosystemGo
	case typ == "java-archive" || typ == "maven" || typ == "gradle" || language == "java":
		return models.EcosystemMaven
	case typ == "gem" || language == "ruby":
		return models.Ecosystem("RubyGems")
	case typ == "rust-crate" || language == "rust":
		return models.Ecosystem("crates.io")
	case typ == "deb" || typ == "rpm" || typ == "apk":
		return models.Ecosystem(strings.ToUpper(typ))
	default:
		return ""
	}
}
