package matcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chavakula/calvigil/internal/models"
)

const ghAdvisoryURL = "https://api.github.com/advisories"

// GitHubAdvisoryMatcher queries the GitHub Advisory Database.
type GitHubAdvisoryMatcher struct {
	client *http.Client
	token  string
}

// NewGitHubAdvisoryMatcher creates a new GitHub Advisory matcher.
// token is optional but provides higher rate limits.
func NewGitHubAdvisoryMatcher(token string) *GitHubAdvisoryMatcher {
	return &GitHubAdvisoryMatcher{
		client: &http.Client{Timeout: 30 * time.Second},
		token:  token,
	}
}

func (m *GitHubAdvisoryMatcher) Name() string { return "github-advisory" }

type ghAdvisory struct {
	GHSAID          string            `json:"ghsa_id"`
	CVEID           string            `json:"cve_id"`
	Summary         string            `json:"summary"`
	Description     string            `json:"description"`
	Severity        string            `json:"severity"`
	CVSSScore       float64           `json:"cvss_score,omitempty"`
	HTMLURL         string            `json:"html_url"`
	Vulnerabilities []ghVulnerability `json:"vulnerabilities"`
	PublishedAt     time.Time         `json:"published_at"`
}

type ghVulnerability struct {
	Package                ghPackage  `json:"package"`
	VulnerableVersionRange string     `json:"vulnerable_version_range"`
	FirstPatchedVersion    *ghVersion `json:"first_patched_version"`
}

type ghPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type ghVersion struct {
	Identifier string `json:"identifier"`
}

// ghEcosystemMap converts our ecosystems to GitHub's ecosystem names.
var ghEcosystemMap = map[models.Ecosystem]string{
	models.EcosystemGo:    "go",
	models.EcosystemPyPI:  "pip",
	models.EcosystemNpm:   "npm",
	models.EcosystemMaven: "maven",
}

func (m *GitHubAdvisoryMatcher) Match(ctx context.Context, packages []models.Package) ([]models.Vulnerability, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	// Group packages by ecosystem for efficient querying
	ecoPackages := make(map[models.Ecosystem][]models.Package)
	for _, pkg := range packages {
		ecoPackages[pkg.Ecosystem] = append(ecoPackages[pkg.Ecosystem], pkg)
	}

	var allVulns []models.Vulnerability
	for eco, pkgs := range ecoPackages {
		ghEco, ok := ghEcosystemMap[eco]
		if !ok {
			continue
		}

		vulns, err := m.queryEcosystem(ctx, ghEco, pkgs)
		if err != nil {
			continue // Skip on error, don't fail the whole scan
		}
		allVulns = append(allVulns, vulns...)
	}

	return allVulns, nil
}

func (m *GitHubAdvisoryMatcher) queryEcosystem(ctx context.Context, ecosystem string, packages []models.Package) ([]models.Vulnerability, error) {
	params := url.Values{}
	params.Set("ecosystem", ecosystem)
	params.Set("per_page", "100")

	reqURL := ghAdvisoryURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if m.token != "" {
		req.Header.Set("Authorization", "Bearer "+m.token)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github advisory api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github advisory api returned status %d", resp.StatusCode)
	}

	var advisories []ghAdvisory
	if err := json.NewDecoder(resp.Body).Decode(&advisories); err != nil {
		return nil, fmt.Errorf("decode github advisory response: %w", err)
	}

	// Build a lookup map for our packages
	pkgMap := make(map[string]models.Package)
	for _, pkg := range packages {
		pkgMap[strings.ToLower(pkg.Name)] = pkg
	}

	var vulns []models.Vulnerability
	for _, adv := range advisories {
		for _, v := range adv.Vulnerabilities {
			pkg, exists := pkgMap[strings.ToLower(v.Package.Name)]
			if !exists {
				continue
			}

			id := adv.CVEID
			if id == "" {
				id = adv.GHSAID
			}

			var aliases []string
			if adv.CVEID != "" && adv.GHSAID != "" {
				aliases = []string{adv.GHSAID}
			}

			fixedIn := ""
			if v.FirstPatchedVersion != nil {
				fixedIn = v.FirstPatchedVersion.Identifier
			}

			vulns = append(vulns, models.Vulnerability{
				ID:          id,
				Aliases:     aliases,
				Summary:     adv.Summary,
				Details:     adv.Description,
				Severity:    ghSeverityToSeverity(adv.Severity),
				Score:       adv.CVSSScore,
				Package:     pkg,
				FixedIn:     fixedIn,
				References:  []string{adv.HTMLURL},
				Source:      models.SourceGitHubAdv,
				PublishedAt: adv.PublishedAt,
			})
		}
	}

	return vulns, nil
}

func ghSeverityToSeverity(s string) models.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	default:
		return models.SeverityUnknown
	}
}
