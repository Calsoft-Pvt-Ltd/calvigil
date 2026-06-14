package matcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestOSSIndexMatcher_Name(t *testing.T) {
	m := NewOSSIndexMatcher("", "")
	if m.Name() != "oss-index" {
		t.Errorf("Name() = %q, want oss-index", m.Name())
	}
}

func TestOSSIndexMatcher_EmptyPackages(t *testing.T) {
	m := NewOSSIndexMatcher("", "")
	vulns, err := m.Match(context.Background(), nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if vulns != nil {
		t.Errorf("expected nil vulns, got %v", vulns)
	}
}

func TestOSSIndexMatcher_Match(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		var req ossIndexRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.Coordinates) != 1 {
			t.Errorf("coordinates = %v, want 1 entry", req.Coordinates)
		}

		resp := []ossIndexComponent{
			{
				Coordinates: req.Coordinates[0],
				Vulnerabilities: []ossIndexVuln{
					{
						ID:          "abc-123",
						DisplayName: "SONATYPE-2024-001",
						Title:       "Prototype pollution",
						Description: "Long description",
						CVSSScore:   8.2,
						CVE:         "CVE-2024-9999",
						Reference:   "https://ossindex.sonatype.org/vuln/abc-123",
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	m := NewOSSIndexMatcher("", "")
	m.baseURL = ts.URL

	pkgs := []models.Package{
		{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm},
	}
	vulns, err := m.Match(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}

	v := vulns[0]
	if v.ID != "CVE-2024-9999" {
		t.Errorf("ID = %q, want CVE-2024-9999", v.ID)
	}
	if len(v.Aliases) != 1 || v.Aliases[0] != "SONATYPE-2024-001" {
		t.Errorf("aliases = %v, want [SONATYPE-2024-001]", v.Aliases)
	}
	if v.Severity != models.SeverityHigh {
		t.Errorf("severity = %q, want HIGH (derived from score 8.2)", v.Severity)
	}
	if v.Score != 8.2 {
		t.Errorf("score = %v, want 8.2", v.Score)
	}
	if v.Source != models.SourceOSSIndex {
		t.Errorf("source = %q, want oss-index", v.Source)
	}
	if v.Package.Name != "lodash" {
		t.Errorf("package = %q, want lodash", v.Package.Name)
	}
}

func TestOSSIndexMatcher_NoCVEFallsBackToDisplayName(t *testing.T) {
	v := ossVulnToModel(ossIndexVuln{
		ID:          "internal-id",
		DisplayName: "SONATYPE-2024-002",
		Title:       "Issue",
		CVSSScore:   5.0,
	}, models.Package{Name: "pkg"})
	if v.ID != "SONATYPE-2024-002" {
		t.Errorf("ID = %q, want SONATYPE-2024-002", v.ID)
	}
	if v.Severity != models.SeverityMedium {
		t.Errorf("severity = %q, want MEDIUM", v.Severity)
	}
}

func TestOSSIndexMatcher_VectorFallbackWhenNoScore(t *testing.T) {
	v := ossVulnToModel(ossIndexVuln{
		CVE:        "CVE-2024-1",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}, models.Package{Name: "pkg"})
	if v.Severity != models.SeverityCritical {
		t.Errorf("severity = %q, want CRITICAL (from vector)", v.Severity)
	}
}

func TestOSSIndexMatcher_RateLimitError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	m := NewOSSIndexMatcher("", "")
	m.baseURL = ts.URL

	_, err := m.Match(context.Background(), []models.Package{
		{Name: "lodash", Version: "1.0.0", Ecosystem: models.EcosystemNpm},
	})
	if err == nil {
		t.Fatal("expected rate limit error, got nil")
	}
}

func TestOSSIndexMatcher_SendsBasicAuth(t *testing.T) {
	gotAuth := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		gotAuth = ok && user == "user@example.com" && pass == "token123"
		json.NewEncoder(w).Encode([]ossIndexComponent{})
	}))
	defer ts.Close()

	m := NewOSSIndexMatcher("user@example.com", "token123")
	m.baseURL = ts.URL

	_, err := m.Match(context.Background(), []models.Package{
		{Name: "lodash", Version: "1.0.0", Ecosystem: models.EcosystemNpm},
	})
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if !gotAuth {
		t.Error("basic auth credentials were not sent")
	}
}

func TestOSSIndexMatcher_RetriesAnonymousAfterBadCredentials(t *testing.T) {
	requests := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			if _, _, ok := r.BasicAuth(); !ok {
				t.Fatal("first request should use configured credentials")
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if _, _, ok := r.BasicAuth(); ok {
			t.Fatal("retry should be anonymous")
		}

		var req ossIndexRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		json.NewEncoder(w).Encode([]ossIndexComponent{{
			Coordinates: req.Coordinates[0],
			Vulnerabilities: []ossIndexVuln{{
				CVE:       "CVE-2026-401",
				Title:     "Recovered via anonymous OSS Index request",
				CVSSScore: 7.2,
			}},
		}})
	}))
	defer ts.Close()

	m := NewOSSIndexMatcher("bad@example.com", "stale-token")
	m.baseURL = ts.URL

	vulns, err := m.Match(context.Background(), []models.Package{
		{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm},
	})
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want authenticated attempt plus anonymous retry", requests)
	}
	if len(vulns) != 1 || vulns[0].ID != "CVE-2026-401" {
		t.Fatalf("unexpected vulns: %+v", vulns)
	}
}

func TestOSSIndexMatcher_UnauthorizedWithoutFallbackIsActionable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	m := NewOSSIndexMatcher("", "")
	m.baseURL = ts.URL

	_, err := m.Match(context.Background(), []models.Package{
		{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm},
	})
	if err == nil {
		t.Fatal("expected unauthorized error")
	}
	if !strings.Contains(err.Error(), "clear them to skip OSS Index") {
		t.Fatalf("error = %q, want actionable credential guidance", err.Error())
	}
}

func TestOSSIndexMatcher_SkipsPackagesWithoutPURL(t *testing.T) {
	m := NewOSSIndexMatcher("", "")
	// Unknown ecosystem produces no PURL, so no API call should happen and
	// the matcher must return cleanly.
	vulns, err := m.Match(context.Background(), []models.Package{
		{Name: "thing", Version: "1.0", Ecosystem: models.Ecosystem("unknown-eco")},
	})
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected no vulns, got %d", len(vulns))
	}
}
