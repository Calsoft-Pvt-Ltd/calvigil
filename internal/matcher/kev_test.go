package matcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestKEVEnricher_FlagsKnownExploited(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2024-1111"},{"cveID":"CVE-2024-2222"}]}`))
	}))
	defer ts.Close()

	k := NewKEVEnricher()
	k.baseURL = ts.URL

	vulns := []models.Vulnerability{
		{ID: "CVE-2024-1111"}, // direct match
		{ID: "GHSA-xxxx", Aliases: []string{"CVE-2024-2222"}}, // alias match
		{ID: "CVE-2024-3333"}, // no match
		{ID: "cve-2024-1111"}, // case-insensitive
	}
	if err := k.Enrich(context.Background(), vulns); err != nil {
		t.Fatalf("Enrich() error: %v", err)
	}

	if !vulns[0].KnownExploited {
		t.Error("direct CVE match not flagged")
	}
	if !vulns[1].KnownExploited {
		t.Error("alias CVE match not flagged")
	}
	if vulns[2].KnownExploited {
		t.Error("unrelated CVE wrongly flagged")
	}
	if !vulns[3].KnownExploited {
		t.Error("case-insensitive match not flagged")
	}
}

func TestKEVEnricher_EmptyVulns(t *testing.T) {
	k := NewKEVEnricher()
	// Must not make any network call for empty input.
	k.baseURL = "http://127.0.0.1:1" // would fail if dialed
	if err := k.Enrich(context.Background(), nil); err != nil {
		t.Fatalf("Enrich() error: %v", err)
	}
}

func TestKEVEnricher_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	k := NewKEVEnricher()
	k.baseURL = ts.URL

	vulns := []models.Vulnerability{{ID: "CVE-2024-1111"}}
	if err := k.Enrich(context.Background(), vulns); err == nil {
		t.Fatal("expected error on server failure, got nil")
	}
	if vulns[0].KnownExploited {
		t.Error("vuln flagged despite enrichment failure")
	}
}

func TestKEVEnricher_MalformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not-json`))
	}))
	defer ts.Close()

	k := NewKEVEnricher()
	k.baseURL = ts.URL

	if err := k.Enrich(context.Background(), []models.Vulnerability{{ID: "CVE-1"}}); err == nil {
		t.Fatal("expected decode error, got nil")
	}
}
