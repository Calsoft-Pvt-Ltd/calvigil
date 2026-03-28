package license

import (
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestClassify_Permissive(t *testing.T) {
	cases := []string{
		"MIT", "MIT-0", "Apache-2.0", "Apache-1.1",
		"BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear", "0BSD", "BSD-2-Clause-Patent",
		"ISC", "curl", "Zlib", "Unlicense", "CC0-1.0", "PDDL-1.0", "WTFPL", "Fair",
		"CC-BY-3.0", "CC-BY-4.0", "BSL-1.0",
		"Python-2.0", "PSF-2.0", "CNRI-Python",
		"AFL-3.0", "Artistic-2.0", "ECL-2.0", "NCSA", "NTP",
		"BlueOak-1.0.0", "PostgreSQL", "UPL-1.0", "OpenSSL", "MS-PL", "JSON", "FTL",
		"PHP-3.01", "OFL-1.1", "W3C", "ICU", "Intel",
		"Unicode-DFS-2016", "IJG", "Libpng", "HPND",
		"SGI-B-2.0", "MulanPSL-2.0", "SAX-PD",
	}
	for _, lic := range cases {
		got := Classify(lic)
		if got != models.LicensePermissive {
			t.Errorf("Classify(%q) = %q, want %q", lic, got, models.LicensePermissive)
		}
	}
}

func TestClassify_Copyleft(t *testing.T) {
	cases := []string{
		"GPL-2.0", "GPL-2.0-only", "GPL-3.0", "GPL-3.0-or-later",
		"AGPL-3.0", "AGPL-3.0-only", "AGPL-1.0",
		"LGPL-2.1", "LGPL-3.0", "LGPL-3.0-or-later",
		"MPL-1.0", "MPL-1.1", "MPL-2.0",
		"EUPL-1.0", "EUPL-1.1", "EUPL-1.2",
		"CPAL-1.0", "OSL-3.0", "SSPL-1.0", "CECILL-2.1",
		"EPL-1.0", "EPL-2.0", "CPL-1.0",
		"APSL-2.0", "RPSL-1.0", "SPL-1.0", "Watcom-1.0",
	}
	for _, lic := range cases {
		got := Classify(lic)
		if got != models.LicenseCopyleft {
			t.Errorf("Classify(%q) = %q, want %q", lic, got, models.LicenseCopyleft)
		}
	}
}

func TestClassify_Unknown(t *testing.T) {
	cases := []string{"CustomLicense", "Proprietary", "Commercial-1.0"}
	for _, lic := range cases {
		got := Classify(lic)
		if got != models.LicenseUnknown {
			t.Errorf("Classify(%q) = %q, want %q", lic, got, models.LicenseUnknown)
		}
	}
}

func TestClassify_Empty(t *testing.T) {
	got := Classify("")
	if got != models.LicenseUnknown {
		t.Errorf("Classify(\"\") = %q, want %q", got, models.LicenseUnknown)
	}
}

func TestClassify_CaseInsensitive(t *testing.T) {
	cases := map[string]models.LicenseRisk{
		"mit":        models.LicensePermissive,
		"APACHE-2.0": models.LicensePermissive,
		"gpl-3.0":    models.LicenseCopyleft,
		"Mpl-2.0":    models.LicenseCopyleft,
		"isc":        models.LicensePermissive,
	}
	for lic, want := range cases {
		got := Classify(lic)
		if got != want {
			t.Errorf("Classify(%q) = %q, want %q", lic, got, want)
		}
	}
}

func TestClassify_WhitespaceHandling(t *testing.T) {
	cases := map[string]models.LicenseRisk{
		" MIT ":      models.LicensePermissive,
		"  GPL-3.0 ": models.LicenseCopyleft,
		"\tISC\t":    models.LicensePermissive,
	}
	for lic, want := range cases {
		got := Classify(lic)
		if got != want {
			t.Errorf("Classify(%q) = %q, want %q", lic, got, want)
		}
	}
}

func TestCheckPackages_MixedLicenses(t *testing.T) {
	pkgs := []models.Package{
		{Name: "safe-pkg", Version: "1.0", License: "MIT"},
		{Name: "copyleft-pkg", Version: "2.0", License: "GPL-3.0"},
		{Name: "unknown-pkg", Version: "3.0", License: "WeirdLicense"},
		{Name: "no-lic-pkg", Version: "4.0", License: ""},
	}
	issues := CheckPackages(pkgs)
	// MIT should not appear in issues. 3 issues: copyleft + unknown + no-license.
	if len(issues) != 3 {
		t.Fatalf("expected 3 issues, got %d", len(issues))
	}

	riskCounts := map[models.LicenseRisk]int{}
	for _, issue := range issues {
		riskCounts[issue.Risk]++
	}
	if riskCounts[models.LicenseCopyleft] != 1 {
		t.Errorf("expected 1 copyleft issue, got %d", riskCounts[models.LicenseCopyleft])
	}
	if riskCounts[models.LicenseUnknown] != 2 {
		t.Errorf("expected 2 unknown issues, got %d", riskCounts[models.LicenseUnknown])
	}
}

func TestCheckPackages_AllPermissive(t *testing.T) {
	pkgs := []models.Package{
		{Name: "a", Version: "1.0", License: "MIT"},
		{Name: "b", Version: "2.0", License: "Apache-2.0"},
		{Name: "c", Version: "3.0", License: "BSD-3-Clause"},
	}
	issues := CheckPackages(pkgs)
	if len(issues) != 0 {
		t.Errorf("expected 0 issues for all permissive, got %d", len(issues))
	}
}

func TestCheckPackages_EmptySlice(t *testing.T) {
	issues := CheckPackages(nil)
	if len(issues) != 0 {
		t.Errorf("expected 0 issues for nil input, got %d", len(issues))
	}
	issues = CheckPackages([]models.Package{})
	if len(issues) != 0 {
		t.Errorf("expected 0 issues for empty slice, got %d", len(issues))
	}
}

func TestCheckPackages_AllNoLicense(t *testing.T) {
	pkgs := []models.Package{
		{Name: "a", Version: "1.0"},
		{Name: "b", Version: "2.0"},
	}
	issues := CheckPackages(pkgs)
	if len(issues) != 2 {
		t.Errorf("expected 2 issues, got %d", len(issues))
	}
	for _, issue := range issues {
		if issue.Risk != models.LicenseUnknown {
			t.Errorf("expected unknown risk, got %q", issue.Risk)
		}
		if issue.Reason != "No license information available" {
			t.Errorf("unexpected reason: %s", issue.Reason)
		}
	}
}
