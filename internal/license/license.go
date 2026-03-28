package license

import (
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// permissiveLicenses and copyleftLicenses are defined in spdx_licenses.go

// Classify returns the license risk for a given SPDX license identifier.
func Classify(spdxID string) models.LicenseRisk {
	normalized := normalizeID(spdxID)
	if normalized == "" {
		return models.LicenseUnknown
	}
	if permissiveLicenses[normalized] {
		return models.LicensePermissive
	}
	if copyleftLicenses[normalized] {
		return models.LicenseCopyleft
	}
	return models.LicenseUnknown
}

// CheckPackages evaluates all packages and returns license compliance issues.
// It flags copyleft and unknown licenses.
func CheckPackages(packages []models.Package) []models.LicenseIssue {
	var issues []models.LicenseIssue
	for _, pkg := range packages {
		if pkg.License == "" {
			issues = append(issues, models.LicenseIssue{
				Package: pkg,
				License: "",
				Risk:    models.LicenseUnknown,
				Reason:  "No license information available",
			})
			continue
		}
		risk := Classify(pkg.License)
		switch risk {
		case models.LicenseCopyleft:
			issues = append(issues, models.LicenseIssue{
				Package: pkg,
				License: pkg.License,
				Risk:    models.LicenseCopyleft,
				Reason:  "Copyleft license may require source code disclosure",
			})
		case models.LicenseUnknown:
			issues = append(issues, models.LicenseIssue{
				Package: pkg,
				License: pkg.License,
				Risk:    models.LicenseUnknown,
				Reason:  "License not in known SPDX database -- review manually",
			})
		}
	}
	return issues
}

// normalizeID normalizes a license string to a standard SPDX identifier.
func normalizeID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if permissiveLicenses[id] || copyleftLicenses[id] {
		return id
	}
	upper := strings.ToUpper(id)
	for k := range permissiveLicenses {
		if strings.ToUpper(k) == upper {
			return k
		}
	}
	for k := range copyleftLicenses {
		if strings.ToUpper(k) == upper {
			return k
		}
	}
	return id
}
