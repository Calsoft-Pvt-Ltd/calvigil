package license

import (
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// permissiveLicenses and copyleftLicenses are defined in spdx_licenses.go

// Classify returns the license risk for a given SPDX license identifier.
// It handles compound SPDX expressions like "(MIT OR Apache-2.0)" and
// "GPL-2.0-only WITH Classpath-exception-2.0".
//
// For OR expressions: returns the most permissive (best-case) classification.
// For AND expressions: returns the most restrictive (worst-case) classification.
// WITH (exception) clauses: the exception is ignored, only the base license matters.
func Classify(spdxID string) models.LicenseRisk {
	spdxID = strings.TrimSpace(spdxID)
	if spdxID == "" {
		return models.LicenseUnknown
	}

	// Strip outer parentheses: "(MIT OR Apache-2.0)" -> "MIT OR Apache-2.0"
	if strings.HasPrefix(spdxID, "(") && strings.HasSuffix(spdxID, ")") {
		spdxID = spdxID[1 : len(spdxID)-1]
	}

	// Handle OR expressions — pick the most permissive (developer chooses)
	if parts := splitSPDXOp(spdxID, " OR "); len(parts) > 1 {
		best := models.LicenseUnknown
		for _, part := range parts {
			r := Classify(part)
			if r == models.LicensePermissive {
				return models.LicensePermissive
			}
			if best == models.LicenseUnknown || r == models.LicenseCopyleft {
				best = r
			}
		}
		return best
	}

	// Handle AND expressions — pick the most restrictive
	if parts := splitSPDXOp(spdxID, " AND "); len(parts) > 1 {
		worst := models.LicensePermissive
		for _, part := range parts {
			r := Classify(part)
			if r == models.LicenseUnknown {
				return models.LicenseUnknown
			}
			if r == models.LicenseCopyleft {
				worst = models.LicenseCopyleft
			}
		}
		return worst
	}

	// Handle WITH (exception clause) — ignore the exception, classify the base
	if idx := strings.Index(strings.ToUpper(spdxID), " WITH "); idx > 0 {
		return Classify(spdxID[:idx])
	}

	// Simple single identifier
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

// splitSPDXOp splits an SPDX expression by a binary operator (case-insensitive),
// trimming whitespace and stripping parentheses from each part.
func splitSPDXOp(expr, op string) []string {
	// Case-insensitive split
	upper := strings.ToUpper(expr)
	upperOp := strings.ToUpper(op)
	if !strings.Contains(upper, upperOp) {
		return nil
	}
	var parts []string
	for {
		idx := strings.Index(strings.ToUpper(expr), upperOp)
		if idx < 0 {
			parts = append(parts, strings.TrimSpace(expr))
			break
		}
		parts = append(parts, strings.TrimSpace(expr[:idx]))
		expr = expr[idx+len(op):]
	}
	return parts
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

// precomputed lowercase lookup maps — built once at init for O(1) case-insensitive matching.
var (
	permissiveLower map[string]string // lowercase → canonical key
	copyleftLower   map[string]string
)

func init() {
	permissiveLower = make(map[string]string, len(permissiveLicenses))
	for k := range permissiveLicenses {
		permissiveLower[strings.ToLower(k)] = k
	}
	copyleftLower = make(map[string]string, len(copyleftLicenses))
	for k := range copyleftLicenses {
		copyleftLower[strings.ToLower(k)] = k
	}
}

// normalizeID normalizes a license string to a standard SPDX identifier.
func normalizeID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	// Fast exact match (most common case — standard SPDX identifiers)
	if permissiveLicenses[id] || copyleftLicenses[id] {
		return id
	}
	lower := strings.ToLower(id)
	// Check common non-SPDX aliases (e.g. "BSD" → "BSD-2-Clause")
	if mapped, ok := licenseAliases[lower]; ok {
		return mapped
	}
	// O(1) case-insensitive lookup via precomputed lowercase maps
	if canonical, ok := permissiveLower[lower]; ok {
		return canonical
	}
	if canonical, ok := copyleftLower[lower]; ok {
		return canonical
	}
	return id
}

// licenseAliases maps common non-SPDX license strings (lowercased) to their
// canonical SPDX identifiers. Package registries (npm, PyPI, etc.) often
// return informal names that don't match SPDX exactly.
var licenseAliases = map[string]string{
	// BSD variants
	"bsd":            "BSD-2-Clause",
	"bsd license":    "BSD-2-Clause",
	"bsd-2":          "BSD-2-Clause",
	"bsd 2-clause":   "BSD-2-Clause",
	"bsd 2 clause":   "BSD-2-Clause",
	"simplified bsd": "BSD-2-Clause",
	"freebsd":        "BSD-2-Clause",
	"bsd-3":          "BSD-3-Clause",
	"bsd 3-clause":   "BSD-3-Clause",
	"bsd 3 clause":   "BSD-3-Clause",
	"new bsd":        "BSD-3-Clause",
	"modified bsd":   "BSD-3-Clause",
	"revised bsd":    "BSD-3-Clause",
	// Apache variants
	"apache":                      "Apache-2.0",
	"apache 2":                    "Apache-2.0",
	"apache 2.0":                  "Apache-2.0",
	"apache2":                     "Apache-2.0",
	"apache-2":                    "Apache-2.0",
	"apache license 2.0":          "Apache-2.0",
	"apache license, version 2.0": "Apache-2.0",
	"apache software license":     "Apache-2.0",
	"asl 2.0":                     "Apache-2.0",
	// MIT variants
	"mit license":     "MIT",
	"the mit license": "MIT",
	"mit/x11":         "MIT",
	// ISC variants
	"isc license": "ISC",
	// GPL variants
	"gpl":        "GPL-2.0-only",
	"gpl2":       "GPL-2.0-only",
	"gpl 2":      "GPL-2.0-only",
	"gpl-2":      "GPL-2.0-only",
	"gpl v2":     "GPL-2.0-only",
	"gplv2":      "GPL-2.0-only",
	"gnu gpl v2": "GPL-2.0-only",
	"gpl3":       "GPL-3.0-only",
	"gpl 3":      "GPL-3.0-only",
	"gpl-3":      "GPL-3.0-only",
	"gpl v3":     "GPL-3.0-only",
	"gplv3":      "GPL-3.0-only",
	"gnu gpl v3": "GPL-3.0-only",
	// LGPL variants
	"lgpl":      "LGPL-2.1-only",
	"lgpl 2.1":  "LGPL-2.1-only",
	"lgpl-2.1":  "LGPL-2.1-only",
	"lgpl v2.1": "LGPL-2.1-only",
	"lgpl 3":    "LGPL-3.0-only",
	"lgpl-3":    "LGPL-3.0-only",
	"lgpl v3":   "LGPL-3.0-only",
	"lgpl-3.0":  "LGPL-3.0-only",
	// AGPL variants
	"agpl":     "AGPL-3.0-only",
	"agpl 3":   "AGPL-3.0-only",
	"agpl-3":   "AGPL-3.0-only",
	"agpl v3":  "AGPL-3.0-only",
	"agpl-3.0": "AGPL-3.0-only",
	// MPL variants
	"mpl":                        "MPL-2.0",
	"mpl 2":                      "MPL-2.0",
	"mpl 2.0":                    "MPL-2.0",
	"mpl-2":                      "MPL-2.0",
	"mozilla public license 2.0": "MPL-2.0",
	// CC variants
	"cc0":           "CC0-1.0",
	"cc0 1.0":       "CC0-1.0",
	"public domain": "CC0-1.0",
	"cc-by-3.0":     "CC-BY-3.0",
	"cc-by-4.0":     "CC-BY-4.0",
	// Artistic
	"artistic":     "Artistic-2.0",
	"artistic 2.0": "Artistic-2.0",
	// Zlib
	"zlib":        "Zlib",
	"zlib/libpng": "Zlib",
	// Python
	"python":                             "PSF-2.0",
	"python software foundation license": "PSF-2.0",
	"psf":                                "PSF-2.0",
	// WTFPL
	"wtfpl": "WTFPL",
	"do what the fuck you want to public license": "WTFPL",
	// Unlicense
	"unlicense":     "Unlicense",
	"the unlicense": "Unlicense",
}
