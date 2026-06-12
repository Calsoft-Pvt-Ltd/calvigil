package matcher

import (
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// This file implements the Canonical Data Model (CDM) for vulnerability
// records. Every source (OSV, NVD, GitHub Advisory, OSS Index, ...) produces
// records with slightly different conventions for IDs, aliases, severity and
// scores. The CDM normalizes each record into a single consistent shape and
// merges duplicate records found across sources so that the best available
// data wins — e.g. a record with severity UNKNOWN from one source is filled
// in from a duplicate that carries a real severity.

// Canonical ID preference order: CVE > GHSA > everything else.
func idRank(id string) int {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return 3
	case strings.HasPrefix(id, "GHSA-"):
		return 2
	default:
		return 1
	}
}

// Normalize converts a vulnerability record into canonical form:
//
//   - The primary ID is the most authoritative identifier available
//     (CVE preferred over GHSA, GHSA over ecosystem-specific IDs); all
//     other identifiers become aliases.
//   - Aliases are deduplicated and never contain the primary ID.
//   - Severity is resolved through a fallback chain: if the source did not
//     provide a usable severity but did provide a CVSS score, the severity
//     is derived from the score. This eliminates most UNKNOWN severities.
//   - Summary and details are whitespace-trimmed.
func Normalize(v *models.Vulnerability) {
	// Pick the most authoritative ID among the primary ID and aliases.
	best := v.ID
	for _, a := range v.Aliases {
		if idRank(a) > idRank(best) {
			best = a
		}
	}
	if best != v.ID && best != "" {
		// Demote the old primary ID to an alias.
		v.Aliases = append(v.Aliases, v.ID)
		v.ID = best
	}

	// Deduplicate aliases, dropping empties and the primary ID itself.
	seen := map[string]bool{v.ID: true}
	deduped := v.Aliases[:0]
	for _, a := range v.Aliases {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		deduped = append(deduped, a)
	}
	v.Aliases = deduped

	// Severity fallback chain: derive from CVSS score when missing.
	if v.Severity == "" {
		v.Severity = models.SeverityUnknown
	}
	if v.Severity == models.SeverityUnknown && v.Score > 0 {
		v.Severity = models.ScoreToSeverity(v.Score)
	}

	v.Summary = strings.TrimSpace(v.Summary)
	v.Details = strings.TrimSpace(v.Details)
}

// Merge fills missing fields in dst from src. Both records are assumed to
// describe the same vulnerability (matching ID or alias). Existing data in
// dst always wins; src only contributes what dst lacks. Aliases and
// references are unioned.
func Merge(dst *models.Vulnerability, src models.Vulnerability) {
	if dst.Severity == models.SeverityUnknown || dst.Severity == "" {
		if src.Severity != models.SeverityUnknown && src.Severity != "" {
			dst.Severity = src.Severity
		}
	}
	if dst.Score == 0 && src.Score > 0 {
		dst.Score = src.Score
		// A real score may upgrade an UNKNOWN severity.
		if dst.Severity == models.SeverityUnknown {
			dst.Severity = models.ScoreToSeverity(dst.Score)
		}
	}
	if dst.Summary == "" {
		dst.Summary = src.Summary
	}
	if dst.Details == "" {
		dst.Details = src.Details
	}
	if dst.FixedIn == "" {
		dst.FixedIn = src.FixedIn
	}
	if dst.PublishedAt.IsZero() {
		dst.PublishedAt = src.PublishedAt
	}
	if !dst.KnownExploited && src.KnownExploited {
		dst.KnownExploited = true
	}

	// Union aliases (including src's primary ID if it differs).
	seen := map[string]bool{dst.ID: true}
	for _, a := range dst.Aliases {
		seen[a] = true
	}
	candidates := append([]string{src.ID}, src.Aliases...)
	for _, a := range candidates {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		dst.Aliases = append(dst.Aliases, a)
	}

	// Union references.
	seenRefs := make(map[string]bool, len(dst.References))
	for _, r := range dst.References {
		seenRefs[r] = true
	}
	for _, r := range src.References {
		if r == "" || seenRefs[r] {
			continue
		}
		seenRefs[r] = true
		dst.References = append(dst.References, r)
	}
}
