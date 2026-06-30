// Package report provides the public, stable view of calvigil's scan report
// data model. External programs (for example, platforms that ingest the JSON
// produced by `calvigil scan -o json`) should import this package instead of
// the internal models package, which is not importable across module
// boundaries.
//
// All types are aliases of the internal canonical model, so this package is
// always schema-identical to what the CLI emits. The JSON contract follows
// semantic versioning of the calvigil module: fields are only added, never
// renamed or removed, within a major version.
package report

import "github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"

// Core result types.
type (
	// ScanResult is the root object of a calvigil JSON report.
	ScanResult = models.ScanResult
	// Vulnerability is a single security finding.
	Vulnerability = models.Vulnerability
	// Package is a discovered software dependency.
	Package = models.Package
	// AIEnrichment is the optional AI-generated context for a finding.
	AIEnrichment = models.AIEnrichment
	// SlopCodeSmellSummary is the optional AI-slop-style code smell rollup.
	SlopCodeSmellSummary = models.SlopCodeSmellSummary
	// SlopCodeSmellCategory groups related smell signals.
	SlopCodeSmellCategory = models.SlopCodeSmellCategory
	// SlopCodeSmellSignal links a concrete finding to the smell score.
	SlopCodeSmellSignal = models.SlopCodeSmellSignal
	// LicenseIssue is a license compliance finding.
	LicenseIssue = models.LicenseIssue
	// IntegrityIssue is a lockfile integrity verification finding.
	IntegrityIssue = models.IntegrityIssue
	// ConsistencyIssue is a phantom/missing dependency finding.
	ConsistencyIssue = models.ConsistencyIssue
)

// Enumerated string types.
type (
	// Severity is one of CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN.
	Severity = models.Severity
	// Ecosystem identifies a package ecosystem (Go, npm, PyPI, ...).
	Ecosystem = models.Ecosystem
	// VulnerabilitySource identifies which engine produced a finding.
	VulnerabilitySource = models.VulnerabilitySource
	// LicenseRisk classifies a license (permissive, copyleft, unknown).
	LicenseRisk = models.LicenseRisk
)

// Severity levels.
const (
	SeverityCritical = models.SeverityCritical
	SeverityHigh     = models.SeverityHigh
	SeverityMedium   = models.SeverityMedium
	SeverityLow      = models.SeverityLow
	SeverityUnknown  = models.SeverityUnknown
)

// Vulnerability sources.
const (
	SourceOSV          = models.SourceOSV
	SourceNVD          = models.SourceNVD
	SourceGitHubAdv    = models.SourceGitHubAdv
	SourceOSSIndex     = models.SourceOSSIndex
	SourceAIAnalysis   = models.SourceAIAnalysis
	SourcePatternMatch = models.SourcePatternMatch
	SourceSemgrep      = models.SourceSemgrep
	SourceIaC          = models.SourceIaC
)

// License risk levels.
const (
	LicensePermissive = models.LicensePermissive
	LicenseCopyleft   = models.LicenseCopyleft
	LicenseUnknown    = models.LicenseUnknown
)

// ParseSeverity converts a string to a Severity, accepting the formats used
// by NVD, GitHub, Semgrep and other sources.
func ParseSeverity(s string) Severity { return models.ParseSeverity(s) }

// ScoreToSeverity maps a CVSS score (0-10) to a Severity level.
func ScoreToSeverity(score float64) Severity { return models.ScoreToSeverity(score) }
