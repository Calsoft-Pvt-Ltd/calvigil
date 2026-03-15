package analyzer

import (
	"context"

	"github.com/chavakula/calvigil/internal/models"
)

// Analyzer performs source code analysis to detect vulnerabilities.
type Analyzer interface {
	// Analyze scans source files in the given directory and returns detected vulnerabilities.
	Analyze(ctx context.Context, projectPath string, verbose bool) ([]models.Vulnerability, error)
}
