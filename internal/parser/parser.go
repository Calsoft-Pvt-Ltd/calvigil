package parser

import (
	"io"

	"github.com/chavakula/calvigil/internal/models"
)

// Parser parses a dependency manifest file and extracts packages.
type Parser interface {
	// Parse reads a dependency file and returns the packages declared in it.
	Parse(r io.Reader, filePath string) ([]models.Package, error)
}

// ForFile returns the appropriate parser for a given filename, or nil if unsupported.
func ForFile(filename string) Parser {
	switch filename {
	case "go.mod":
		return &GoModParser{}
	case "requirements.txt":
		return &RequirementsTxtParser{}
	case "Pipfile.lock":
		return &PipfileLockParser{}
	case "poetry.lock":
		return &PoetryLockParser{}
	case "package-lock.json":
		return &NpmLockParser{}
	case "yarn.lock":
		return &YarnLockParser{}
	case "pnpm-lock.yaml":
		return &PnpmLockParser{}
	case "pom.xml":
		return &PomXMLParser{}
	case "build.gradle", "build.gradle.kts":
		return &GradleParser{}
	default:
		return nil
	}
}
