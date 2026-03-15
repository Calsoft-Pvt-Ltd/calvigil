package reporter

import (
	"io"

	"github.com/chavakula/calvigil/internal/models"
)

// Reporter writes scan results in a specific format.
type Reporter interface {
	// Report writes the scan results to the given writer.
	Report(result *models.ScanResult, w io.Writer) error
}

// ForFormat returns the appropriate reporter for the given output format.
func ForFormat(format string) Reporter {
	switch format {
	case "json":
		return &JSONReporter{}
	case "sarif":
		return &SARIFReporter{}
	case "cyclonedx":
		return &CycloneDXReporter{}
	case "openvex":
		return &OpenVEXReporter{}
	case "html":
		return &HTMLReporter{}
	case "pdf":
		return &PDFReporter{}
	default:
		return &TableReporter{}
	}
}
