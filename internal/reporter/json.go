package reporter

import (
	"encoding/json"
	"io"

	"github.com/chavakula/calvigil/internal/models"
)

// JSONReporter outputs scan results as JSON.
type JSONReporter struct{}

func (r *JSONReporter) Report(result *models.ScanResult, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
