package reporter

import (
	"encoding/json"
	"io"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// JSONReporter outputs scan results as JSON.
type JSONReporter struct{}

func init() {
	Register("json", func() Reporter { return &JSONReporter{} })
}

func (r *JSONReporter) Report(result *models.ScanResult, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
