package reporter

import (
	"io"
	"sync"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// Reporter writes scan results in a specific format.
type Reporter interface {
	// Report writes the scan results to the given writer.
	Report(result *models.ScanResult, w io.Writer) error
}

// --- Registry pattern: reporters self-register via init() ---

var (
	registry      = make(map[string]func() Reporter)
	registryMutex sync.RWMutex
)

// Register registers a reporter factory for the given format name.
// Typically called from init() in each reporter file.
func Register(format string, factory func() Reporter) {
	registryMutex.Lock()
	defer registryMutex.Unlock()
	registry[format] = factory
}

// Formats returns the list of registered format names.
func Formats() []string {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	out := make([]string, 0, len(registry))
	for f := range registry {
		out = append(out, f)
	}
	return out
}

// ForFormat returns the appropriate reporter for the given output format.
// Falls back to the table reporter if the format is unknown.
func ForFormat(format string) Reporter {
	registryMutex.RLock()
	factory, ok := registry[format]
	registryMutex.RUnlock()

	if !ok {
		// Default fallback
		return &TableReporter{}
	}
	return factory()
}
