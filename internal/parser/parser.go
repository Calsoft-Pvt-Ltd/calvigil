package parser

import (
	"io"
	"sync"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// Parser parses a dependency manifest file and extracts packages.
type Parser interface {
	// Parse reads a dependency file and returns the packages declared in it.
	Parse(r io.Reader, filePath string) ([]models.Package, error)
}

// --- Registry pattern: parsers self-register via init() ---

var (
	parserRegistry      = make(map[string]func() Parser)
	parserRegistryMutex sync.RWMutex
)

// Register registers a parser factory for the given manifest filename.
// Typically called from init() in each parser file.
func Register(filename string, factory func() Parser) {
	parserRegistryMutex.Lock()
	defer parserRegistryMutex.Unlock()
	parserRegistry[filename] = factory
}

// SupportedFiles returns the list of registered manifest filenames.
func SupportedFiles() []string {
	parserRegistryMutex.RLock()
	defer parserRegistryMutex.RUnlock()
	out := make([]string, 0, len(parserRegistry))
	for f := range parserRegistry {
		out = append(out, f)
	}
	return out
}

// ForFile returns the appropriate parser for a given filename, or nil if unsupported.
func ForFile(filename string) Parser {
	parserRegistryMutex.RLock()
	factory, ok := parserRegistry[filename]
	parserRegistryMutex.RUnlock()

	if !ok {
		return nil
	}
	return factory()
}
