package detector

import (
	"os"
	"path/filepath"

	"github.com/chavakula/calvigil/internal/models"
)

// MarkerFile maps a filename to its ecosystem.
type MarkerFile struct {
	Name      string
	Ecosystem models.Ecosystem
}

// knownMarkers lists all dependency manifest files we can parse.
var knownMarkers = []MarkerFile{
	// Go
	{Name: "go.mod", Ecosystem: models.EcosystemGo},
	// Python
	{Name: "requirements.txt", Ecosystem: models.EcosystemPyPI},
	{Name: "Pipfile.lock", Ecosystem: models.EcosystemPyPI},
	{Name: "poetry.lock", Ecosystem: models.EcosystemPyPI},
	// Node.js
	{Name: "package-lock.json", Ecosystem: models.EcosystemNpm},
	{Name: "yarn.lock", Ecosystem: models.EcosystemNpm},
	{Name: "pnpm-lock.yaml", Ecosystem: models.EcosystemNpm},
	// Java / Maven / Gradle
	{Name: "pom.xml", Ecosystem: models.EcosystemMaven},
	{Name: "build.gradle", Ecosystem: models.EcosystemGradle},
	{Name: "build.gradle.kts", Ecosystem: models.EcosystemGradle},
}

// DetectedFile represents a discovered dependency manifest file.
type DetectedFile struct {
	Path      string           // Absolute path to the file
	Filename  string           // Just the filename (e.g., "go.mod")
	Ecosystem models.Ecosystem // Which ecosystem this belongs to
}

// Detect walks the given directory and finds all known dependency manifest files.
// It returns the list of detected files and the unique set of ecosystems found.
func Detect(root string) ([]DetectedFile, []models.Ecosystem, error) {
	var files []DetectedFile
	ecosystemSet := make(map[models.Ecosystem]bool)

	markerMap := make(map[string]models.Ecosystem)
	for _, m := range knownMarkers {
		markerMap[m.Name] = m.Ecosystem
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip files we can't read
		}

		// Skip hidden directories and common non-project directories
		if info.IsDir() {
			name := info.Name()
			if name == "node_modules" || name == ".git" || name == "vendor" ||
				name == ".idea" || name == ".vscode" || name == "target" ||
				name == "build" || name == "dist" || name == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}

		if eco, ok := markerMap[info.Name()]; ok {
			files = append(files, DetectedFile{
				Path:      path,
				Filename:  info.Name(),
				Ecosystem: eco,
			})
			ecosystemSet[eco] = true
		}

		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	ecosystems := make([]models.Ecosystem, 0, len(ecosystemSet))
	for eco := range ecosystemSet {
		ecosystems = append(ecosystems, eco)
	}

	return files, ecosystems, nil
}
