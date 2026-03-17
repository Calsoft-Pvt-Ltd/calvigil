package parser

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// ConanLockParser parses C/C++ conan.lock files (Conan v2 JSON format).
type ConanLockParser struct{}

func init() {
	Register("conan.lock", func() Parser { return &ConanLockParser{} })
}

// conanLockV2 represents the Conan v2 lockfile format.
type conanLockV2 struct {
	Requires []string `json:"requires"`
	// Conan v1 format uses "graph_lock" with nodes
	GraphLock *conanGraphLock `json:"graph_lock,omitempty"`
}

type conanGraphLock struct {
	Nodes map[string]conanNode `json:"nodes"`
}

type conanNode struct {
	Ref string `json:"ref"` // e.g. "zlib/1.2.13"
}

func (p *ConanLockParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	var lock conanLockV2
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	var packages []models.Package
	seen := make(map[string]bool)

	// Conan v2: "requires" is a flat list like ["zlib/1.2.13", "openssl/3.1.0#hash"]
	for _, req := range lock.Requires {
		name, version := parseConanRef(req)
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		packages = append(packages, models.Package{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemConan,
			FilePath:  filePath,
		})
	}

	// Conan v1: graph_lock.nodes[].ref = "name/version"
	if lock.GraphLock != nil {
		for _, node := range lock.GraphLock.Nodes {
			if node.Ref == "" {
				continue
			}
			name, version := parseConanRef(node.Ref)
			if name == "" || version == "" {
				continue
			}
			key := name + "@" + version
			if seen[key] {
				continue
			}
			seen[key] = true
			packages = append(packages, models.Package{
				Name:      name,
				Version:   version,
				Ecosystem: models.EcosystemConan,
				FilePath:  filePath,
			})
		}
	}

	return packages, nil
}

// parseConanRef splits a Conan reference like "zlib/1.2.13#revhash" into name and version.
func parseConanRef(ref string) (name, version string) {
	// Strip revision hash after '#'
	if idx := strings.Index(ref, "#"); idx != -1 {
		ref = ref[:idx]
	}
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
