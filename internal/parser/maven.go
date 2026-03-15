package parser

import (
	"encoding/xml"
	"io"
	"regexp"
	"strings"

	"github.com/chavakula/calvigil/internal/models"
)

// PomXMLParser parses Maven pom.xml files.
type PomXMLParser struct{}

type pomProject struct {
	XMLName      xml.Name        `xml:"project"`
	Dependencies pomDependencies `xml:"dependencies"`
}

type pomDependencies struct {
	Dependency []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

func (p *PomXMLParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	var project pomProject
	if err := xml.NewDecoder(r).Decode(&project); err != nil {
		return nil, err
	}

	var packages []models.Package
	for _, dep := range project.Dependencies.Dependency {
		// Skip test dependencies
		if strings.EqualFold(dep.Scope, "test") {
			continue
		}
		// Skip dependencies with unresolved properties like ${project.version}
		if strings.Contains(dep.Version, "${") || dep.Version == "" {
			continue
		}

		name := dep.GroupID + ":" + dep.ArtifactID
		packages = append(packages, models.Package{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: models.EcosystemMaven,
			FilePath:  filePath,
		})
	}

	return packages, nil
}

// GradleParser parses build.gradle and build.gradle.kts files.
type GradleParser struct{}

// gradleDepRegex matches dependency declarations like:
//
//	implementation 'group:artifact:version'
//	implementation "group:artifact:version"
//	compile 'group:artifact:version'
//	api("group:artifact:version")
var gradleDepRegex = regexp.MustCompile(
	`(?:implementation|api|compile|runtimeOnly|compileOnly)\s*[\(]?\s*['"]([^:'"]+):([^:'"]+):([^'"]+)['"]`,
)

func (p *GradleParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var packages []models.Package
	matches := gradleDepRegex.FindAllStringSubmatch(string(data), -1)
	for _, match := range matches {
		if len(match) >= 4 {
			name := match[1] + ":" + match[2]
			version := match[3]
			packages = append(packages, models.Package{
				Name:      name,
				Version:   version,
				Ecosystem: models.EcosystemMaven,
				FilePath:  filePath,
			})
		}
	}

	return packages, nil
}
