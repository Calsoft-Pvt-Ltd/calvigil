package reporter

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// SPDXReporter outputs scan results as an SPDX 2.3 JSON document.
type SPDXReporter struct{}

func init() {
	Register("spdx", func() Reporter { return &SPDXReporter{} })
}

// SPDX 2.3 JSON types

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages,omitempty"`
	Relationships     []spdxRelationship `json:"relationships,omitempty"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string            `json:"licenseDeclared,omitempty"`
	CopyrightText    string            `json:"copyrightText"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
	Supplier         string            `json:"supplier,omitempty"`
	Annotations      []spdxAnnotation  `json:"annotations,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

type spdxAnnotation struct {
	Annotator      string `json:"annotator"`
	AnnotationDate string `json:"annotationDate"`
	AnnotationType string `json:"annotationType"`
	Comment        string `json:"comment"`
}

func (r *SPDXReporter) Report(result *models.ScanResult, w io.Writer) error {
	projectName := result.ProjectPath
	if idx := strings.LastIndex(projectName, "/"); idx >= 0 {
		projectName = projectName[idx+1:]
	}

	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              projectName,
		DocumentNamespace: fmt.Sprintf("https://calvigil.dev/spdx/%s-%s", projectName, spdxHash(result)),
		CreationInfo: spdxCreationInfo{
			Created:  result.ScannedAt.UTC().Format(time.RFC3339),
			Creators: []string{"Tool: calvigil-0.1.0"},
		},
	}

	// Root package
	rootPkg := spdxPackage{
		SPDXID:           "SPDXRef-RootPackage",
		Name:             projectName,
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		CopyrightText:    "NOASSERTION",
	}
	doc.Packages = append(doc.Packages, rootPkg)

	// Build vulnerability lookup for annotations
	vulnMap := make(map[string][]models.Vulnerability)
	for _, v := range result.Vulnerabilities {
		if v.Package.Name == "" {
			continue
		}
		key := v.Package.Name + "@" + v.Package.Version
		vulnMap[key] = append(vulnMap[key], v)
	}

	// Add component packages
	seen := make(map[string]bool)
	packages := result.Packages
	if len(packages) == 0 {
		for _, v := range result.Vulnerabilities {
			if v.Package.Name == "" {
				continue
			}
			key := v.Package.Name + "@" + v.Package.Version
			if !seen[key] {
				packages = append(packages, v.Package)
				seen[key] = true
			}
		}
	}

	for i, pkg := range packages {
		key := pkg.Name + "@" + pkg.Version
		if seen[key] && len(result.Packages) > 0 {
			continue
		}
		seen[key] = true

		spdxID := fmt.Sprintf("SPDXRef-Package-%d", i+1)
		sp := spdxPackage{
			SPDXID:           spdxID,
			Name:             pkg.Name,
			VersionInfo:      pkg.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			CopyrightText:    "NOASSERTION",
		}

		if pkg.License != "" {
			sp.LicenseDeclared = pkg.License
			sp.LicenseConcluded = pkg.License
		} else {
			sp.LicenseDeclared = "NOASSERTION"
			sp.LicenseConcluded = "NOASSERTION"
		}

		purl := pkg.PURL
		if purl == "" {
			purl = pkg.ToPURL()
		}
		if purl != "" {
			sp.ExternalRefs = append(sp.ExternalRefs, spdxExternalRef{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			})
		}

		if pkg.Ecosystem != "" {
			sp.Supplier = fmt.Sprintf("Organization: %s", pkg.Ecosystem)
		}

		if vulns, ok := vulnMap[key]; ok {
			for _, v := range vulns {
				sp.Annotations = append(sp.Annotations, spdxAnnotation{
					Annotator:      "Tool: calvigil",
					AnnotationDate: result.ScannedAt.UTC().Format(time.RFC3339),
					AnnotationType: "REVIEW",
					Comment: fmt.Sprintf("Vulnerability %s (%s): %s [Fixed in: %s]",
						v.ID, v.Severity, v.Summary, orEmpty(v.FixedIn, "unknown")),
				})
			}
		}

		doc.Packages = append(doc.Packages, sp)

		doc.Relationships = append(doc.Relationships, spdxRelationship{
			SPDXElementID:      "SPDXRef-RootPackage",
			RelationshipType:   "DEPENDS_ON",
			RelatedSPDXElement: spdxID,
		})
	}

	doc.Relationships = append(doc.Relationships, spdxRelationship{
		SPDXElementID:      "SPDXRef-DOCUMENT",
		RelationshipType:   "DESCRIBES",
		RelatedSPDXElement: "SPDXRef-RootPackage",
	})

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(doc)
}

func spdxHash(result *models.ScanResult) string {
	h := sha256.New()
	h.Write([]byte(result.ProjectPath))
	h.Write([]byte(result.ScannedAt.String()))
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
}

func orEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
