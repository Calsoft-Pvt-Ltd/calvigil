package binary

import (
	"archive/zip"
	"bufio"
	"debug/buildinfo"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// ScanResult holds the output of a binary/SCA scan.
type ScanResult struct {
	Packages []models.Package
	Files    []ScannedFile
}

// ScannedFile records a binary that was scanned and what was found in it.
type ScannedFile struct {
	Path     string
	Type     string // "go-binary", "jar", "python-wheel", "rust-binary"
	PkgCount int
}

// Scan walks the given directory (or single file) and extracts embedded
// dependency information from compiled binaries, JAR archives, and Python
// wheels/eggs.
func Scan(root string, verbose bool) (*ScanResult, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("cannot stat %s: %w", root, err)
	}

	result := &ScanResult{}

	if !info.IsDir() {
		pkgs, sf := scanFile(root, verbose)
		result.Packages = pkgs
		if sf != nil {
			result.Files = append(result.Files, *sf)
		}
		return result, nil
	}

	seen := make(map[string]bool)
	err = filepath.Walk(root, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if fi.IsDir() {
			if shouldSkipDir(fi.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if fi.Size() == 0 {
			return nil
		}

		pkgs, sf := scanFile(path, verbose)
		if sf != nil {
			result.Files = append(result.Files, *sf)
		}
		for _, p := range pkgs {
			key := string(p.Ecosystem) + "|" + p.Name + "|" + p.Version
			if !seen[key] {
				seen[key] = true
				result.Packages = append(result.Packages, p)
			}
		}
		return nil
	})

	return result, err
}

func scanFile(path string, verbose bool) ([]models.Package, *ScannedFile) {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".jar", ".war", ".ear":
		pkgs := scanJAR(path)
		if len(pkgs) > 0 {
			return pkgs, &ScannedFile{Path: path, Type: "jar", PkgCount: len(pkgs)}
		}
		return nil, nil
	case ".whl":
		pkgs := scanWheel(path)
		if len(pkgs) > 0 {
			return pkgs, &ScannedFile{Path: path, Type: "python-wheel", PkgCount: len(pkgs)}
		}
		return nil, nil
	case ".egg":
		pkgs := scanWheel(path)
		if len(pkgs) > 0 {
			return pkgs, &ScannedFile{Path: path, Type: "python-egg", PkgCount: len(pkgs)}
		}
		return nil, nil
	}

	if pkgs := scanGoBinary(path); len(pkgs) > 0 {
		return pkgs, &ScannedFile{Path: path, Type: "go-binary", PkgCount: len(pkgs)}
	}

	return nil, nil
}

// scanGoBinary uses debug/buildinfo to read Go module data from a compiled binary.
func scanGoBinary(path string) []models.Package {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil
	}

	var pkgs []models.Package
	for _, dep := range bi.Deps {
		if dep.Path == "" || dep.Version == "" {
			continue
		}
		name := dep.Path
		version := dep.Version
		if dep.Replace != nil {
			name = dep.Replace.Path
			version = dep.Replace.Version
		}
		pkgs = append(pkgs, models.Package{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemGo,
			FilePath:  path,
			Indirect:  true,
		})
	}
	return pkgs
}

var (
	pomPropsGroupRe    = regexp.MustCompile(`(?m)^groupId=(.+)$`)
	pomPropsArtifactRe = regexp.MustCompile(`(?m)^artifactId=(.+)$`)
	pomPropsVersionRe  = regexp.MustCompile(`(?m)^version=(.+)$`)
	jarFilenameRe      = regexp.MustCompile(`^(.+?)-(\d+\..+)\.jar$`)
)

// scanJAR opens a JAR/WAR/EAR and extracts Maven coordinates from
// embedded META-INF/maven/.../pom.properties files, plus the MANIFEST.MF.
func scanJAR(path string) []models.Package {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer zr.Close()

	var pkgs []models.Package
	seen := make(map[string]bool)

	for _, f := range zr.File {
		name := f.Name

		if strings.HasSuffix(name, "pom.properties") && strings.Contains(name, "META-INF/maven/") {
			if pkg := parsePomProperties(f, path); pkg != nil {
				key := pkg.Name + "@" + pkg.Version
				if !seen[key] {
					seen[key] = true
					pkgs = append(pkgs, *pkg)
				}
			}
		}

		if strings.HasSuffix(name, ".jar") && strings.Contains(name, "BOOT-INF/lib/") {
			if pkg := parseJARFilename(name, path); pkg != nil {
				key := pkg.Name + "@" + pkg.Version
				if !seen[key] {
					seen[key] = true
					pkgs = append(pkgs, *pkg)
				}
			}
		}
	}

	if len(pkgs) == 0 {
		if pkg := scanJARManifest(zr, path); pkg != nil {
			pkgs = append(pkgs, *pkg)
		}
	}

	return pkgs
}

func parsePomProperties(f *zip.File, binaryPath string) *models.Package {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil
	}
	content := string(data)

	groupID := extractRegex(pomPropsGroupRe, content)
	artifactID := extractRegex(pomPropsArtifactRe, content)
	version := extractRegex(pomPropsVersionRe, content)

	if artifactID == "" || version == "" {
		return nil
	}

	name := artifactID
	if groupID != "" {
		name = groupID + ":" + artifactID
	}

	return &models.Package{
		Name:      name,
		Version:   version,
		Ecosystem: models.EcosystemMaven,
		FilePath:  binaryPath,
	}
}

func parseJARFilename(zipEntry string, binaryPath string) *models.Package {
	base := filepath.Base(zipEntry)
	m := jarFilenameRe.FindStringSubmatch(base)
	if len(m) != 3 {
		return nil
	}
	return &models.Package{
		Name:      m[1],
		Version:   m[2],
		Ecosystem: models.EcosystemMaven,
		FilePath:  binaryPath,
		Indirect:  true,
	}
}

func scanJARManifest(zr *zip.ReadCloser, binaryPath string) *models.Package {
	for _, f := range zr.File {
		if strings.EqualFold(f.Name, "META-INF/MANIFEST.MF") {
			rc, err := f.Open()
			if err != nil {
				return nil
			}
			defer rc.Close()
			return parseManifest(rc, binaryPath)
		}
	}
	return nil
}

func parseManifest(r io.Reader, binaryPath string) *models.Package {
	sc := bufio.NewScanner(r)
	var name, version string
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Implementation-Title: ") {
			name = strings.TrimPrefix(line, "Implementation-Title: ")
		} else if strings.HasPrefix(line, "Bundle-SymbolicName: ") && name == "" {
			name = strings.TrimPrefix(line, "Bundle-SymbolicName: ")
		} else if strings.HasPrefix(line, "Implementation-Version: ") {
			version = strings.TrimPrefix(line, "Implementation-Version: ")
		} else if strings.HasPrefix(line, "Bundle-Version: ") && version == "" {
			version = strings.TrimPrefix(line, "Bundle-Version: ")
		}
	}
	if name != "" && version != "" {
		return &models.Package{
			Name:      strings.TrimSpace(name),
			Version:   strings.TrimSpace(version),
			Ecosystem: models.EcosystemMaven,
			FilePath:  binaryPath,
		}
	}
	return nil
}

// scanWheel opens a .whl or .egg zip and reads the METADATA or PKG-INFO file.
func scanWheel(path string) []models.Package {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer zr.Close()

	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/METADATA") || strings.HasSuffix(f.Name, "/PKG-INFO") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			pkg := parsePythonMetadata(rc, path)
			rc.Close()
			if pkg != nil {
				return []models.Package{*pkg}
			}
		}
	}
	return nil
}

func parsePythonMetadata(r io.Reader, binaryPath string) *models.Package {
	sc := bufio.NewScanner(r)
	var name, version string
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Name: ") {
			name = strings.TrimPrefix(line, "Name: ")
		} else if strings.HasPrefix(line, "Version: ") {
			version = strings.TrimPrefix(line, "Version: ")
		}
	}
	if name != "" && version != "" {
		return &models.Package{
			Name:      strings.ToLower(strings.TrimSpace(name)),
			Version:   strings.TrimSpace(version),
			Ecosystem: models.EcosystemPyPI,
			FilePath:  binaryPath,
		}
	}
	return nil
}

func extractRegex(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

var binarySkipDirs = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true,
	"__pycache__": true, ".idea": true, ".vscode": true,
	".venv": true, "venv": true, ".env": true,
	".cache": true, ".tox": true, ".nox": true,
}

func shouldSkipDir(name string) bool {
	return binarySkipDirs[name]
}
