package models

import (
	"net/url"
	"strings"
)

// ToPURL generates a Package URL (https://github.com/package-url/purl-spec)
// from a Package. Format: pkg:type/namespace/name@version
func (p Package) ToPURL() string {
	purlType, namespace, name := ecosystemToPURL(p.Ecosystem, p.Name)
	if purlType == "" {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("pkg:")
	sb.WriteString(purlType)
	sb.WriteString("/")

	if namespace != "" {
		sb.WriteString(url.PathEscape(namespace))
		sb.WriteString("/")
	}

	sb.WriteString(url.PathEscape(name))

	if p.Version != "" {
		sb.WriteString("@")
		sb.WriteString(url.PathEscape(p.Version))
	}

	return sb.String()
}

// ecosystemToPURL maps our ecosystem + package name to PURL type/namespace/name.
func ecosystemToPURL(eco Ecosystem, pkgName string) (purlType, namespace, name string) {
	switch eco {
	case EcosystemGo:
		// Go packages: pkg:golang/github.com/foo/bar@v1.0.0
		// The "namespace" is everything before the last path segment
		purlType = "golang"
		parts := strings.Split(pkgName, "/")
		if len(parts) > 1 {
			namespace = strings.Join(parts[:len(parts)-1], "/")
			name = parts[len(parts)-1]
		} else {
			name = pkgName
		}

	case EcosystemNpm:
		// Scoped: pkg:npm/%40scope/name@version
		// Unscoped: pkg:npm/name@version
		purlType = "npm"
		if strings.HasPrefix(pkgName, "@") {
			parts := strings.SplitN(pkgName, "/", 2)
			if len(parts) == 2 {
				namespace = parts[0]
				name = parts[1]
			} else {
				name = pkgName
			}
		} else {
			name = pkgName
		}

	case EcosystemPyPI:
		// Python: pkg:pypi/name@version (names normalized: lowercase, hyphens)
		purlType = "pypi"
		name = strings.ToLower(strings.ReplaceAll(pkgName, "_", "-"))

	case EcosystemMaven:
		// Maven: pkg:maven/group/artifact@version
		purlType = "maven"
		parts := strings.SplitN(pkgName, ":", 2)
		if len(parts) == 2 {
			namespace = parts[0]
			name = parts[1]
		} else {
			// Try dot-separated group
			dotParts := strings.Split(pkgName, ".")
			if len(dotParts) > 1 {
				name = dotParts[len(dotParts)-1]
				namespace = strings.Join(dotParts[:len(dotParts)-1], ".")
			} else {
				name = pkgName
			}
		}

	default:
		return "", "", ""
	}

	return purlType, namespace, name
}

// EnsurePURL populates the PURL field on a Package if it's empty.
func (p *Package) EnsurePURL() {
	if p.PURL == "" {
		p.PURL = p.ToPURL()
	}
}
