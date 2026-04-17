package image

import (
	"fmt"
	"regexp"
	"strings"
)

// Supported scheme prefixes understood by syft. A scheme is an opaque
// prefix followed by ":" (e.g. "docker-archive:foo.tar"). Anything left of
// the first ":" is matched against this set case-insensitively.
var supportedSchemes = map[string]struct{}{
	"docker":         {},
	"docker-archive": {},
	"oci":            {},
	"oci-archive":    {},
	"oci-dir":        {},
	"podman":         {},
	"containerd":     {},
	"singularity":    {},
	"registry":       {},
	"dir":            {},
	"file":           {},
}

// ociRefPattern matches the "name[:tag][@digest]" portion of an OCI
// reference. Name components may contain lowercase letters, digits, dots,
// underscores, and hyphens, separated by "/" and optionally prefixed by a
// registry host:port.
var ociRefPattern = regexp.MustCompile(
	`^[A-Za-z0-9][A-Za-z0-9._-]*` + // first path component (registry or name)
		`(?::[0-9]{1,5})?` + // optional registry port
		`(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*` + // additional path components
		`(?::[A-Za-z0-9][A-Za-z0-9._-]*)?` + // optional tag
		`(?:@sha256:[a-f0-9]{64})?$`, // optional digest
)

// safePathPattern matches a safe path for scheme-prefixed refs (docker-archive,
// dir, etc.). Disallows shell metacharacters and control characters while
// still permitting absolute paths, extensions, and common path chars.
var safePathPattern = regexp.MustCompile(`^[A-Za-z0-9._/@:+\-]+$`)

// validateImageRef validates a user-supplied image reference before it is
// forwarded to syft via exec.Command. It rejects shell metacharacters,
// embedded whitespace, and control characters so a malformed ref cannot be
// misinterpreted by syft or an underlying container runtime.
//
// Accepted forms:
//   - Plain OCI references:   nginx, nginx:1.25, library/nginx@sha256:...
//   - With registry:          ghcr.io/org/app:tag
//   - Scheme-prefixed paths:  docker-archive:/tmp/image.tar, dir:/rootfs
func validateImageRef(ref string) error {
	if ref == "" {
		return fmt.Errorf("image reference is empty")
	}
	if len(ref) > 1024 {
		return fmt.Errorf("image reference too long (max 1024 chars)")
	}
	// Reject control characters and whitespace outright.
	for _, r := range ref {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("image reference contains control characters")
		}
		if r == ' ' || r == '\t' {
			return fmt.Errorf("image reference contains whitespace")
		}
	}
	// Reject shell metacharacters. exec.Command does not invoke a shell, but
	// syft may pass parts of the ref to an external runtime (podman, docker)
	// which could interpret them.
	if strings.ContainsAny(ref, "`$;&|<>()*?!\\\"'") {
		return fmt.Errorf("image reference contains unsafe characters")
	}

	// If the ref has a scheme prefix understood by syft, validate the path
	// portion; otherwise treat the whole string as an OCI ref.
	if i := strings.Index(ref, ":"); i > 0 {
		scheme := strings.ToLower(ref[:i])
		if _, ok := supportedSchemes[scheme]; ok {
			path := ref[i+1:]
			if path == "" {
				return fmt.Errorf("image reference scheme %q has empty path", scheme)
			}
			if strings.Contains(path, "..") {
				return fmt.Errorf("image reference path contains traversal sequence")
			}
			if !safePathPattern.MatchString(path) {
				return fmt.Errorf("image reference path contains unsafe characters")
			}
			return nil
		}
	}

	if !ociRefPattern.MatchString(ref) {
		return fmt.Errorf("invalid image reference format: %q", ref)
	}
	return nil
}
