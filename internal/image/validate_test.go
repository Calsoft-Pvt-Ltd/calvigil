package image

import "testing"

func TestValidateImageRef_Accepts(t *testing.T) {
	cases := []string{
		"nginx",
		"nginx:latest",
		"nginx:1.25",
		"library/nginx",
		"library/nginx:1.25",
		"ghcr.io/org/app:v1.2.3",
		"registry.example.com:5000/team/service:tag",
		"alpine@sha256:" + repeat("a", 64),
		"docker-archive:/tmp/image.tar",
		"dir:/var/lib/rootfs",
		"oci-archive:/tmp/foo.tar",
	}
	for _, c := range cases {
		if err := validateImageRef(c); err != nil {
			t.Errorf("validateImageRef(%q) = %v, want nil", c, err)
		}
	}
}

func TestValidateImageRef_Rejects(t *testing.T) {
	cases := map[string]string{
		"empty":             "",
		"space":             "nginx latest",
		"tab":               "nginx\ttag",
		"semicolon":         "nginx;rm -rf /",
		"backtick":          "nginx:`whoami`",
		"dollar":            "nginx:$(whoami)",
		"pipe":              "nginx|cat",
		"redirect":          "nginx>/tmp/x",
		"control_char":      "nginx\x00latest",
		"newline":           "nginx\nevil",
		"traversal_in_path": "docker-archive:../../etc/passwd",
		"unknown_scheme":    "http://evil/payload",
		"leading_slash":     "/nginx",
		"bad_digest_length": "nginx@sha256:abcdef",
		"empty_scheme_path": "docker-archive:",
		"quotes":            "nginx:\"tag\"",
	}
	for name, ref := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateImageRef(ref); err == nil {
				t.Errorf("validateImageRef(%q) = nil, want error", ref)
			}
		})
	}
}

func TestValidateImageRef_TooLong(t *testing.T) {
	ref := repeat("a", 1025)
	if err := validateImageRef(ref); err == nil {
		t.Error("expected error for oversized ref")
	}
}

// repeat returns a string of n copies of s (test helper).
func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
