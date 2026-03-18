package parser

import (
	"strings"
	"testing"
)

func TestGoModTransitiveDeps(t *testing.T) {
	input := "module example.com/myproject\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgithub.com/stretchr/testify v1.8.4\n\tgolang.org/x/net v0.15.0 // indirect\n\tgolang.org/x/text v0.13.0 // indirect\n)\n"

	p := &GoModParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "go.mod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 4 {
		t.Fatalf("expected 4 packages, got %d", len(pkgs))
	}

	directCount, indirectCount := 0, 0
	for _, pkg := range pkgs {
		if pkg.Indirect {
			indirectCount++
		} else {
			directCount++
		}
	}
	if directCount != 2 {
		t.Errorf("expected 2 direct deps, got %d", directCount)
	}
	if indirectCount != 2 {
		t.Errorf("expected 2 indirect deps, got %d", indirectCount)
	}

	for _, pkg := range pkgs {
		switch pkg.Name {
		case "github.com/gin-gonic/gin":
			if pkg.Indirect {
				t.Error("gin should be direct")
			}
		case "golang.org/x/net":
			if !pkg.Indirect {
				t.Error("x/net should be indirect")
			}
		}
	}
}

func TestNpmLockV2TransitiveDeps(t *testing.T) {
	input := `{"name":"my-app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"my-app","version":"1.0.0"},"node_modules/express":{"version":"4.18.2"},"node_modules/express/node_modules/cookie":{"version":"0.5.0"},"node_modules/lodash":{"version":"4.17.21"}}}`

	p := &NpmLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "package-lock.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	for _, pkg := range pkgs {
		switch pkg.Name {
		case "express":
			if pkg.Indirect {
				t.Error("express should be direct (depth 1)")
			}
		case "cookie":
			if !pkg.Indirect {
				t.Error("cookie should be transitive (nested under express)")
			}
		case "lodash":
			if pkg.Indirect {
				t.Error("lodash should be direct (depth 1)")
			}
		}
	}
}

func TestNpmLockV1TransitiveDeps(t *testing.T) {
	input := `{"name":"my-app","version":"1.0.0","lockfileVersion":1,"dependencies":{"express":{"version":"4.18.2","requires":{"cookie":"0.5.0"},"dependencies":{"cookie":{"version":"0.5.0"}}},"lodash":{"version":"4.17.21"}}}`

	p := &NpmLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "package-lock.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) < 3 {
		t.Fatalf("expected at least 3 packages, got %d", len(pkgs))
	}

	foundTransitiveCookie := false
	for _, pkg := range pkgs {
		switch pkg.Name {
		case "express":
			if pkg.Indirect {
				t.Error("express should be direct (top-level)")
			}
		case "cookie":
			if !pkg.Indirect {
				t.Error("cookie should be transitive (nested)")
			}
			foundTransitiveCookie = true
		case "lodash":
			if pkg.Indirect {
				t.Error("lodash should be direct (top-level)")
			}
		}
	}
	if !foundTransitiveCookie {
		t.Error("expected to find transitive cookie package")
	}
}

func TestCargoLockTransitiveDeps(t *testing.T) {
	input := "# Cargo generated\n[[package]]\nname = \"my-project\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde 1.0.180\",\n \"tokio 1.32.0\",\n]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.180\"\ndependencies = [\n \"serde_derive 1.0.180\",\n]\n\n[[package]]\nname = \"serde_derive\"\nversion = \"1.0.180\"\n\n[[package]]\nname = \"tokio\"\nversion = \"1.32.0\"\n"

	p := &CargoLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "Cargo.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages (root skipped), got %d", len(pkgs))
	}

	for _, pkg := range pkgs {
		switch pkg.Name {
		case "serde":
			if pkg.Indirect {
				t.Error("serde should be direct (in root deps)")
			}
		case "tokio":
			if pkg.Indirect {
				t.Error("tokio should be direct (in root deps)")
			}
		case "serde_derive":
			if !pkg.Indirect {
				t.Error("serde_derive should be transitive (not in root deps)")
			}
		}
	}
}

func TestGemfileLockTransitiveDeps(t *testing.T) {
	input := "GEM\n  remote: https://rubygems.org/\n  specs:\n    actionpack (7.0.4)\n      actionview (= 7.0.4)\n      activesupport (= 7.0.4)\n    actionview (7.0.4)\n    activesupport (7.0.4)\n    rails (7.0.4)\n      actionpack (= 7.0.4)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (~> 7.0)\n"

	p := &GemfileLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "Gemfile.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	directCount, indirectCount := 0, 0
	for _, pkg := range pkgs {
		if pkg.Indirect {
			indirectCount++
		} else {
			directCount++
		}
	}

	if directCount == 0 {
		t.Error("expected some direct gems (4-space indent)")
	}
	if indirectCount == 0 {
		t.Error("expected some transitive gems (6-space indent)")
	}

	for _, pkg := range pkgs {
		if pkg.Name == "rails" && pkg.Indirect {
			t.Error("rails at 4-space indent should be direct")
		}
	}
}

func TestPoetryLockWithoutPyProjectAllDirect(t *testing.T) {
	input := "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[[package]]\nname = \"urllib3\"\nversion = \"2.0.7\"\n"

	p := &PoetryLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "/tmp/nonexistent/poetry.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	for _, pkg := range pkgs {
		if pkg.Indirect {
			t.Errorf("without pyproject.toml, %s should default to direct", pkg.Name)
		}
	}
}

func TestRequirementsTxtAllDirect(t *testing.T) {
	input := "requests==2.31.0\nflask>=2.3.0\nurllib3==2.0.7\n"

	p := &RequirementsTxtParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "requirements.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	for _, pkg := range pkgs {
		if pkg.Indirect {
			t.Errorf("%s in requirements.txt should be direct", pkg.Name)
		}
	}
}

func TestPipfileLockAllDirect(t *testing.T) {
	input := `{"_meta":{"requires":{"python_version":"3.11"}},"default":{"requests":{"version":"==2.31.0"},"urllib3":{"version":"==2.0.7"}},"develop":{}}`

	p := &PipfileLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "Pipfile.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	for _, pkg := range pkgs {
		if pkg.Indirect {
			t.Errorf("%s in Pipfile.lock should be direct", pkg.Name)
		}
	}
}

func TestComposerLockWithoutJsonAllDirect(t *testing.T) {
	input := `{"packages":[{"name":"monolog/monolog","version":"3.5.0"},{"name":"psr/log","version":"3.0.0"}],"packages-dev":[]}`

	p := &ComposerLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "/tmp/nonexistent/composer.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	for _, pkg := range pkgs {
		if pkg.Indirect {
			t.Errorf("without composer.json, %s should default to direct", pkg.Name)
		}
	}
}
