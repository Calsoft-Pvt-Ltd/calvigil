package models

import "testing"

func TestToPURL_Go(t *testing.T) {
	p := Package{Name: "github.com/foo/bar", Version: "v1.2.3", Ecosystem: EcosystemGo}
	want := "pkg:golang/github.com%2Ffoo/bar@v1.2.3"
	if got := p.ToPURL(); got != want {
		t.Errorf("ToPURL() Go = %q, want %q", got, want)
	}
}

func TestToPURL_GoSingle(t *testing.T) {
	p := Package{Name: "example", Version: "v1.0.0", Ecosystem: EcosystemGo}
	want := "pkg:golang/example@v1.0.0"
	if got := p.ToPURL(); got != want {
		t.Errorf("ToPURL() Go single = %q, want %q", got, want)
	}
}

func TestToPURL_Npm(t *testing.T) {
	p := Package{Name: "lodash", Version: "4.17.21", Ecosystem: EcosystemNpm}
	want := "pkg:npm/lodash@4.17.21"
	if got := p.ToPURL(); got != want {
		t.Errorf("ToPURL() npm = %q, want %q", got, want)
	}
}

func TestToPURL_NpmScoped(t *testing.T) {
	p := Package{Name: "@babel/core", Version: "7.0.0", Ecosystem: EcosystemNpm}
	want := "pkg:npm/@babel/core@7.0.0"
	if got := p.ToPURL(); got != want {
		t.Errorf("ToPURL() npm scoped = %q, want %q", got, want)
	}
}

func TestToPURL_PyPI(t *testing.T) {
	p := Package{Name: "Flask_RESTful", Version: "0.3.9", Ecosystem: EcosystemPyPI}
	want := "pkg:pypi/flask-restful@0.3.9"
	if got := p.ToPURL(); got != want {
		t.Errorf("ToPURL() PyPI = %q, want %q", got, want)
	}
}

func TestToPURL_Maven(t *testing.T) {
	p := Package{Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", Ecosystem: EcosystemMaven}
	want := "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	if got := p.ToPURL(); got != want {
		t.Errorf("ToPURL() Maven = %q, want %q", got, want)
	}
}

func TestToPURL_MavenDotSeparated(t *testing.T) {
	p := Package{Name: "com.google.guava.guava", Version: "31.0", Ecosystem: EcosystemMaven}
	want := "pkg:maven/com.google.guava/guava@31.0"
	if got := p.ToPURL(); got != want {
		t.Errorf("ToPURL() Maven dot = %q, want %q", got, want)
	}
}

func TestToPURL_Crates(t *testing.T) {
	p := Package{Name: "serde", Version: "1.0.130", Ecosystem: EcosystemCrates}
	want := "pkg:cargo/serde@1.0.130"
	if got := p.ToPURL(); got != want {
		t.Errorf("ToPURL() crates = %q, want %q", got, want)
	}
}

func TestToPURL_RubyGem(t *testing.T) {
	p := Package{Name: "rails", Version: "7.0.0", Ecosystem: EcosystemRubyGem}
	want := "pkg:gem/rails@7.0.0"
	if got := p.ToPURL(); got != want {
		t.Errorf("ToPURL() gem = %q, want %q", got, want)
	}
}

func TestToPURL_PHP(t *testing.T) {
	p := Package{Name: "laravel/framework", Version: "9.0.0", Ecosystem: EcosystemPHP}
	want := "pkg:composer/laravel/framework@9.0.0"
	if got := p.ToPURL(); got != want {
		t.Errorf("ToPURL() PHP = %q, want %q", got, want)
	}
}

func TestToPURL_Conan(t *testing.T) {
	p := Package{Name: "boost", Version: "1.80.0", Ecosystem: EcosystemConan}
	want := "pkg:conan/boost@1.80.0"
	if got := p.ToPURL(); got != want {
		t.Errorf("ToPURL() conan = %q, want %q", got, want)
	}
}

func TestToPURL_NoVersion(t *testing.T) {
	p := Package{Name: "lodash", Ecosystem: EcosystemNpm}
	want := "pkg:npm/lodash"
	if got := p.ToPURL(); got != want {
		t.Errorf("ToPURL() no version = %q, want %q", got, want)
	}
}

func TestToPURL_UnknownEcosystem(t *testing.T) {
	p := Package{Name: "foo", Version: "1.0", Ecosystem: Ecosystem("unknown")}
	if got := p.ToPURL(); got != "" {
		t.Errorf("ToPURL() unknown ecosystem should be empty, got %q", got)
	}
}

func TestEnsurePURL(t *testing.T) {
	p := Package{Name: "lodash", Version: "4.17.21", Ecosystem: EcosystemNpm}
	p.EnsurePURL()
	if p.PURL == "" {
		t.Error("EnsurePURL should populate PURL")
	}

	// Should not overwrite existing PURL
	p.PURL = "pkg:npm/custom@1.0"
	p.EnsurePURL()
	if p.PURL != "pkg:npm/custom@1.0" {
		t.Error("EnsurePURL should not overwrite existing PURL")
	}
}
