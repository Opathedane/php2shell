package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGroupInstallationsDedupesExtensionsWithoutLosingEvidence(t *testing.T) {
	r := NewReport("web01", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.3-fpm", Version: "8.3.24", Source: "dpkg", Location: "/var/lib/dpkg/status"})
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.3-cli", Version: "8.3.24", Source: "dpkg", Location: "/var/lib/dpkg/status"})
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.3-common", Version: "8.3.24", Source: "dpkg", Location: "/var/lib/dpkg/status"})
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.3-mysql", Version: "8.3.24", Source: "dpkg", Location: "/var/lib/dpkg/status", Interpretation: "PACKAGE_VERSION_ONLY_VENDOR_BACKPORT_AND_ACTIVE_SAPI_UNVERIFIED"})
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.4-fpm", Version: "8.4.11", Source: "dpkg", Location: "/var/lib/dpkg/status"})
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php-common", Version: "", Source: "dpkg", Detail: "Package version: 24.04.1", Interpretation: "PACKAGE_METADATA_ONLY_NOT_PHP_RUNTIME_VERSION"})
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	// Extension packages must remain in evidence.
	foundExt := false
	for _, e := range r.Evidence {
		if e.Name == "php8.3-mysql" {
			foundExt = true
		}
		if e.Name == "php-common" && e.Version != "" {
			t.Fatal("php-common must not carry a PHP runtime version")
		}
	}
	if !foundExt {
		t.Fatal("extension evidence missing")
	}

	groups := GroupInstallations(r)
	if len(groups) < 2 {
		t.Fatalf("expected distinct 8.3 and 8.4 groups, got %+v", groups)
	}
	// Patch assessments should not explode one-per-extension.
	for _, a := range r.PatchAssessments {
		if a.Component == "php8.3-mysql" {
			t.Fatal("extension should not produce its own patch assessment row")
		}
		if a.Component == "php-common" {
			t.Fatal("php-common packaging revision must not be assessed as PHP")
		}
	}

	html := string(EncodeHTML(r))
	if !strings.Contains(html, "PHP 8.3.24") || !strings.Contains(html, "PHP 8.4.11") {
		t.Fatal("grouped versions missing from HTML")
	}
	if !strings.Contains(html, "Update review required") {
		t.Fatal("human assessment label missing")
	}
	if strings.Count(html, "<details>") < 4 {
		t.Fatal("expected multiple collapsible sections")
	}
	if strings.Contains(html, "<script>") {
		t.Fatal("no script tags allowed")
	}
}

func TestHTMLEscapingPreservedInRedesign(t *testing.T) {
	r := NewReport(`<script>alert(1)</script>`, "linux", "amd64")
	r.AddEvidence(Evidence{Type: "installed_package", Name: `<img src=x onerror=alert(1)>`, Version: "8.3.24", Source: "dpkg"})
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	s := string(EncodeHTML(r))
	if strings.Contains(s, "<script>alert") || strings.Contains(s, "<img src=x") {
		t.Fatal("unescaped HTML")
	}
	if !strings.Contains(s, "&lt;img") {
		t.Fatal("expected escaped content")
	}
}

func TestHTMLOnlySaveStillHolds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.html")
	r := NewReport("web01", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.3-fpm", Version: "8.3.24", Source: "dpkg"})
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	if err := Save(r, path); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "sample.html" {
		t.Fatalf("html-only violated: %+v", entries)
	}
}

func TestFocusedNextStepsMentionVersions(t *testing.T) {
	r := NewReport("web01", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.3-fpm", Version: "8.3.24", Source: "dpkg"})
	EvaluatePatchPosture(r)
	steps := BuildFocusedNextSteps(r)
	joined := strings.Join(steps, " ")
	if !strings.Contains(joined, "8.3.24") || !strings.Contains(joined, "8.3.36") {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, "serves HTTP") {
		t.Fatal("expected active runtime guidance")
	}
}
