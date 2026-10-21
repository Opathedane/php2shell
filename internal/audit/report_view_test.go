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

func TestDistinctInstallationsSameVersionStaySeparate(t *testing.T) {
	r := NewReport("web01", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php-fpm", Version: "8.3.24", Source: "static", Location: "/opt/app-a/sbin/php-fpm"})
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php-fpm", Version: "8.3.24", Source: "static", Location: "/opt/app-b/sbin/php-fpm"})
	EvaluatePatchPosture(r)
	groups := GroupInstallations(r)
	if len(groups) != 2 {
		t.Fatalf("expected 2 distinct install groups for same version, got %d (%+v)", len(groups), groups)
	}
	if groups[0].Key == groups[1].Key {
		t.Fatal("install keys must differ")
	}
	if !strings.HasPrefix(groups[0].Key, "install:binary-dir:") || !strings.HasPrefix(groups[1].Key, "install:binary-dir:") {
		t.Fatalf("expected binary-dir install keys, got %q and %q", groups[0].Key, groups[1].Key)
	}
}

func TestRepositoryDeclarationIsNotConfirmedPHPInstall(t *testing.T) {
	r := NewReport("dev", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "repository_declaration", Name: "Dockerfile", Version: "8.3.24", Source: "dockerfile", Location: "/repo/Dockerfile"})
	r.AddEvidence(Evidence{Type: "php_webroot_filename", Name: "index.php", Source: "webroot", Location: "/var/www/index.php"})
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	label, vers := humanPHPDetected(r)
	if label != "Declared only (not confirmed installed)" {
		t.Fatalf("label=%q", label)
	}
	if len(vers) != 1 || vers[0] != "8.3.24" {
		t.Fatal(vers)
	}
	if r.Summary.PHPDiscovery != "PHP_DECLARED_ONLY_NOT_CONFIRMED_INSTALLED" {
		t.Fatal(r.Summary.PHPDiscovery)
	}
	html := string(EncodeHTML(r))
	if strings.Contains(html, `<p class="value">Yes</p>`) {
		t.Fatal("must not report PHP installed Yes from repository declaration alone")
	}
	if !strings.Contains(html, "Declared only") {
		t.Fatal(html)
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
