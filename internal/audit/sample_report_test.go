package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWriteSampleSimplifiedHTML produces a realistic sample report for manual review.
// Output: testdata/sample-simplified-report.html (gitignored via writing under t.TempDir in CI;
// when PHP2SHELL_WRITE_SAMPLE=1, writes under testdata/).
func TestWriteSampleSimplifiedHTML(t *testing.T) {
	r := NewReport("app-web-01.example.local", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 16, 5, 0, 0, time.UTC)
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.3-fpm", Version: "8.3.24", Source: "dpkg installed package metadata", Location: "/var/lib/dpkg/status", Detail: "Package version: 8.3.24-1ubuntu1", Interpretation: "PACKAGE_VERSION_ONLY_VENDOR_BACKPORT_AND_ACTIVE_SAPI_UNVERIFIED"})
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.3-cli", Version: "8.3.24", Source: "dpkg installed package metadata", Location: "/var/lib/dpkg/status", Detail: "Package version: 8.3.24-1ubuntu1", Interpretation: "PACKAGE_VERSION_ONLY_VENDOR_BACKPORT_AND_ACTIVE_SAPI_UNVERIFIED"})
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.3-common", Version: "8.3.24", Source: "dpkg installed package metadata", Location: "/var/lib/dpkg/status", Detail: "Package version: 8.3.24-1ubuntu1", Interpretation: "PACKAGE_VERSION_ONLY_VENDOR_BACKPORT_AND_ACTIVE_SAPI_UNVERIFIED"})
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.3-mysql", Version: "8.3.24", Source: "dpkg installed package metadata", Location: "/var/lib/dpkg/status", Detail: "Package version: 8.3.24-1ubuntu1", Interpretation: "PACKAGE_VERSION_ONLY_VENDOR_BACKPORT_AND_ACTIVE_SAPI_UNVERIFIED"})
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.4-fpm", Version: "8.4.11", Source: "dpkg installed package metadata", Location: "/var/lib/dpkg/status", Detail: "Package version: 8.4.11-1", Interpretation: "PACKAGE_VERSION_ONLY_VENDOR_BACKPORT_AND_ACTIVE_SAPI_UNVERIFIED"})
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php-common", Version: "", Source: "dpkg installed package metadata", Location: "/var/lib/dpkg/status", Detail: "Package version: 24.04.1", Interpretation: "PACKAGE_METADATA_ONLY_NOT_PHP_RUNTIME_VERSION"})
	r.AddEvidence(Evidence{Type: "running_process", Name: "php-fpm8.3", Source: "/proc/PID/comm snapshot", Location: "PID=2214", Interpretation: "PROCESS_NAME_ONLY_ACTIVE_HTTP_SAPI_AND_PATCH_STATUS_UNVERIFIED"})
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php-fpm8.3", Version: "8.3.24", Source: "well-known path static binary inspection", Location: "/usr/sbin/php-fpm8.3", Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION"})
	r.AddCheck("packages", "PARTIAL", "Read 1 supported package databases; 6 PHP-related packages")
	r.AddCheck("active_http_sapi_verification", "NOT_IMPLEMENTED", "Package/process/path observations cannot verify the PHP runtime actually serving HTTP traffic")
	r.AddWarning("Signed indicator rules not loaded")
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	html := EncodeHTML(r)
	outDir := t.TempDir()
	if os.Getenv("PHP2SHELL_WRITE_SAMPLE") == "1" {
		outDir = filepath.Join(moduleRootDir(t), "testdata")
		_ = os.MkdirAll(outDir, 0755)
	}
	path := filepath.Join(outDir, "sample-simplified-report.html")
	if err := os.WriteFile(path, html, 0600); err != nil {
		t.Fatal(err)
	}
	s := string(html)
	for _, want := range []string{
		"PHP2Shell Security Assessment",
		"Update review required",
		"PHP 8.3.24",
		"PHP 8.4.11",
		"Recommended next steps",
		"<details>",
		"Full technical evidence",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("sample missing %q", want)
		}
	}
	t.Log("wrote", path)
}
