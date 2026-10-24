package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateExampleReports(t *testing.T) {
	if os.Getenv("PHP2SHELL_GEN_EXAMPLES") != "1" {
		t.Skip("set PHP2SHELL_GEN_EXAMPLES=1 to regenerate")
	}
	dir := filepath.Join("..", "..", "testdata", "examples", "v2.7.2-qa")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, r *Report) {
		t.Helper()
		r.GeneratedUTC = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
		r.ToolVersion = Version
		FinalizeSummary(r)
		if err := os.WriteFile(filepath.Join(dir, name), EncodeHTML(r), 0644); err != nil {
			t.Fatal(err)
		}
	}

	r := NewReport("web-prod-01", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php-fpm", Version: "8.3.24", Source: "static", Location: "/usr/sbin/php-fpm8.3", Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION"})
	EvaluatePatchPosture(r)
	write("01-below-upstream.html", r)

	r2 := NewReport("web-prod-02", "linux", "amd64")
	r2.AddEvidence(Evidence{Type: "binary_static_version", Name: "php-fpm", Version: "8.3.36", Source: "static", Location: "/usr/sbin/php-fpm8.3", Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION"})
	EvaluatePatchPosture(r2)
	write("02-at-upstream-runtime-unverified.html", r2)

	r3 := NewReport("legacy-app", "linux", "amd64")
	r3.AddEvidence(Evidence{Type: "installed_package", Name: "php8.1-fpm", Version: "8.1.2", Source: "dpkg", Location: "/var/lib/dpkg/status", Detail: "Package version: 8.1.2-1ubuntu2.22", Interpretation: "PACKAGE_VERSION_ONLY_VENDOR_BACKPORT_AND_ACTIVE_SAPI_UNVERIFIED"})
	EvaluatePatchPosture(r3)
	write("03-legacy-vendor-verification.html", r3)

	r4 := NewReport("empty-host", "linux", "amd64")
	EvaluatePatchPosture(r4)
	write("04-no-php-detected.html", r4)

	r5 := NewReport("multi-php", "linux", "amd64")
	r5.AddEvidence(Evidence{Type: "binary_static_version", Name: "php", Version: "8.2.34", Source: "static", Location: "/usr/bin/php8.2", Interpretation: "x"})
	r5.AddEvidence(Evidence{Type: "binary_static_version", Name: "php-fpm", Version: "8.4.27", Source: "static", Location: "/usr/sbin/php-fpm8.4", Interpretation: "x"})
	EvaluatePatchPosture(r5)
	write("05-multiple-installations.html", r5)

	r6 := NewReport("partial", "linux", "amd64")
	r6.AddEvidence(Evidence{Type: "binary_static_version", Name: "php", Version: "8.4.20", Source: "static", Location: "/usr/bin/php", Interpretation: "x"})
	r6.AddCheck("webroot", "ACCESS_DENIED", "permission denied")
	r6.AddCheck("configuration", "TRUNCATED", "limit")
	EvaluatePatchPosture(r6)
	write("06-incomplete-coverage.html", r6)

	r7 := NewReport("dfir", "linux", "amd64")
	r7.AddEvidence(Evidence{Type: "binary_static_version", Name: "php-fpm", Version: "8.3.36", Source: "static", Location: "/usr/sbin/php-fpm", Interpretation: "x"})
	EvaluatePatchPosture(r7)
	r7.ExploitationAttemptStatus = "SUSPECTED_ATTEMPTS_REVIEW"
	r7.PossibleCompromiseStatus = "NOT_ASSESSED"
	r7.InvestigationCoverage = "PARTIAL"
	write("07-optional-dfir-findings.html", r7)
}
