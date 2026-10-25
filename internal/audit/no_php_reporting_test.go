package audit

import (
	"strings"
	"testing"
)

func attachCompleteWindowsCoverage(r *Report) {
	r.AddCheck("packages", "NOT_SUPPORTED", "No passive native package database reader for this OS; no package commands executed")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0 PHP-like binary paths")
	r.AddCheck("windows_processes", "PARTIAL", "Observed 0 PHP/IIS process names")
	r.AddCheck("windows_iis_configuration", "NOT_APPLICABLE", "IIS configuration not present")
}

func attachCompleteLinuxCoverage(r *Report) {
	r.AddCheck("packages", "PARTIAL", "Read 1 supported package databases; 0 PHP-related packages; RPM/pacman and vendor alternatives not covered")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0 PHP-like binary paths")
	r.AddCheck("processes", "PARTIAL", "Observed 0 matching process names")
}

func TestWindowsNoPHPWithinCoverage(t *testing.T) {
	r := NewReport("win-empty", "windows", "amd64")
	attachCompleteWindowsCoverage(r)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	if r.Summary.PHPDiscovery != "NO_PHP_DETECTED_WITHIN_SCAN_COVERAGE" {
		t.Fatalf("php_discovery=%s", r.Summary.PHPDiscovery)
	}
	if r.Summary.PatchReview != "NO_PHP_SPECIFIC_REMEDIATION_IDENTIFIED" {
		t.Fatalf("patch_review=%s", r.Summary.PatchReview)
	}
	// Machine vulnerability status stays conservative / schema-stable.
	if r.VulnerabilityStatus != "NO_COMPARABLE_PHP_VERSION_FOUND_INVENTORY_INCOMPLETE" {
		t.Fatalf("vulnerability_status=%s", r.VulnerabilityStatus)
	}
	label, _ := humanPHPDetected(r)
	if label != "No PHP detected within scan coverage" {
		t.Fatal(label)
	}
	if HumanVulnerabilityLabelFor(r) != "No PHP-specific patch assessment" {
		t.Fatal(HumanVulnerabilityLabelFor(r))
	}
	if !strings.Contains(overallPriority(r), "no PHP detected within scan coverage") {
		t.Fatal(overallPriority(r))
	}

	html := string(EncodeHTML(r))
	if !strings.Contains(html, "No PHP detected within scan coverage") {
		t.Fatal("expected prominent no-PHP message")
	}
	if strings.Contains(html, "OS package database (no dpkg/apk") || strings.Contains(html, "dpkg/apk") {
		t.Fatal("Windows report must not warn about missing dpkg/apk")
	}
	if strings.Contains(html, "Identify which PHP binary or SAPI") {
		t.Fatal("must not recommend runtime identification when no PHP found")
	}
	if strings.Contains(html, "Apply upstream PHP 8.5.12") {
		t.Fatal("must not dump upstream patch remediation when no PHP found")
	}
	if strings.Contains(html, "Validate remediation by checking the active web handler") {
		t.Fatal("must not recommend remediation validation when no PHP found")
	}
	if !strings.Contains(html, "<strong>0</strong> PHP installations") {
		t.Fatal("expected zero installations wording")
	}
	// Scan execution incompleteness is independent: packages NOT_SUPPORTED must not force exit 2.
	if ScanIncomplete(r) {
		t.Fatal("Windows packages NOT_SUPPORTED must not mark ScanIncomplete")
	}
}

func TestLinuxNoPHPWithinCoverage(t *testing.T) {
	r := NewReport("linux-empty", "linux", "amd64")
	attachCompleteLinuxCoverage(r)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	if r.Summary.PHPDiscovery != "NO_PHP_DETECTED_WITHIN_SCAN_COVERAGE" {
		t.Fatal(r.Summary.PHPDiscovery)
	}
	html := string(EncodeHTML(r))
	if !strings.Contains(html, "No PHP detected within scan coverage") {
		t.Fatal(html)
	}
	if strings.Contains(html, "Immediately prioritize internet-reachable") {
		t.Fatal("unexpected remediation dump")
	}
}

func TestNoPHPIncompleteInventory(t *testing.T) {
	r := NewReport("partial-empty", "linux", "amd64")
	r.AddCheck("packages", "UNAVAILABLE", "Cannot read dpkg status database: permission denied")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0 PHP-like binary paths")
	r.AddCheck("processes", "ACCESS_DENIED", "Cannot list /proc")
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	if r.Summary.PHPDiscovery != "NO_PHP_EVIDENCE_FOUND_COVERAGE_LIMITED" {
		t.Fatal(r.Summary.PHPDiscovery)
	}
	label, _ := humanPHPDetected(r)
	if label != "Unable to determine — inventory incomplete" {
		t.Fatal(label)
	}
	if !strings.Contains(overallPriority(r), "inventory incomplete") {
		t.Fatal(overallPriority(r))
	}
	html := string(EncodeHTML(r))
	if strings.Contains(html, "No PHP detected within scan coverage") {
		t.Fatal("must not claim complete coverage")
	}
	if !strings.Contains(html, "packages") || !strings.Contains(html, "processes") {
		t.Fatal("expected genuine gaps in executive card")
	}
	joined := strings.Join(r.RecommendedActions, "\n")
	if strings.Contains(joined, "Apply upstream PHP 8.5.12") {
		t.Fatal("incomplete no-PHP must not dump full patch recipe")
	}
}

func TestPHPEvidenceVersionUnknown(t *testing.T) {
	r := NewReport("unknown-ver", "linux", "amd64")
	attachCompleteLinuxCoverage(r)
	r.AddEvidence(Evidence{
		Type: "binary_path", Name: "php", Source: "PATH", Location: "/opt/custom/php",
		Detail: "no version marker found", Interpretation: "PRESENT_VERSION_UNKNOWN_NOT_RUNTIME_VERIFIED",
	})
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	label, vers := humanPHPDetected(r)
	if label != "Yes (exact versions limited)" {
		t.Fatal(label)
	}
	if len(vers) != 0 {
		t.Fatal(vers)
	}
	if r.Summary.PHPDiscovery != "PHP_RELATED_EVIDENCE_FOUND_RUNTIME_UNVERIFIED" {
		t.Fatal(r.Summary.PHPDiscovery)
	}
	if !strings.Contains(overallPriority(r), "PHP version unknown") {
		t.Fatal(overallPriority(r))
	}
	html := string(EncodeHTML(r))
	if !strings.Contains(html, "without a comparable release version") && !strings.Contains(html, "exact versions limited") {
		t.Fatal("expected version-unknown messaging")
	}
	if !strings.Contains(html, "Identify which PHP binary or SAPI") {
		t.Fatal("runtime identification remains relevant when PHP evidence exists")
	}
}

func TestMultiplePHPInstallationsReporting(t *testing.T) {
	r := NewReport("multi", "linux", "amd64")
	attachCompleteLinuxCoverage(r)
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php", Version: "8.2.34", Source: "static", Location: "/usr/bin/php8.2"})
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php-fpm", Version: "8.4.27", Source: "static", Location: "/usr/sbin/php-fpm8.4"})
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	label, vers := humanPHPDetected(r)
	if label != "Yes" || len(vers) < 2 {
		t.Fatalf("label=%q vers=%v", label, vers)
	}
	groups := GroupInstallations(r)
	if len(groups) < 2 {
		t.Fatalf("groups=%d", len(groups))
	}
	html := string(EncodeHTML(r))
	if strings.Contains(html, "No PHP detected within scan coverage") {
		t.Fatal("must not use no-PHP banner when installs exist")
	}
	if !strings.Contains(html, "Update review required") && !strings.Contains(html, "8.2.34") {
		t.Fatal("expected multi-install assessment content")
	}
	if r.VulnerabilityStatus == "MULTIPLE_RUNTIMES_MIXED_PATCH_LEVELS_REVIEW_REQUIRED" {
		if !strings.Contains(html, "Multiple PHP installations with mixed patch levels") {
			t.Fatal("expected mixed-patch executive detail")
		}
	}
	if !strings.Contains(html, ":focus-visible") {
		t.Fatal("expected focus-visible accessibility styles")
	}
	if OverallPriority(r) == "" || !strings.Contains(html, "Overall priority:") {
		t.Fatal("priority must appear in HTML")
	}
}

func TestHTMLPatchedAndBelowThresholdPhrases(t *testing.T) {
	patched := NewReport("ok", "linux", "amd64")
	attachCompleteLinuxCoverage(patched)
	patched.AddEvidence(Evidence{Type: "binary_static_version", Name: "php", Version: "8.4.27", Source: "static", Location: "/usr/bin/php"})
	EvaluatePatchPosture(patched)
	FinalizeSummary(patched)
	htmlOK := string(EncodeHTML(patched))
	if !strings.Contains(htmlOK, "No below-threshold versions observed") && !strings.Contains(htmlOK, "At or above upstream fix") {
		t.Fatalf("patched wording missing: status=%s", patched.VulnerabilityStatus)
	}

	below := NewReport("old", "linux", "amd64")
	attachCompleteLinuxCoverage(below)
	below.AddEvidence(Evidence{Type: "binary_static_version", Name: "php", Version: "8.4.24", Source: "static", Location: "/usr/bin/php"})
	EvaluatePatchPosture(below)
	FinalizeSummary(below)
	htmlBelow := string(EncodeHTML(below))
	if !strings.Contains(htmlBelow, "Update review required") {
		t.Fatal(htmlBelow)
	}
	if !strings.Contains(htmlBelow, "Recommended next steps") {
		t.Fatal("expected next steps section")
	}
}

func TestGenuineWindowsEvidenceSourceFailure(t *testing.T) {
	r := NewReport("win-denied", "windows", "amd64")
	r.AddCheck("packages", "NOT_SUPPORTED", "No passive native package database reader for this OS")
	r.AddCheck("binary_paths", "ACCESS_DENIED", "Cannot enumerate PATH directories")
	r.AddCheck("windows_processes", "UNAVAILABLE", "WMI query failed")
	r.AddCheck("windows_iis_configuration", "ACCESS_DENIED", "Cannot read applicationHost.config")
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	if r.Summary.PHPDiscovery != "NO_PHP_EVIDENCE_FOUND_COVERAGE_LIMITED" {
		t.Fatal(r.Summary.PHPDiscovery)
	}
	gaps := relevantPHPInventoryGaps(r)
	joined := strings.Join(gaps, ";")
	if strings.Contains(joined, "packages") {
		t.Fatalf("packages NOT_SUPPORTED must not be a Windows gap: %v", gaps)
	}
	if !strings.Contains(joined, "binary_paths") || !strings.Contains(joined, "windows_processes") || !strings.Contains(joined, "windows_iis_configuration") {
		t.Fatalf("expected Windows discovery failures: %v", gaps)
	}
	html := string(EncodeHTML(r))
	if strings.Contains(html, "dpkg/apk") {
		t.Fatal("must not mention dpkg/apk on Windows")
	}
	if !ScanIncomplete(r) {
		t.Fatal("ACCESS_DENIED/UNAVAILABLE must mark ScanIncomplete independently of PHP detection")
	}
}

func TestLinuxUnsupportedPackagesNotConfusedWithWindows(t *testing.T) {
	r := NewReport("rhel-empty", "linux", "amd64")
	r.AddCheck("packages", "NOT_SUPPORTED", "No readable dpkg/apk database on this host. RPM not inventoried")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0")
	r.AddCheck("processes", "PARTIAL", "Observed 0")
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	// Soft packaging gap → incomplete for no-PHP claim, not Windows-style dpkg noise wording in limParts alone.
	if r.Summary.PHPDiscovery != "NO_PHP_EVIDENCE_FOUND_COVERAGE_LIMITED" {
		t.Fatal(r.Summary.PHPDiscovery)
	}
	gaps := relevantPHPInventoryGaps(r)
	if len(gaps) == 0 || !strings.Contains(gaps[0], "unsupported packaging") {
		t.Fatalf("gaps=%v", gaps)
	}
}

func TestBareReportWithoutCoverageStaysConservative(t *testing.T) {
	r := NewReport("bare", "windows", "amd64")
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	if r.Summary.PHPDiscovery != "NO_PHP_EVIDENCE_FOUND_COVERAGE_LIMITED" {
		t.Fatal(r.Summary.PHPDiscovery)
	}
}
