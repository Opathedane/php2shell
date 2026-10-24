package audit

import (
	"strings"
	"testing"
)

func TestNoPHPFoundIsNotClearance(t *testing.T) {
	r := NewReport("example", "windows", "amd64")
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	if r.Summary.PHPDiscovery != "NO_PHP_EVIDENCE_FOUND_COVERAGE_LIMITED" {
		t.Fatal(r.Summary)
	}
	if r.Summary.CompromiseReview != "NOT_ASSESSED_NO_VALIDATED_CVE_DETECTION" {
		t.Fatal(r.Summary)
	}
	html := string(EncodeHTML(r))
	if !strings.Contains(html, "Recommended next steps") {
		t.Fatal("summary not in HTML")
	}
	if !strings.Contains(html, "<details>") {
		t.Fatal("expected collapsible technical sections")
	}
}
func TestUrgentPatchAndIOCMatchRetainUncertainty(t *testing.T) {
	r := NewReport("example", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.4-fpm", Version: "8.4.26", Source: "dpkg"})
	EvaluatePatchPosture(r)
	r.CompromiseStatus = "INDICATORS_MATCHED_REVIEW_REQUIRED"
	FinalizeSummary(r)
	if r.Summary.PatchReview != "URGENT_PATCH_OR_VENDOR_BACKPORT_REVIEW" || r.Summary.CompromiseReview != "IOC_MATCHES_INVESTIGATE" {
		t.Fatal(r.Summary)
	}
	if !strings.Contains(string(EncodeHTML(r)), "8.4.27") {
		t.Fatal("fix missing")
	}
}
func TestGenericIISProcessDoesNotProvePHP(t *testing.T) {
	r := NewReport("example", "windows", "amd64")
	r.AddEvidence(Evidence{Type: "running_process", Name: "w3wp.exe"})
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	if r.Summary.PHPDiscovery != "NO_PHP_EVIDENCE_FOUND_COVERAGE_LIMITED" {
		t.Fatal(r.Summary)
	}
}

func TestHTMLRecommendedStepsBeforeOptionalInvestigation(t *testing.T) {
	r := NewReport("dfir", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php-fpm", Version: "8.3.36", Source: "static", Location: "/usr/sbin/php-fpm"})
	EvaluatePatchPosture(r)
	r.ExploitationAttemptStatus = "SUSPECTED_ATTEMPTS_REVIEW"
	r.InvestigationCoverage = "PARTIAL"
	FinalizeSummary(r)
	html := string(EncodeHTML(r))
	steps := strings.Index(html, "Recommended next steps")
	ir := strings.Index(html, `aria-label="Optional investigation"`)
	if steps < 0 || ir < 0 {
		t.Fatalf("missing sections steps=%d ir=%d", steps, ir)
	}
	if steps > ir {
		t.Fatal("Recommended next steps must appear before optional investigation cards")
	}
	if strings.Contains(html, "FPM_EXIT_SOFTWARE") {
		t.Fatal("primary HTML must not expose FPM_EXIT_SOFTWARE jargon")
	}
}
