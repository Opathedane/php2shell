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
	if !strings.Contains(string(EncodeHTML(r)), "What to do next") {
		t.Fatal("summary not in HTML")
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
