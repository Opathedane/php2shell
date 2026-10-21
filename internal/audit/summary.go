package audit

import "strings"

// ReviewSummary is an evidence-qualified triage summary, not a clearance.
// It cannot establish active runtime state, internet exposure or prior compromise.
// HTML rendering maps these identifiers to human-readable labels.
type ReviewSummary struct {
	PHPDiscovery     string   `json:"php_discovery"`
	PatchReview      string   `json:"patch_review"`
	CompromiseReview string   `json:"compromise_review"`
	NextSteps        []string `json:"next_steps"`
}

// FinalizeSummary must run after host/repository collection, patch assessment,
// IOC matching and optional log collection.
func FinalizeSummary(r *Report) {
	s := ReviewSummary{NextSteps: BuildFocusedNextSteps(r)}
	label, _ := humanPHPDetected(r)
	switch {
	case strings.HasPrefix(label, "Yes"):
		s.PHPDiscovery = "PHP_RELATED_EVIDENCE_FOUND_RUNTIME_UNVERIFIED"
	case strings.HasPrefix(label, "Declared"):
		s.PHPDiscovery = "PHP_DECLARED_ONLY_NOT_CONFIRMED_INSTALLED"
	case strings.HasPrefix(label, "Possible"):
		s.PHPDiscovery = "PHP_ARTIFACTS_ONLY_INSTALLATION_UNCONFIRMED"
	default:
		s.PHPDiscovery = "NO_PHP_EVIDENCE_FOUND_COVERAGE_LIMITED"
	}
	switch r.VulnerabilityStatus {
	case "BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED", "LEGACY_PHP_VENDOR_PATCH_VERIFICATION_REQUIRED", "MULTIPLE_RUNTIMES_MIXED_PATCH_LEVELS_REVIEW_REQUIRED":
		s.PatchReview = "URGENT_PATCH_OR_VENDOR_BACKPORT_REVIEW"
	case "INSTALL_EVIDENCE_VERSION_CONFLICT_REVIEW_REQUIRED":
		s.PatchReview = "CONFLICTING_VERSION_EVIDENCE_REVIEW"
	case "REPOSITORY_DECLARATION_BELOW_FIX_DEPLOYMENT_UNKNOWN":
		s.PatchReview = "CHECK_DEPLOYED_IMAGE_AND_VERSION"
	case "UPSTREAM_FIX_LEVEL_OBSERVED_ACTIVE_RUNTIME_UNVERIFIED":
		s.PatchReview = "UPSTREAM_THRESHOLD_OBSERVED_VERIFY_ACTIVE_RUNTIME"
	default:
		s.PatchReview = "PATCH_STATUS_UNDETERMINED"
	}
	switch r.CompromiseStatus {
	case "INDICATORS_MATCHED_REVIEW_REQUIRED":
		s.CompromiseReview = "IOC_MATCHES_INVESTIGATE"
	case "NO_MATCHES_SCOPE_LIMITED":
		s.CompromiseReview = "NO_IOC_MATCHES_LIMITED_COVERAGE_NOT_CLEARED"
	default:
		s.CompromiseReview = "NOT_ASSESSED_NO_VALIDATED_CVE_DETECTION"
	}
	r.Summary = s
}
