package audit

// ReviewSummary is an evidence-qualified triage summary, not a clearance.
// It cannot establish active runtime state, internet exposure or prior compromise.
// HTML rendering maps these identifiers to human-readable labels.
type ReviewSummary struct {
	PHPDiscovery              string   `json:"php_discovery"`
	PatchReview               string   `json:"patch_review"`
	CompromiseReview          string   `json:"compromise_review"` // legacy signed-IOC rollup
	ExploitationAttemptReview string   `json:"exploitation_attempt_review,omitempty"`
	PossibleCompromiseReview  string   `json:"possible_compromise_review,omitempty"`
	InvestigationCoverageReview string `json:"investigation_coverage_review,omitempty"`
	NextSteps                 []string `json:"next_steps"`
}

// FinalizeSummary must run after host/repository collection, patch assessment,
// IOC matching and optional log collection.
func FinalizeSummary(r *Report) {
	s := ReviewSummary{NextSteps: BuildFocusedNextSteps(r)}
	switch classifyPHPDiscovery(r) {
	case phpDiscAssessable, phpDiscVersionUnknown:
		s.PHPDiscovery = "PHP_RELATED_EVIDENCE_FOUND_RUNTIME_UNVERIFIED"
	case phpDiscDeclaredOnly:
		s.PHPDiscovery = "PHP_DECLARED_ONLY_NOT_CONFIRMED_INSTALLED"
	case phpDiscConfigCandidates:
		s.PHPDiscovery = "PHP_CONFIG_CANDIDATES_ONLY_INSTALLATION_UNCONFIRMED"
	case phpDiscConfigIncomplete:
		s.PHPDiscovery = "PHP_CONFIG_COVERAGE_INCOMPLETE_INSTALLATION_UNCONFIRMED"
	case phpDiscArtifactsOnly:
		s.PHPDiscovery = "PHP_ARTIFACTS_ONLY_INSTALLATION_UNCONFIRMED"
	case phpDiscNoneWithinCoverage:
		s.PHPDiscovery = "NO_PHP_DETECTED_WITHIN_SCAN_COVERAGE"
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
		if NoPHPDetectedWithinScanCoverage(r) {
			s.PatchReview = "NO_PHP_SPECIFIC_REMEDIATION_IDENTIFIED"
		} else {
			s.PatchReview = "PATCH_STATUS_UNDETERMINED"
		}
	}
	switch r.CompromiseStatus {
	case "INDICATORS_MATCHED_REVIEW_REQUIRED":
		s.CompromiseReview = "IOC_MATCHES_INVESTIGATE"
	case "NO_MATCHES_SCOPE_LIMITED":
		s.CompromiseReview = "NO_IOC_MATCHES_LIMITED_COVERAGE_NOT_CLEARED"
	default:
		s.CompromiseReview = "NOT_ASSESSED_NO_VALIDATED_CVE_DETECTION"
	}
	switch r.ExploitationAttemptStatus {
	case "SUSPECTED_ATTEMPTS_REVIEW":
		s.ExploitationAttemptReview = "SUSPECTED_ATTEMPTS_REVIEW_REQUIRED"
	case "NO_MATCHES_IN_SCOPE":
		s.ExploitationAttemptReview = "NO_ATTEMPT_MATCHES_IN_SCOPE_NOT_CLEARED"
	default:
		s.ExploitationAttemptReview = "EXPLOITATION_ATTEMPTS_NOT_ASSESSED"
	}
	switch r.PossibleCompromiseStatus {
	case "POSSIBLE_COMPROMISE_REVIEW":
		s.PossibleCompromiseReview = "POSSIBLE_COMPROMISE_REVIEW_REQUIRED"
	case "NO_MATCHES_IN_SCOPE":
		s.PossibleCompromiseReview = "NO_COMPROMISE_MATCHES_IN_SCOPE_NOT_CLEARED"
	default:
		s.PossibleCompromiseReview = "POSSIBLE_COMPROMISE_NOT_ASSESSED"
	}
	switch r.InvestigationCoverage {
	case "NOT_REQUESTED":
		s.InvestigationCoverageReview = "INVESTIGATION_NOT_REQUESTED"
	case "INCOMPLETE":
		s.InvestigationCoverageReview = "INVESTIGATION_COVERAGE_INCOMPLETE"
	case "PARTIAL_TIMESTAMP_UNCERTAIN":
		s.InvestigationCoverageReview = "INVESTIGATION_COVERAGE_PARTIAL_TIMESTAMP_UNCERTAIN"
	case "ASSESSED_SCOPE_LIMITED":
		s.InvestigationCoverageReview = "INVESTIGATION_ASSESSED_SCOPE_LIMITED_CONTINUITY_UNPROVEN"
	default:
		s.InvestigationCoverageReview = "INVESTIGATION_COVERAGE_UNDETERMINED"
	}
	r.Summary = s
}
