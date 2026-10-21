package audit

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
	detected := false
	for _, e := range r.Evidence {
		switch e.Type {
		case "binary_path", "binary_static_version", "installed_package", "repository_declaration", "operator_reported_web_runtime", "iis_php_handler_config", "configuration_observation", "php_webroot_filename", "docker_container_metadata":
			if e.Type != "docker_container_metadata" {
				detected = true
			}
		case "running_process":
			if e.Name != "w3wp.exe" {
				detected = true
			}
		}
	}
	if detected {
		s.PHPDiscovery = "PHP_RELATED_EVIDENCE_FOUND_RUNTIME_UNVERIFIED"
	} else {
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
