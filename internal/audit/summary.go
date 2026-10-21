package audit

// ReviewSummary is an evidence-qualified triage summary, not a clearance.
// It cannot establish active runtime state, internet exposure or prior compromise.
type ReviewSummary struct {
	PHPDiscovery     string   `json:"php_discovery"`
	PatchReview      string   `json:"patch_review"`
	CompromiseReview string   `json:"compromise_review"`
	NextSteps        []string `json:"next_steps"`
}

// FinalizeSummary must run after host/repository collection, patch assessment,
// IOC matching and optional log collection.
func FinalizeSummary(r *Report) {
	s := ReviewSummary{NextSteps: []string{}}
	detected := false
	for _, e := range r.Evidence {
		switch e.Type {
		case "binary_path", "binary_static_version", "installed_package", "repository_declaration", "operator_reported_web_runtime", "iis_php_handler_config", "configuration_observation", "php_webroot_filename", "docker_container_metadata":
			// Docker metadata without PHP evidence does not establish PHP presence.
			if e.Type != "docker_container_metadata" {
				detected = true
			}
		case "running_process":
			// Generic IIS w3wp.exe is not sufficient evidence of PHP.
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
		s.NextSteps = append(s.NextSteps, "Urgently identify the web-serving runtime for each below-threshold or legacy version, install the official fix or verify a vendor backport for both CVEs, restart every worker, then verify the serving runtime.")
	case "INSTALL_EVIDENCE_VERSION_CONFLICT_REVIEW_REQUIRED":
		s.PatchReview = "CONFLICTING_VERSION_EVIDENCE_REVIEW"
		s.NextSteps = append(s.NextSteps, "Correlated evidence for the same PHP installation reports different versions. Reconcile package records, binary paths, and deployment state before treating any observation as authoritative.")
	case "REPOSITORY_DECLARATION_BELOW_FIX_DEPLOYMENT_UNKNOWN":
		s.PatchReview = "CHECK_DEPLOYED_IMAGE_AND_VERSION"
		s.NextSteps = append(s.NextSteps, "A repository declares an older PHP image/version. Check the deployed image digest and running web runtime before assigning production exposure.")
	case "UPSTREAM_FIX_LEVEL_OBSERVED_ACTIVE_RUNTIME_UNVERIFIED":
		s.PatchReview = "UPSTREAM_THRESHOLD_OBSERVED_VERIFY_ACTIVE_RUNTIME"
		s.NextSteps = append(s.NextSteps, "Observed upstream patch levels meet the thresholds, but confirm the active HTTP handler and every container, pool and worker; an installed package is not proof.")
	default:
		s.PatchReview = "PATCH_STATUS_UNDETERMINED"
		s.NextSteps = append(s.NextSteps, "Determine the exact active PHP web-runtime version and distribution package/build; compare it to the official fixes or a documented vendor backport.")
	}
	switch r.CompromiseStatus {
	case "INDICATORS_MATCHED_REVIEW_REQUIRED":
		s.CompromiseReview = "IOC_MATCHES_INVESTIGATE"
		s.NextSteps = append(s.NextSteps, "Preserve matched files/logs and escalate to incident response for validation; a match alone is not proof of successful exploitation.")
	case "NO_MATCHES_SCOPE_LIMITED":
		s.CompromiseReview = "NO_IOC_MATCHES_LIMITED_COVERAGE_NOT_CLEARED"
		s.NextSteps = append(s.NextSteps, "Review log and EDR coverage, including the pre-patch period. No matched indicators cannot exclude exploitation.")
	default:
		s.CompromiseReview = "NOT_ASSESSED_NO_VALIDATED_CVE_DETECTION"
		s.NextSteps = append(s.NextSteps, "Compromise status cannot be determined: no validated PHP2Shell-specific indicator set is bundled. Preserve historical HTTP/error logs and EDR telemetry for investigation.")
	}
	s.NextSteps = append(s.NextSteps, "Read the Coverage table: missing permissions, unsupported package managers and unexamined logs limit every conclusion.")
	r.Summary = s
}
