package audit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// These thresholds originate from the PHP security advisory dated 2026-10-21.
// A package-version comparison is NOT verification of a running HTTP SAPI and
// it cannot rule out distribution-maintained source backports.
const AdvisoryURL = "https://www.php.net/archive/2026.php#2026-10-21-1"
const AdvisoryDate = "2026-10-21"

var officialFixes = map[string]int{"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
var cleanPHPVersion = regexp.MustCompile(`(?i)^\s*(\d+)\.(\d+)(?:\.(\d+))?(?:[-+][a-z0-9._+:-]+)?\s*$`)
var preRelease = regexp.MustCompile(`(?i)(?:rc\d*|alpha\d*|beta\d*|dev|snapshot)`)

type PatchAssessment struct {
	Component       string `json:"component"`
	ObservedVersion string `json:"observed_version"`
	EvidenceType    string `json:"evidence_type"`
	Source          string `json:"source"`
	Location        string `json:"location,omitempty"`
	RuntimeKey      string `json:"runtime_key,omitempty"`
	InstallKey      string `json:"install_key,omitempty"`
	Status          string `json:"status"`
	MinimumFixed    string `json:"minimum_fixed,omitempty"`
	Priority        string `json:"priority"`
	RequiredAction  string `json:"required_action"`
	Qualification   string `json:"qualification"`
	Confidence      string `json:"confidence,omitempty"` // HIGH | MEDIUM | LOW — version observation confidence, not exploit certainty
}

type VersionDecision struct{ Status, MinimumFixed, Priority, Action, Qualification string }

// CheckPHPVersion is deliberately conservative: a missing patch number, a
// version constraint, an RC, or an EOL stream must never become "patched".
func CheckPHPVersion(input string) VersionDecision {
	v := strings.TrimSpace(input)
	if v == "" || strings.ContainsAny(v, "<>^~*|, ") {
		return VersionDecision{"UNDETERMINED_VERSION", "", "REVIEW", "Determine the exact deployed PHP patch version; a PHP requirement or a major.minor line is insufficient.", "Not an exact installed version."}
	}
	match := cleanPHPVersion.FindStringSubmatch(v)
	if match == nil {
		return VersionDecision{"UNDETERMINED_VERSION", "", "REVIEW", "Determine the exact deployed PHP patch version from trusted deployment evidence.", "Version string not safely comparable."}
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	if match[3] == "" {
		return VersionDecision{"UNDETERMINED_VERSION", "", "REVIEW", "Find the exact deployed PHP patch version for this branch.", "Only major.minor is known."}
	}
	patch, _ := strconv.Atoi(match[3])
	if preRelease.MatchString(v) {
		return VersionDecision{"PRERELEASE_NOT_APPROVED", "", "REVIEW", "Do not use a prerelease build in production; install a supported patched stable release.", "Release candidates and pre-releases are not approved by this advisory comparison."}
	}
	branch := fmt.Sprintf("%d.%d", major, minor)
	if min, ok := officialFixes[branch]; ok {
		target := fmt.Sprintf("%s.%d", branch, min)
		if patch < min {
			return VersionDecision{"BELOW_UPSTREAM_FIX", target, "CRITICAL", "Update the PHP web-serving runtime to " + target + " or later on this supported branch (or verify an equivalent vendor security backport), restart every PHP worker and verify the serving runtime.", "Version below the upstream fix; vendor backports and actual deployment remain unverified."}
		}
		return VersionDecision{"AT_OR_ABOVE_UPSTREAM_FIX", target, "VERIFY", "Verify this version is the one actively handling HTTP requests; restart workers after deployment and check all pools, hosts, and containers.", "An observed version at or above the upstream fix is not proof of a patched running SAPI or past non-compromise."}
	}
	if major < 8 || (major == 8 && minor <= 1) {
		return VersionDecision{"LEGACY_VENDOR_VERIFICATION_REQUIRED", "", "CRITICAL", "Upgrade the web-serving PHP runtime to a currently supported fixed branch. If using a supported LTS vendor or official minimal source backport, obtain and verify exact patch evidence; do not assume a PHP 8.1-or-earlier build is fixed.", "Upstream PHP 8.1 and earlier receive no normal security releases. Backports are separate and must be evidenced."}
	}
	return VersionDecision{"BRANCH_NOT_COVERED", "", "REVIEW", "Verify this PHP branch against its own official security advisory and stable release status; do not assume it is protected.", "Not one of the supported stable branches listed in the 2026-10-21 advisory."}
}

// EvaluatePatchPosture classifies observations without upgrading the claim from
// package inventory or source declaration to active web-runtime verification.
func EvaluatePatchPosture(r *Report) {
	ReconcileBinaryInstallAliases(r)
	r.PatchAssessments = []PatchAssessment{}
	r.AdditionalAdvisories = nil
	// Official patch actions take precedence over generic preview guidance.
	r.RecommendedActions = []string{}
	belowHost, belowRepo, legacy, observed := 0, 0, 0, 0
	seen := map[string]bool{}
	for _, e := range r.Evidence {
		switch e.Type {
		case "installed_package", "repository_declaration", "operator_reported_web_runtime", "binary_static_version", "binary_path_inferred_version":
		default:
			continue
		}
		if e.Version == "" {
			continue
		}
		// Extension packages share the install version; keep them in evidence but avoid
		// duplicating identical vulnerability rows for every module package.
		if e.Type == "installed_package" && IsPHPExtensionPackage(e.Name) {
			continue
		}
		key := e.Type + "\x00" + e.Location + "\x00" + e.Name + "\x00" + e.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		d := CheckPHPVersion(e.Version)
		confidence := "HIGH"
		scope := "Static inventory only; not attestation of the serving HTTP runtime."
		if e.Type == "repository_declaration" {
			scope = "Source declaration only; may not match production."
			confidence = "MEDIUM"
		}
		if e.Type == "operator_reported_web_runtime" {
			scope = "Reported by an operator; not independently verified by this tool."
			confidence = "MEDIUM"
		}
		if e.Type == "installed_package" {
			scope += " A vendor may have backported a fix without changing the upstream version string."
			confidence = "MEDIUM"
		}
		if e.Type == "binary_static_version" {
			scope = "Verified from passive binary metadata (embedded string and/or PE resource); not proof the binary serves HTTP or is the active runtime."
			confidence = "HIGH"
			if strings.Contains(e.Detail, "inspect_coverage=partial") {
				confidence = "MEDIUM"
			}
		}
		if e.Type == "binary_path_inferred_version" {
			scope = "PATH-INFERRED version from installer directory layout (and/or corroborated alias). Not verified from binary metadata; not proof of the active HTTP runtime; CLI path must not be treated as the web SAPI."
			confidence = "MEDIUM"
		}
		r.PatchAssessments = append(r.PatchAssessments, PatchAssessment{
			Component: e.Name, ObservedVersion: e.Version, EvidenceType: e.Type, Source: e.Source, Location: e.Location,
			Status: d.Status, MinimumFixed: d.MinimumFixed, Priority: d.Priority, RequiredAction: d.Action,
			Qualification: scope + " " + d.Qualification, Confidence: confidence,
		})
		observed++
		switch d.Status {
		case "BELOW_UPSTREAM_FIX":
			if e.Type == "repository_declaration" {
				belowRepo++
			} else {
				belowHost++
			}
		case "LEGACY_VENDOR_VERIFICATION_REQUIRED":
			if e.Type != "repository_declaration" {
				legacy++
			}
		}
	}
	r.PatchAssessments = assignInstallKeysWithAliases(r.PatchAssessments, r.binaryAliasDirs())
	r.VulnerabilityStatus = aggregateHostVulnerability(r.PatchAssessments, belowRepo, observed)
	if belowHost > 0 {
		r.AddAction("URGENT: Observed installed or operator-reported PHP version below the upstream fixes. Patch all relevant running web SAPIs, not only the CLI binary. Confirm vendor backports where applicable.")
	}
	if belowRepo > 0 {
		r.AddAction("Review Dockerfiles, CI and deployment manifests naming versions below the fixes. Verify actual deployed image digest/runtime before assigning vulnerability status.")
	}
	if legacy > 0 {
		r.AddAction("Escalate PHP 8.1 and older for supported-branch upgrade or obtain explicit vendor/LTS patch evidence for both CVEs.")
	}
	if observed == 0 || r.VulnerabilityStatus == "INDETERMINATE_REVIEW_REQUIRED" {
		r.AddAction("Inventory the exact active PHP patch versions for all production web handlers; static package, binary-name and repository observations may miss deployments.")
	}
	r.AddAction("Immediately prioritize internet-reachable mod_php and other web-facing PHP (FPM, CGI, FrankenPHP, LiteSpeed). Determine network reachability separately; this is NOT an external exposure scan.")
	r.AddAction("Apply upstream PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or your vendor's verified equivalent patches. Restart/recycle all PHP workers, pools and services; re-scan and verify the active web-serving SAPI and container images.")
	r.AddAction("If patching must be delayed: consider administratively enforced memory_limit=-1, conservative post_max_size and edge request bounds for CVE-2026-109618; these are incomplete risk reductions and have availability tradeoffs.")
	r.AddAction("For CVE-2026-109619, administratively disable session.upload_progress.enabled and restart all workers; on PHP 8.5, consider fatal_error_backtraces=0 until patched. Neither measure covers every attack path.")
	r.AddAction("Confirm WAF/origin access cannot be bypassed and document time-bounded restrictions if a patch cannot be deployed immediately.")
	r.AddAction("Preserve and review access/error logs and EDR telemetry from before patching; patched servers may already have been compromised. A clean IOC result does not rule out compromise.")
	r.AddAction("See official advisories: https://www.php.net/ and https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w and https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp")
	installs := map[string]struct{}{}
	for _, a := range r.PatchAssessments {
		if a.InstallKey != "" && isHostRuntimeEvidence(a.EvidenceType) {
			installs[a.InstallKey] = struct{}{}
		}
	}
	r.AddCheck("official_php2shell_version_rules", "APPLIED", fmt.Sprintf("Upstream fixes: 8.2.35, 8.3.36, 8.4.27, 8.5.12. Compared %d evidence records across %d correlated install groups; NOT vendor backport or active HTTP runtime verification", observed, len(installs)))
	if r.VulnerabilityStatus == "INSTALL_EVIDENCE_VERSION_CONFLICT_REVIEW_REQUIRED" {
		r.AddAction("Conflicting PHP version evidence was observed for the same correlated installation. Reconcile package metadata, binary paths, and deployment records before assigning patch status.")
	}
	if r.VulnerabilityStatus == "MULTIPLE_RUNTIMES_MIXED_PATCH_LEVELS_REVIEW_REQUIRED" {
		r.AddAction("Multiple distinct PHP installations show different patch levels. Patch every web-serving runtime; one at-threshold install does not protect other handlers.")
	}
	// Secondary informational advisory (CVE-2026-115560) — config observation only; no invented fixed versions.
	EvaluateSessionUploadProgressAdvisory(r)
}
