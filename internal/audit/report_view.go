package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// InstallGroup is a user-facing roll-up of related PHP patch evidence.
type InstallGroup struct {
	Key             string
	Label           string
	Version         string
	MinimumFixed    string
	Status          string
	StatusLabel     string
	Priority        string
	Assessments     []PatchAssessment
	RelatedEvidence []Evidence
}

// HumanVulnerabilityLabel returns an administrator-facing patch-exposure summary.
func HumanVulnerabilityLabel(status string) string { return humanVulnerability(status) }

// HumanVulnerabilityLabelFor returns the patch-exposure label using discovery context
// (e.g. no-PHP within coverage → no PHP-specific assessment) without changing machine status codes.
func HumanVulnerabilityLabelFor(r *Report) string {
	if r == nil {
		return humanVulnerability("")
	}
	if NoPHPDetectedWithinScanCoverage(r) {
		return "No PHP-specific patch assessment"
	}
	return humanVulnerability(r.VulnerabilityStatus)
}

// HumanPatchStatusLabel returns an administrator-facing per-assessment status.
func HumanPatchStatusLabel(status string) string { return humanPatchStatus(status) }

// HumanCompromiseLabel returns an administrator-facing signed-IOC rollup label.
func HumanCompromiseLabel(status string) string { return humanCompromise(status) }

// HumanPHPDetected returns the discovery label and distinct observed versions.
func HumanPHPDetected(r *Report) (label string, versions []string) { return humanPHPDetected(r) }

// HumanRuntime returns serving-runtime label and detail (never claims verified HTTP SAPI from inventory alone).
func HumanRuntime(r *Report) (label, detail string) { return humanRuntime(r) }

// HumanAdvisoryStatusLabel returns an administrator-facing CVE-2026-115560 status.
func HumanAdvisoryStatusLabel(status string) string {
	switch status {
	case "MANUAL_VERIFICATION_REQUIRED":
		return "Manual verification required"
	case "MITIGATION_CONFIGURED_NOT_RUNTIME_VERIFIED":
		return "Mitigation configured (runtime not verified)"
	case "NO_RISKY_INITIAL_HANDLER_OBSERVED":
		return "No risky initial serialize_handler observed"
	case "UNDETERMINED":
		return "Undetermined — more configuration evidence needed"
	default:
		if status == "" {
			return "Undetermined"
		}
		return status
	}
}

// OfficialFixThresholdsSummary lists embedded upstream fix thresholds for display.
func OfficialFixThresholdsSummary() string {
	return "8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (upstream; vendor backports require separate verification)"
}

// PHPLifecycleNote returns a short lifecycle note for a major.minor branch (informational only).
func PHPLifecycleNote(version string) string {
	v := strings.TrimSpace(version)
	match := cleanPHPVersion.FindStringSubmatch(v)
	if match == nil {
		return ""
	}
	branch := match[1] + "." + match[2]
	switch branch {
	case "8.5":
		return "PHP 8.5: active support until 31 Dec 2027; security until 31 Dec 2029 (php.net)"
	case "8.4":
		return "PHP 8.4: active support until 31 Dec 2026; security until 31 Dec 2028 (php.net)"
	case "8.3":
		return "PHP 8.3: security-only until 31 Dec 2027 (php.net)"
	case "8.2":
		return "PHP 8.2: security-only until 31 Dec 2026 (php.net) — plan upgrade"
	default:
		maj, _ := strconv.Atoi(match[1])
		min, _ := strconv.Atoi(match[2])
		if maj < 8 || (maj == 8 && min <= 1) {
			return "PHP " + branch + ": end of upstream life — upgrade or verify vendor LTS backports"
		}
		return "PHP " + branch + ": confirm support status on php.net/supported-versions.php"
	}
}

func humanPatchStatus(status string) string {
	switch status {
	case "BELOW_UPSTREAM_FIX":
		return "Update review required"
	case "AT_OR_ABOVE_UPSTREAM_FIX":
		return "At or above upstream fix (active runtime unverified)"
	case "LEGACY_VENDOR_VERIFICATION_REQUIRED":
		return "Legacy PHP — upgrade or verify vendor backport"
	case "UNDETERMINED_VERSION", "PRERELEASE_NOT_APPROVED", "BRANCH_NOT_COVERED":
		return "Inconclusive"
	default:
		if status == "" {
			return "Inconclusive"
		}
		return status
	}
}

func humanVulnerability(status string) string {
	switch status {
	case "BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED", "LEGACY_PHP_VENDOR_PATCH_VERIFICATION_REQUIRED", "MULTIPLE_RUNTIMES_MIXED_PATCH_LEVELS_REVIEW_REQUIRED":
		return "Update review required"
	case "INSTALL_EVIDENCE_VERSION_CONFLICT_REVIEW_REQUIRED":
		return "Conflicting version evidence — review required"
	case "REPOSITORY_DECLARATION_BELOW_FIX_DEPLOYMENT_UNKNOWN":
		return "Repository declares below-threshold PHP — verify deployment"
	case "UPSTREAM_FIX_LEVEL_OBSERVED_ACTIVE_RUNTIME_UNVERIFIED":
		return "No below-threshold versions observed (active runtime unverified)"
	case "NO_COMPARABLE_PHP_VERSION_FOUND_INVENTORY_INCOMPLETE", "INDETERMINATE_REVIEW_REQUIRED", "NOT_VERIFIED":
		return "Inconclusive"
	default:
		if status == "" {
			return "Inconclusive"
		}
		return "Inconclusive"
	}
}

func humanCompromise(status string) string {
	switch status {
	case "INDICATORS_MATCHED_REVIEW_REQUIRED":
		return "Indicators detected — investigation required"
	case "NO_MATCHES_SCOPE_LIMITED":
		return "No matches within assessed scope (not a clearance)"
	case "NOT_ASSESSED":
		return "Not assessed"
	default:
		return "Inconclusive"
	}
}

func humanPHPDetected(r *Report) (label string, versions []string) {
	confirmedVers := map[string]struct{}{}
	declaredVers := map[string]struct{}{}
	for _, e := range r.Evidence {
		switch e.Type {
		case "installed_package":
			if e.Version == "" || e.Interpretation == "PACKAGE_METADATA_ONLY_NOT_PHP_RUNTIME_VERSION" {
				continue
			}
			if e.Version != "" {
				confirmedVers[e.Version] = struct{}{}
			}
		case "binary_path", "binary_static_version", "binary_path_inferred_version", "iis_php_handler_config", "apache_php_handler_config", "apache_php_module_config", "operator_reported_web_runtime":
			if e.Version != "" {
				confirmedVers[e.Version] = struct{}{}
			}
		case "repository_declaration":
			if e.Version != "" {
				declaredVers[e.Version] = struct{}{}
			}
		}
	}
	collect := func(m map[string]struct{}) []string {
		out := make([]string, 0, len(m))
		for v := range m {
			out = append(out, v)
		}
		sort.Strings(out)
		return out
	}
	switch classifyPHPDiscovery(r) {
	case phpDiscAssessable:
		return "Yes", collect(confirmedVers)
	case phpDiscVersionUnknown:
		return "Yes (exact versions limited)", collect(confirmedVers)
	case phpDiscDeclaredOnly:
		return "Declared only (not confirmed installed)", collect(declaredVers)
	case phpDiscConfigCandidates:
		return "PHP configuration candidates only (installation unconfirmed)", nil
	case phpDiscConfigIncomplete:
		return "PHP configuration coverage incomplete (candidates not inspected)", nil
	case phpDiscArtifactsOnly:
		return "Possible PHP-related artifacts only", nil
	case phpDiscNoneWithinCoverage:
		return "No PHP detected within scan coverage", nil
	default:
		return "Unable to determine — inventory incomplete", nil
	}
}

func humanRuntime(r *Report) (label, detail string) {
	switch classifyPHPDiscovery(r) {
	case phpDiscNoneWithinCoverage:
		return "Not applicable", "No PHP installation was detected within applicable inventory coverage, so no HTTP-serving PHP runtime was identified. This is not proof the host has no PHP elsewhere."
	case phpDiscNoneIncomplete:
		return "Not verified", "Relevant PHP inventory was incomplete; the scan could not determine whether a PHP web runtime is present."
	}
	switch r.EffectiveWebRuntime {
	case "OPERATOR_REPORTED_NOT_ATTESTED":
		return "Candidates identified", "Operator-reported web runtime recorded; not independently verified."
	case "NOT_VERIFIED", "":
		hasCandidate := false
		for _, e := range r.Evidence {
			if e.Type == "running_process" && e.Name != "w3wp.exe" {
				hasCandidate = true
				break
			}
			if e.Type == "iis_php_handler_config" || e.Type == "apache_php_handler_config" || e.Type == "apache_php_module_config" ||
				e.Type == "binary_static_version" || e.Type == "binary_path_inferred_version" || e.Type == "binary_path" {
				hasCandidate = true
				break
			}
		}
		if hasCandidate {
			return "Candidates identified", "Installed packages, binaries, or processes were observed; the HTTP-serving PHP runtime is not verified."
		}
		return "Not verified", "This scan could not identify the PHP runtime that serves HTTP traffic."
	default:
		return "Not verified", r.EffectiveWebRuntime
	}
}

func overallPriority(r *Report) string {
	switch r.CompromiseStatus {
	case "INDICATORS_MATCHED_REVIEW_REQUIRED":
		return "Critical — indicator matches require investigation"
	}
	if r.PossibleCompromiseStatus == "POSSIBLE_COMPROMISE_REVIEW" {
		if possibleCompromiseIsWebrootMetadataOnly(r) {
			return "Elevated — low-confidence webroot metadata leads require review (not EDR-strength evidence)"
		}
		return "High — possible compromise leads require review"
	}
	if r.ExploitationAttemptStatus == "SUSPECTED_ATTEMPTS_REVIEW" {
		return "High — suspected exploitation attempts require review"
	}
	switch r.VulnerabilityStatus {
	case "BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED", "LEGACY_PHP_VENDOR_PATCH_VERIFICATION_REQUIRED", "MULTIPLE_RUNTIMES_MIXED_PATCH_LEVELS_REVIEW_REQUIRED":
		return "High — update review required"
	case "INSTALL_EVIDENCE_VERSION_CONFLICT_REVIEW_REQUIRED", "REPOSITORY_DECLARATION_BELOW_FIX_DEPLOYMENT_UNKNOWN":
		return "Elevated — verification required"
	case "UPSTREAM_FIX_LEVEL_OBSERVED_ACTIVE_RUNTIME_UNVERIFIED":
		return "Moderate — confirm active runtime"
	default:
		switch classifyPHPDiscovery(r) {
		case phpDiscNoneWithinCoverage:
			return "Informational — no PHP detected within scan coverage"
		case phpDiscVersionUnknown:
			return "Review required — PHP version unknown"
		case phpDiscNoneIncomplete:
			return "Review required — inventory incomplete"
		default:
			return "Review required — inventory incomplete"
		}
	}
}

var phpBranchToken = regexp.MustCompile(`(?i)(?:php-fpm|php-cgi|lsphp|php)(\d)\.(\d)`)

func groupKeyForAssessment(a PatchAssessment) string {
	// Prefer established install/runtime correlation. Distinct binary installs that
	// share a PHP version must remain separate (install:binary:<path>).
	if strings.HasPrefix(a.InstallKey, "install:binary-dir:") || strings.HasPrefix(a.InstallKey, "install:binary:") || strings.HasPrefix(a.InstallKey, "install:operator:") {
		return a.InstallKey
	}
	if a.EvidenceType == "repository_declaration" {
		return "repo:" + a.Location + ":" + a.Component + ":" + a.ObservedVersion
	}
	// Distro package siblings (phpX.Y-fpm/cli/common) without a binary InstallKey
	// share one host install identity by branch+version — not by raw version alone
	// across unrelated evidence types.
	if a.EvidenceType == "installed_package" {
		if branch := debianPHPBranch(a.Component); branch != "" && a.ObservedVersion != "" {
			return "install:distro:" + branch + ":" + a.ObservedVersion
		}
	}
	if a.InstallKey != "" {
		return a.InstallKey
	}
	if a.ObservedVersion != "" {
		return "install:unique:" + a.EvidenceType + ":" + a.Location + ":" + a.Component + ":" + a.ObservedVersion
	}
	return "install:unique:" + a.EvidenceType + ":" + a.Component + ":" + a.Location
}

func phpBranchFromToken(s string) string {
	m := phpBranchToken.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2]
}

// GroupInstallations rolls related patch assessments into install-centric groups.
// All assessments remain present inside groups; evidence is never dropped.
func GroupInstallations(r *Report) []InstallGroup {
	order := []string{}
	groups := map[string]*InstallGroup{}
	for _, a := range r.PatchAssessments {
		key := groupKeyForAssessment(a)
		g, ok := groups[key]
		if !ok {
			g = &InstallGroup{
				Key:          key,
				Version:      a.ObservedVersion,
				MinimumFixed: a.MinimumFixed,
				Status:       a.Status,
				Priority:     a.Priority,
			}
			groups[key] = g
			order = append(order, key)
		}
		g.Assessments = append(g.Assessments, a)
		// Prefer worst status within the group.
		g.Status = worseStatus(g.Status, a.Status)
		g.StatusLabel = humanPatchStatus(g.Status)
		if a.Priority == "CRITICAL" {
			g.Priority = "CRITICAL"
		}
		if g.MinimumFixed == "" {
			g.MinimumFixed = a.MinimumFixed
		}
		if g.Version == "" {
			g.Version = a.ObservedVersion
		}
	}
	for _, g := range groups {
		g.Label = installGroupLabel(g)
		g.RelatedEvidence = relatedEvidenceForGroup(r, g)
	}
	out := make([]InstallGroup, 0, len(order))
	for _, key := range order {
		out = append(out, *groups[key])
	}
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := priorityRank(out[i].Priority), priorityRank(out[j].Priority)
		if pi != pj {
			return pi < pj
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func installGroupLabel(g *InstallGroup) string {
	if (strings.HasPrefix(g.Key, "install:binary-dir:") || strings.HasPrefix(g.Key, "install:binary:")) && len(g.Assessments) > 0 {
		loc := g.Assessments[0].Location
		inferred := false
		// Prefer a versioned verified binary path; otherwise any binary path.
		for _, a := range g.Assessments {
			if a.EvidenceType == "binary_static_version" && a.Location != "" {
				loc = a.Location
				inferred = false
				break
			}
			if a.EvidenceType == "binary_path_inferred_version" && a.Location != "" {
				loc = a.Location
				inferred = true
			}
		}
		if g.Version != "" && loc != "" && !strings.Contains(loc, "dpkg/status") && !strings.Contains(loc, "apk/db") {
			label := "PHP " + g.Version + " @ " + loc
			if inferred {
				label += " (path-inferred)"
			}
			return label
		}
	}
	if g.Version != "" {
		return "PHP " + g.Version
	}
	if len(g.Assessments) > 0 && g.Assessments[0].Component != "" {
		return g.Assessments[0].Component
	}
	return "PHP installation"
}

func priorityRank(p string) int {
	switch p {
	case "CRITICAL":
		return 0
	case "REVIEW":
		return 1
	case "VERIFY":
		return 2
	default:
		return 3
	}
}

func worseStatus(a, b string) string {
	rank := func(s string) int {
		switch s {
		case "BELOW_UPSTREAM_FIX", "LEGACY_VENDOR_VERIFICATION_REQUIRED":
			return 0
		case "UNDETERMINED_VERSION", "PRERELEASE_NOT_APPROVED", "BRANCH_NOT_COVERED":
			return 1
		case "AT_OR_ABOVE_UPSTREAM_FIX":
			return 2
		default:
			return 3
		}
	}
	if rank(b) < rank(a) {
		return b
	}
	return a
}

func relatedEvidenceForGroup(r *Report, g *InstallGroup) []Evidence {
	wantNames := map[string]struct{}{}
	wantLocs := map[string]struct{}{}
	branches := map[string]struct{}{}
	binaryScoped := strings.HasPrefix(g.Key, "install:binary-dir:") || strings.HasPrefix(g.Key, "install:binary:")
	for _, a := range g.Assessments {
		wantNames[strings.ToLower(a.Component)] = struct{}{}
		if a.Location != "" {
			wantLocs[normalizeInstallPath(a.Location)] = struct{}{}
		}
		if br := debianPHPBranch(a.Component); br != "" {
			branches[br] = struct{}{}
		}
		if br := phpBranchFromToken(a.Location); br != "" {
			branches[br] = struct{}{}
		}
	}
	var out []Evidence
	seen := map[string]bool{}
	add := func(e Evidence) {
		key := e.Type + "\x00" + e.Location + "\x00" + e.Name + "\x00" + e.Version
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, e)
	}
	matchedHandlerSites := map[string]struct{}{}
	matchedDocRoots := map[string]struct{}{}
	for _, e := range r.Evidence {
		loc := normalizeInstallPath(e.Location)
		low := strings.ToLower(e.Name)
		sharedInventoryDB := loc == normalizeInstallPath("/var/lib/dpkg/status") || loc == normalizeInstallPath("/lib/apk/db/installed")
		if _, ok := wantLocs[loc]; ok && loc != "." && loc != "" && !sharedInventoryDB {
			add(e)
			continue
		}
		if e.Type == "iis_php_handler_config" && iisHandlerRelatedToGroup(e, g) {
			add(e)
			if site := iisDetailField(e.Detail, "site"); site != "" {
				matchedHandlerSites[iisSiteRootName(site)] = struct{}{}
			}
			continue
		}
		if (e.Type == "apache_php_handler_config" || e.Type == "apache_php_module_config") && apacheHandlerRelatedToGroup(e, g) {
			add(e)
			if site := iisDetailField(e.Detail, "site"); site != "" {
				matchedHandlerSites[iisSiteRootName(site)] = struct{}{}
			}
			if doc := iisDetailField(e.Detail, "document_root"); doc != "" {
				matchedDocRoots[normalizeInstallPath(doc)] = struct{}{}
			}
			continue
		}
		if binaryScoped {
			// Do not attach other installs' same-version packages to a binary path group.
			continue
		}
		if _, ok := wantNames[low]; ok {
			add(e)
			continue
		}
		if br := debianPHPBranch(e.Name); br != "" {
			if _, ok := branches[br]; ok {
				add(e)
			}
		}
	}
	// Attach site/app/vdir or Apache vhost rows that share a site name or DocumentRoot
	// with a handler already correlated to this PHP install (where supported).
	for _, e := range r.Evidence {
		switch e.Type {
		case "iis_site_config":
			if _, ok := matchedHandlerSites[iisSiteRootName(e.Name)]; ok {
				add(e)
			}
		case "apache_vhost_config":
			if _, ok := matchedHandlerSites[iisSiteRootName(e.Name)]; ok {
				add(e)
				continue
			}
			if _, ok := matchedDocRoots[normalizeInstallPath(e.Location)]; ok {
				add(e)
			}
		case "php_ini_candidate", "configuration_observation":
			if related := iisDetailField(e.Detail, "related_binary"); related != "" {
				relKey := normalizeInstallPath(related)
				for _, a := range g.Assessments {
					if normalizeInstallPath(a.Location) == relKey || normalizeInstallPath(parentDirAnyOS(a.Location)) == normalizeInstallPath(parentDirAnyOS(related)) {
						add(e)
						break
					}
				}
			}
		}
	}
	return out
}

func apacheHandlerRelatedToGroup(e Evidence, g *InstallGroup) bool {
	if g == nil {
		return false
	}
	exe := HandlerExecutableFromDetail(e.Detail)
	if exe == "" {
		exe = iisDetailField(e.Detail, "handler_exe")
	}
	exeKey := normalizeInstallPath(exe)
	exeDir := normalizeInstallPath(parentDirAnyOS(exe))
	backend := strings.ToLower(iisDetailField(e.Detail, "backend"))
	for _, a := range g.Assessments {
		aLoc := normalizeInstallPath(a.Location)
		aDir := normalizeInstallPath(parentDirAnyOS(a.Location))
		if exeKey != "" && (exeKey == aLoc || (exeDir != "." && exeDir != "" && exeDir == aDir)) {
			return true
		}
		// Correlate versioned FPM socket/path hints (e.g. php8.4-fpm.sock) to the install branch.
		if backend != "" {
			if branch := phpBranchFromVersion(a.ObservedVersion); branch != "" && strings.Contains(backend, "php"+branch) {
				return true
			}
		}
	}
	return false
}

func phpBranchFromVersion(ver string) string {
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

func iisDetailField(detail, key string) string {
	prefix := key + "="
	for _, part := range strings.Split(detail, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, prefix) {
			return strings.TrimPrefix(part, prefix)
		}
	}
	return ""
}

// iisSiteRootName strips app/vdir suffixes from site labels ("somewebsite/api" → "somewebsite").
func iisSiteRootName(label string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return ""
	}
	if i := strings.IndexAny(label, "/ "); i >= 0 {
		return strings.ToLower(label[:i])
	}
	return strings.ToLower(label)
}

func iisHandlerRelatedToGroup(e Evidence, g *InstallGroup) bool {
	if g == nil {
		return false
	}
	exe := HandlerExecutableFromDetail(e.Detail)
	exeKey := normalizeInstallPath(exe)
	exeDir := normalizeInstallPath(parentDirAnyOS(exe))
	for _, a := range g.Assessments {
		aLoc := normalizeInstallPath(a.Location)
		aDir := normalizeInstallPath(parentDirAnyOS(a.Location))
		if exeKey != "" && (exeKey == aLoc || (exeDir != "." && exeDir != "" && exeDir == aDir)) {
			return true
		}
	}
	return false
}

// BuildFocusedNextSteps returns short, finding-specific actions (not a generic dump).
func BuildFocusedNextSteps(r *Report) []string {
	steps := []string{}
	add := func(s string) {
		for _, existing := range steps {
			if existing == s {
				return
			}
		}
		steps = append(steps, s)
	}

	kind := classifyPHPDiscovery(r)
	switch kind {
	case phpDiscNoneWithinCoverage:
		add("No PHP installation was detected within the applicable scan coverage. No PHP-specific patch remediation was identified. This is not proof that PHP is absent from the host or that the host is safe — custom install paths, containers, and offline images may be outside coverage.")
		add("If PHP may live outside default discovery paths, re-run with authorized --config-root, --deep-root, or --php-ini locations. Review advisory context at " + AdvisoryURL + " only when PHP is confirmed elsewhere.")
	case phpDiscNoneIncomplete:
		gaps := relevantPHPInventoryGaps(r)
		msg := "Relevant PHP inventory sources were unavailable or incomplete; absence of PHP findings is not proof PHP is missing from the host."
		if len(gaps) > 0 {
			msg += " Gaps: " + strings.Join(gaps, "; ") + "."
		}
		add(msg)
		add("Re-run with adequate permissions for failed inventory checks, then reassess. Do not treat this host as cleared for PHP patch status.")
	default:
		groups := GroupInstallations(r)
		below := []string{}
		legacy := []string{}
		for _, g := range groups {
			switch g.Status {
			case "BELOW_UPSTREAM_FIX":
				target := g.MinimumFixed
				if target == "" {
					target = "the official fixed release for this branch"
				}
				below = append(below, fmt.Sprintf("%s (update toward %s or verify an equivalent vendor security backport)", g.Label, target))
			case "LEGACY_VENDOR_VERIFICATION_REQUIRED":
				legacy = append(legacy, g.Label)
			}
		}
		if len(below) > 0 {
			add("Update or verify vendor backports for: " + strings.Join(below, "; ") + ". Restart PHP-FPM, Apache/mod_php, IIS FastCGI, or other workers that may load these builds, then confirm the serving runtime version.")
		}
		if len(legacy) > 0 {
			add("Plan an upgrade off legacy PHP (" + strings.Join(legacy, ", ") + ") to a supported fixed branch, or obtain documented vendor/LTS patch evidence for both CVEs.")
		}
		if kind == phpDiscVersionUnknown {
			add("PHP-related evidence was observed without a comparable patch version. Inventory the exact active PHP patch versions for production web handlers before assigning vulnerability status.")
		}
		rtLabel, _ := humanRuntime(r)
		if rtLabel != "Verified" && rtLabel != "Not applicable" {
			add("Identify which PHP binary or SAPI actually serves HTTP (FPM pool, Apache module, IIS handler, container entrypoint). Package and CLI versions alone are not sufficient.")
		}
		if iniPath := FirstUncorrelatedPrimaryIni(r); iniPath != "" {
			add("Review uncorrelated php.ini candidate(s) such as " + iniPath + ". Configuration alone does not confirm a PHP install, version, or active web runtime; supply --php-ini, --config-root, or --deep-root for known custom locations if discovery missed them.")
		} else if CountPHPIniSkips(r) > 0 {
			add("Re-run with read access to skipped PHP configuration candidates (see php_ini_skip evidence), or pass --php-ini / --config-root / --deep-root for known custom paths. Skipped files were not inspected and secrets were not reported.")
		}
	}

	switch r.ExploitationAttemptStatus {
	case "SUSPECTED_ATTEMPTS_REVIEW":
		add("Review suspected exploitation-attempt leads (error-log patterns, long request-target anomalies, temporal correlations). A single memory error, crash, or long request-target is not proof of successful exploitation; correlation is not causality.")
	case "NO_MATCHES_IN_SCOPE":
		add("No exploitation-attempt patterns matched in the assessed log scope — not a clearance. Expand retention from at least 2026-10-17 and supply offline EDR/process telemetry when available.")
	}
	switch r.PossibleCompromiseStatus {
	case "POSSIBLE_COMPROMISE_REVIEW":
		add("Review possible compromise leads (process relationships and/or webroot filesystem heuristics) against host baselines. Normal apps may launch shells; CMS uploads can look suspicious; validate before concluding. Never treat as confirmed compromise or webshell.")
	case "NO_MATCHES_IN_SCOPE":
		add("No process or webroot compromise patterns matched in assessed scope — not a clearance. Expand retention and correlate with access/error evidence.")
	case "NOT_ASSESSED":
		if r.InvestigationCoverage != "NOT_REQUESTED" {
			add("Possible host compromise was not assessed (offline process/EDR telemetry and/or usable webroot investigation missing). Do not equate patched or no attempt matches with an uncompromised host.")
		}
	}
	switch r.CompromiseStatus {
	case "INDICATORS_MATCHED_REVIEW_REQUIRED":
		add("Preserve matched files and logs, and escalate for incident response validation. Indicator matches are not automatic proof of successful exploitation.")
	case "NO_MATCHES_SCOPE_LIMITED":
		add("Treat the host as not cleared for compromise: expand log/EDR review for the pre-patch window. Absence of IOC matches is not proof of safety.")
	default:
		if r.InvestigationCoverage == "NOT_REQUESTED" && kind != phpDiscNoneWithinCoverage && kind != phpDiscNoneIncomplete {
			add("Compromise investigation was not requested. Use --access-log / --error-log / --process-telemetry / --webroot for evidence-based review; missing inputs leave statuses NOT_ASSESSED, not negative.")
		}
	}
	if ScanIncomplete(r) {
		add("Re-run with adequate permissions for any incomplete coverage items (packages, configs, logs, or webroot) listed in the coverage section.")
	}
	if kind != phpDiscNoneWithinCoverage && kind != phpDiscNoneIncomplete {
		add("Validate remediation by checking the active web handler version after restart, and review official guidance at " + AdvisoryURL + ".")
	}
	if len(steps) > 6 {
		steps = steps[:6]
	}
	return steps
}
