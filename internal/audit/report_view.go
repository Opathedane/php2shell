package audit

import (
	"fmt"
	"regexp"
	"sort"
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
	confirmed, declared, artifacts := false, false, false
	for _, e := range r.Evidence {
		switch e.Type {
		case "installed_package":
			if e.Version == "" || e.Interpretation == "PACKAGE_METADATA_ONLY_NOT_PHP_RUNTIME_VERSION" {
				artifacts = true
				continue
			}
			confirmed = true
			confirmedVers[e.Version] = struct{}{}
		case "binary_path", "binary_static_version", "binary_path_inferred_version", "iis_php_handler_config", "apache_php_handler_config", "apache_php_module_config", "operator_reported_web_runtime":
			confirmed = true
			if e.Version != "" {
				confirmedVers[e.Version] = struct{}{}
			}
		case "apache_vhost_config", "apache_remote_php_backend":
			artifacts = true
		case "running_process":
			if e.Name != "w3wp.exe" {
				confirmed = true
			}
		case "repository_declaration":
			declared = true
			if e.Version != "" {
				declaredVers[e.Version] = struct{}{}
			}
		case "configuration_observation", "php_webroot_filename":
			artifacts = true
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
	if confirmed {
		versions = collect(confirmedVers)
		if len(versions) == 0 {
			return "Yes (exact versions limited)", versions
		}
		return "Yes", versions
	}
	if declared {
		versions = collect(declaredVers)
		return "Declared only (not confirmed installed)", versions
	}
	if artifacts {
		return "Possible PHP-related artifacts only", nil
	}
	return "Unable to determine", nil
}

func humanRuntime(r *Report) (label, detail string) {
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
	switch r.VulnerabilityStatus {
	case "BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED", "LEGACY_PHP_VENDOR_PATCH_VERIFICATION_REQUIRED", "MULTIPLE_RUNTIMES_MIXED_PATCH_LEVELS_REVIEW_REQUIRED":
		return "High — update review required"
	case "INSTALL_EVIDENCE_VERSION_CONFLICT_REVIEW_REQUIRED", "REPOSITORY_DECLARATION_BELOW_FIX_DEPLOYMENT_UNKNOWN":
		return "Elevated — verification required"
	case "UPSTREAM_FIX_LEVEL_OBSERVED_ACTIVE_RUNTIME_UNVERIFIED":
		return "Moderate — confirm active runtime"
	default:
		return "Review required — inventory incomplete"
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
	rtLabel, _ := humanRuntime(r)
	if rtLabel != "Verified" {
		add("Identify which PHP binary or SAPI actually serves HTTP (FPM pool, Apache module, IIS handler, container entrypoint). Package and CLI versions alone are not sufficient.")
	}
	switch r.CompromiseStatus {
	case "INDICATORS_MATCHED_REVIEW_REQUIRED":
		add("Preserve matched files and logs, and escalate for incident response validation. Indicator matches are not automatic proof of successful exploitation.")
	case "NO_MATCHES_SCOPE_LIMITED":
		add("Treat the host as not cleared for compromise: expand log/EDR review for the pre-patch window. Absence of IOC matches is not proof of safety.")
	default:
		add("Compromise was not assessed with a validated PHP2Shell-specific indicator pack. Retain access/error logs and EDR telemetry if investigation is required.")
	}
	if ScanIncomplete(r) {
		add("Re-run with adequate permissions for any incomplete coverage items (packages, configs, logs, or webroot) listed in the coverage section.")
	}
	add("Validate remediation by checking the active web handler version after restart, and review official guidance at " + AdvisoryURL + ".")
	if len(steps) > 6 {
		steps = steps[:6]
	}
	return steps
}
