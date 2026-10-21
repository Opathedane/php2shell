package audit

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var debianPHPPackage = regexp.MustCompile(`(?i)^php(\d)\.(\d)-(fpm|cli|cgi)$`)

func evidenceRuntimeKey(e Evidence) string {
	switch e.Type {
	case "binary_static_version", "binary_path", "binary_path_inferred_version":
		return "evidence:binary:" + normalizeInstallPath(e.Location)
	case "installed_package":
		return "evidence:package:" + e.Name
	case "operator_reported_web_runtime":
		return "evidence:operator:" + e.Name + ":" + e.Version
	default:
		return "evidence:" + e.Type + ":" + e.Location + ":" + e.Name
	}
}

func canonicalBinaryInstallDir(location string, aliasDirs map[string]string) string {
	dir := normalizeInstallPath(parentDirAnyOS(location))
	if aliasDirs != nil {
		if canon, ok := aliasDirs[dir]; ok && canon != "" {
			return canon
		}
	}
	return dir
}

func normalizeInstallPath(p string) string {
	// Slash-normalize so Windows paths remain stable install keys on any GOOS
	// (fleet CSV / demos / cross-platform tests). Filesystem opens still use filepath.
	p = strings.ReplaceAll(p, `\`, `/`)
	p = path.Clean(p)
	return strings.ToLower(p)
}

// parentDirAnyOS returns the parent directory using slash semantics for both
// Windows and Unix path spellings.
func parentDirAnyOS(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), `\`, `/`)
	p = strings.TrimRight(p, `/`)
	if p == "" {
		return "."
	}
	i := strings.LastIndex(p, `/`)
	if i < 0 {
		return "."
	}
	if i == 0 {
		return "/"
	}
	return p[:i]
}

func debianPackageBinaryPaths(packageName string) []string {
	m := debianPHPPackage.FindStringSubmatch(packageName)
	if m == nil {
		return nil
	}
	major, minor, kind := m[1], m[2], strings.ToLower(m[3])
	branch := major + "." + minor
	switch kind {
	case "fpm":
		return []string{filepath.Join("/usr/sbin", "php-fpm"+branch)}
	case "cli":
		return []string{filepath.Join("/usr/bin", "php"+branch)}
	case "cgi":
		return []string{
			filepath.Join("/usr/bin", "php-cgi"+branch),
			filepath.Join("/usr/bin", "php"+branch+"-cgi"),
		}
	default:
		return nil
	}
}

func assignInstallKeys(assessments []PatchAssessment) []PatchAssessment {
	return assignInstallKeysWithAliases(assessments, nil)
}

func assignInstallKeysWithAliases(assessments []PatchAssessment, aliasDirs map[string]string) []PatchAssessment {
	binaryInstall := map[string]string{}
	for i := range assessments {
		a := &assessments[i]
		if !isHostRuntimeEvidence(a.EvidenceType) {
			continue
		}
		a.RuntimeKey = evidenceRuntimeKey(Evidence{Type: a.EvidenceType, Name: a.Component, Version: a.ObservedVersion, Location: a.Location})
		if a.EvidenceType == "binary_static_version" || a.EvidenceType == "binary_path_inferred_version" {
			dir := canonicalBinaryInstallDir(a.Location, aliasDirs)
			key := "install:binary-dir:" + dir
			a.InstallKey = key
			binaryInstall[normalizeInstallPath(a.Location)] = key
			binaryInstall[dir] = key
		}
	}
	for i := range assessments {
		a := &assessments[i]
		if a.EvidenceType != "installed_package" {
			continue
		}
		key := "install:package:" + a.Component
		for _, candidate := range debianPackageBinaryPaths(a.Component) {
			if linked, ok := binaryInstall[normalizeInstallPath(candidate)]; ok {
				key = linked
				break
			}
		}
		a.InstallKey = key
	}
	for i := range assessments {
		a := &assessments[i]
		if a.EvidenceType == "operator_reported_web_runtime" {
			a.InstallKey = "install:operator:" + a.Component + ":" + a.ObservedVersion
		}
	}
	return assessments
}

type installRollup struct {
	versions map[string]struct{}
	worst    int
}

const (
	rollupUnknown = iota
	rollupAtOrAbove
	rollupBelow
	rollupLegacy
)

func statusRollupRank(status string) int {
	switch status {
	case "BELOW_UPSTREAM_FIX":
		return rollupBelow
	case "LEGACY_VENDOR_VERIFICATION_REQUIRED":
		return rollupLegacy
	case "AT_OR_ABOVE_UPSTREAM_FIX":
		return rollupAtOrAbove
	default:
		return rollupUnknown
	}
}

func aggregateHostVulnerability(assessments []PatchAssessment, belowRepo int, observed int) string {
	byInstall := map[string]*installRollup{}
	conflicts := 0
	for _, a := range assessments {
		if !isHostRuntimeEvidence(a.EvidenceType) || a.InstallKey == "" {
			continue
		}
		g, ok := byInstall[a.InstallKey]
		if !ok {
			g = &installRollup{versions: map[string]struct{}{}}
			byInstall[a.InstallKey] = g
		}
		if a.ObservedVersion != "" {
			g.versions[normalizeVersionKey(a.ObservedVersion)] = struct{}{}
		}
		r := statusRollupRank(a.Status)
		if r > g.worst {
			g.worst = r
		}
	}
	belowInstalls, legacyInstalls, atOrAboveInstalls, unknownInstalls := 0, 0, 0, 0
	for _, g := range byInstall {
		if len(g.versions) > 1 {
			conflicts++
		}
		switch g.worst {
		case rollupBelow:
			belowInstalls++
		case rollupLegacy:
			legacyInstalls++
		case rollupAtOrAbove:
			atOrAboveInstalls++
		default:
			unknownInstalls++
		}
	}
	if conflicts > 0 {
		return "INSTALL_EVIDENCE_VERSION_CONFLICT_REVIEW_REQUIRED"
	}
	if belowInstalls > 0 && atOrAboveInstalls > 0 {
		return "MULTIPLE_RUNTIMES_MIXED_PATCH_LEVELS_REVIEW_REQUIRED"
	}
	if belowInstalls > 0 {
		return "BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED"
	}
	if legacyInstalls > 0 {
		return "LEGACY_PHP_VENDOR_PATCH_VERIFICATION_REQUIRED"
	}
	if belowRepo > 0 {
		return "REPOSITORY_DECLARATION_BELOW_FIX_DEPLOYMENT_UNKNOWN"
	}
	if observed == 0 {
		return "NO_COMPARABLE_PHP_VERSION_FOUND_INVENTORY_INCOMPLETE"
	}
	if atOrAboveInstalls > 0 && belowInstalls == 0 && legacyInstalls == 0 && unknownInstalls == 0 {
		return "UPSTREAM_FIX_LEVEL_OBSERVED_ACTIVE_RUNTIME_UNVERIFIED"
	}
	return "INDETERMINATE_REVIEW_REQUIRED"
}

func normalizeVersionKey(v string) string {
	match := cleanPHPVersion.FindStringSubmatch(v)
	if len(match) >= 4 && match[3] != "" {
		return match[1] + "." + match[2] + "." + match[3]
	}
	return strings.TrimSpace(v)
}

func isHostRuntimeEvidence(t string) bool {
	switch t {
	case "installed_package", "binary_static_version", "binary_path_inferred_version", "operator_reported_web_runtime":
		return true
	default:
		return false
	}
}
