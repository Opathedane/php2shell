package audit

import (
	"fmt"
	"path/filepath"
	"strings"
)

// PHP discovery classification (internal). Used to keep HTML/CLI/CSV/summary semantics aligned
// without changing vulnerability-detection rules or scan-execution status.
const (
	phpDiscAssessable         = "assessable"
	phpDiscVersionUnknown     = "version_unknown"
	phpDiscDeclaredOnly       = "declared_only"
	phpDiscConfigCandidates   = "config_candidates"
	phpDiscConfigIncomplete   = "config_incomplete"
	phpDiscArtifactsOnly      = "artifacts_only"
	phpDiscNoneWithinCoverage = "none_within_coverage"
	phpDiscNoneIncomplete     = "none_incomplete"
)

func isWindowsLikeOS(osname string) bool {
	o := strings.ToLower(strings.TrimSpace(osname))
	return strings.Contains(o, "windows") || o == "win32" || o == "win64"
}

// IsWindowsLikeOS reports whether the OS name looks like Windows (for OS-aware messaging).
func IsWindowsLikeOS(osname string) bool { return isWindowsLikeOS(osname) }

// ShouldWarnPackageDBNotSupported is true when the console/HTML should mention missing
// dpkg/apk package inventory. False on Windows (packages=NOT_SUPPORTED is expected).
func ShouldWarnPackageDBNotSupported(r *Report) bool {
	if r == nil || isWindowsLikeOS(r.OS) {
		return false
	}
	for _, c := range r.Coverage {
		if c.Name == "packages" && strings.EqualFold(c.Status, "NOT_SUPPORTED") {
			return true
		}
	}
	return false
}

// isPHPDiscoveryCheck names coverage rows that matter for PHP presence inventory.
func isPHPDiscoveryCheck(name string) bool {
	switch name {
	case "packages", "binary_paths", "processes", "windows_processes",
		"windows_iis_configuration", "deep_discovery", "configuration", "apache_configuration",
		"nginx_configuration", "php_fpm_configuration",
		"webroot": // only contributes when present; NOT_REQUESTED is ignored below
		return true
	default:
		return false
	}
}

func hasApplicablePHPDiscoveryChecks(r *Report) bool {
	if r == nil {
		return false
	}
	for _, c := range r.Coverage {
		if isPHPDiscoveryCheck(c.Name) {
			return true
		}
	}
	return false
}

// relevantPHPInventoryGaps returns discovery gaps that justify "inventory incomplete"
// for no-PHP messaging. OS-aware: packages NOT_SUPPORTED is ignored on Windows and
// treated as a packaging-system gap on Linux (RPM etc.). NOT_APPLICABLE IIS/Apache is ignored.
func relevantPHPInventoryGaps(r *Report) []string {
	if r == nil {
		return nil
	}
	var gaps []string
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		gaps = append(gaps, s)
	}
	for _, c := range r.Coverage {
		if !isPHPDiscoveryCheck(c.Name) {
			continue
		}
		st := strings.ToUpper(c.Status)
		switch c.Name {
		case "packages":
			if st == "NOT_SUPPORTED" {
				if isWindowsLikeOS(r.OS) {
					continue // expected: no dpkg/apk on Windows
				}
				add("packages (unsupported packaging system; RPM/yum/dnf/pacman not inventoried)")
				continue
			}
		case "windows_iis_configuration", "apache_configuration", "nginx_configuration", "php_fpm_configuration", "webroot":
			if st == "NOT_APPLICABLE" || st == "NOT_SUPPORTED" || st == "NOT_REQUESTED" {
				continue
			}
		}
		switch st {
		case "INCOMPLETE", "UNAVAILABLE", "TRUNCATED", "TIMEOUT", "ACCESS_DENIED", "UNSUPPORTED_FORMAT":
			add(c.Name)
		}
	}
	return gaps
}

// NoPHPDetectedWithinScanCoverage is true when no PHP-related evidence was observed and
// applicable discovery checks completed without relevant gaps.
func NoPHPDetectedWithinScanCoverage(r *Report) bool {
	return classifyPHPDiscovery(r) == phpDiscNoneWithinCoverage
}

// NoPHPWithIncompleteInventory is true when no PHP evidence was observed but relevant
// discovery sources are missing, failed, or unsupported on Linux packaging systems.
func NoPHPWithIncompleteInventory(r *Report) bool {
	return classifyPHPDiscovery(r) == phpDiscNoneIncomplete
}

func classifyPHPDiscovery(r *Report) string {
	if r == nil {
		return phpDiscNoneIncomplete
	}
	confirmedVers := map[string]struct{}{}
	confirmed, declared, artifacts := false, false, false
	iniCandidates, iniSkips := 0, 0
	for _, e := range r.Evidence {
		switch e.Type {
		case "installed_package":
			if e.Version == "" || e.Interpretation == "PACKAGE_METADATA_ONLY_NOT_PHP_RUNTIME_VERSION" {
				artifacts = true
				continue
			}
			confirmed = true
			confirmedVers[e.Version] = struct{}{}
		case "binary_path", "binary_static_version", "binary_path_inferred_version", "iis_php_handler_config", "apache_php_handler_config", "apache_php_module_config", "nginx_php_handler_config", "php_fpm_pool_config", "operator_reported_web_runtime":
			confirmed = true
			if e.Version == "" {
				// Configured handlers/pools without a version stay version_unknown once confirmed.
			} else {
				confirmedVers[e.Version] = struct{}{}
			}
		case "apache_vhost_config", "apache_remote_php_backend", "nginx_site_config", "nginx_remote_php_backend", "nginx_php_upstream_config":
			artifacts = true
		case "running_process":
			if e.Name != "w3wp.exe" {
				confirmed = true
			}
		case "repository_declaration":
			declared = true
		case "php_ini_candidate":
			artifacts = true
			iniCandidates++
		case "configuration_observation", "php_webroot_filename":
			artifacts = true
		case "php_ini_skip", "nginx_config_skip", "php_fpm_config_skip", "nginx_include_unresolved":
			artifacts = true
			iniSkips++
		}
	}
	if confirmed {
		if len(confirmedVers) == 0 {
			return phpDiscVersionUnknown
		}
		return phpDiscAssessable
	}
	if declared {
		return phpDiscDeclaredOnly
	}
	if artifacts {
		if iniCandidates > 0 {
			return phpDiscConfigCandidates
		}
		if iniSkips > 0 {
			return phpDiscConfigIncomplete
		}
		return phpDiscArtifactsOnly
	}
	if hasApplicablePHPDiscoveryChecks(r) && len(relevantPHPInventoryGaps(r)) == 0 {
		return phpDiscNoneWithinCoverage
	}
	return phpDiscNoneIncomplete
}

// BinaryInstallCoverage summarizes PHP binary candidate version provenance for operator-facing reports.
// Path-inferred counts are not confirmed installations or proven vulnerability exposure.
type BinaryInstallCoverage struct {
	BinaryCandidates int
	InstallDirs      int
	Verified         int
	PathInferred     int
	VersionUnknown   int
}

// CountBinaryInstallCoverage tallies binary_path / binary_static_version / binary_path_inferred_version evidence.
func CountBinaryInstallCoverage(r *Report) BinaryInstallCoverage {
	var c BinaryInstallCoverage
	if r == nil {
		return c
	}
	dirs := map[string]struct{}{}
	for _, e := range r.Evidence {
		switch e.Type {
		case "binary_static_version":
			c.Verified++
			c.BinaryCandidates++
			if e.Location != "" {
				dirs[normalizeInstallPath(filepath.Dir(e.Location))] = struct{}{}
			}
		case "binary_path_inferred_version":
			c.PathInferred++
			c.BinaryCandidates++
			if e.Location != "" {
				dirs[normalizeInstallPath(filepath.Dir(e.Location))] = struct{}{}
			}
		case "binary_path":
			c.VersionUnknown++
			c.BinaryCandidates++
			if e.Location != "" {
				dirs[normalizeInstallPath(filepath.Dir(e.Location))] = struct{}{}
			}
		}
	}
	c.InstallDirs = len(dirs)
	return c
}

// FormatBinaryInstallCoverageDetail returns a concise operator-facing coverage sentence.
func FormatBinaryInstallCoverageDetail(c BinaryInstallCoverage) string {
	if c.BinaryCandidates == 0 {
		return ""
	}
	return fmt.Sprintf(
		"%d PHP binary candidate(s) across %d install director(ies): %d with verified binary metadata, %d path-inferred (MEDIUM confidence; not binary-verified), %d without comparable version. Path-inferred versions are not confirmed installations or proven vulnerability exposure and require manual verification. Not proof of the HTTP-serving runtime.",
		c.BinaryCandidates, c.InstallDirs, c.Verified, c.PathInferred, c.VersionUnknown,
	)
}

// executiveVerificationGaps lists operator-facing gaps for the HTML "What could not be verified" card.
// Excludes Windows packages NOT_SUPPORTED and does not invent an HTTP-runtime gap when no PHP was found.
func executiveVerificationGaps(r *Report) []string {
	if r == nil {
		return nil
	}
	kind := classifyPHPDiscovery(r)
	var parts []string
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		parts = append(parts, s)
	}

	switch kind {
	case phpDiscNoneWithinCoverage:
		// No PHP to verify as an HTTP runtime; soft coverage limits belong in the detail text.
	case phpDiscNoneIncomplete:
		for _, g := range relevantPHPInventoryGaps(r) {
			add(g)
		}
	default:
		rtLabel, _ := humanRuntime(r)
		if rtLabel != "Verified" {
			add("HTTP-serving PHP runtime")
		}
		cov := CountBinaryInstallCoverage(r)
		if cov.PathInferred > 0 {
			add("path-inferred PHP version(s) (not binary-verified; manual verification required)")
		}
		if cov.VersionUnknown > 0 {
			add("PHP binary candidate(s) without comparable version")
		}
		for _, g := range relevantPHPInventoryGaps(r) {
			add(g)
		}
		// Genuine Windows discovery failures already appear via relevantPHPInventoryGaps.
		// Do not re-add packages NOT_SUPPORTED on Windows.
	}
	return parts
}
