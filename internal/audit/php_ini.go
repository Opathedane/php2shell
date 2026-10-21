package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	maxPHPIniFiles           = 200
	maxPHPIniBytes           = 2 << 20
	maxPHPIniScanDirPerDir   = 32
	maxNearbyBinaryProbes    = 16
	maxNearbyBinaryDiscover  = 8
)

// readPHPIniContents loads a candidate ini for inspection. Defaults to ReadRegular
// (no symlink follow). Tests may replace this with a deterministic stub; production
// code must leave it pointing at ReadRegular.
var readPHPIniContents = ReadRegular

// phpIniWellKnownPatternsFn returns well-known php.ini globs. Tests may replace
// this with an empty list for hermetic operator-path regressions (CI images often
// ship /etc/php or Windows PHP trees that would otherwise pollute fixtures).
var phpIniWellKnownPatternsFn = phpIniWellKnownPatterns

// phpIniScanState collects bounded php.ini / conf.d candidates without claiming
// effective SAPI settings or exact PHP versions.
type phpIniScanState struct {
	seenFile         map[string]bool
	seenSkip         map[string]bool
	seenNearbyProbe  map[string]bool
	inspected        int
	truncated        bool
	templates        int
	primaries        int
	fragments        int
	settings         int
	correlated       int
	uncorrelated     int
	skippedUnread    int
	skippedOversize  int
	skippedSymlink   int
	skippedOther     int
	operatorInspected int
	nearbyFromIni    int
}

func newPHPIniScanState() *phpIniScanState {
	return &phpIniScanState{
		seenFile:        map[string]bool{},
		seenSkip:        map[string]bool{},
		seenNearbyProbe: map[string]bool{},
	}
}

// scanConfigs inventories php.ini-style files on Windows and Linux using well-known
// paths, env hints, sidecars next to discovered binaries, web-server references,
// and optional operator-authorized --php-ini / --config-root / --deep-root paths.
func scanConfigs(r *Report, opts HostScanOptions, deepOutcomes []deepDiscoverOutcome) {
	st := newPHPIniScanState()
	for _, p := range phpIniEnvCandidates() {
		st.observePHPIniFile(r, p.path, p.source, p.class, false)
	}
	for _, pattern := range phpIniWellKnownPatternsFn() {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			st.observePHPIniFile(r, path, "well-known PHP configuration path", classifyPHPIniBasename(filepath.Base(path)), false)
		}
	}
	st.observeSidecarsFromEvidence(r)
	st.observePATHDirConfigs(r)
	st.observeWebServerIniRefs(r)
	st.observeOperatorPaths(r, opts)
	st.observeDeepRoots(r, deepOutcomes)

	status := "PARTIAL"
	if st.truncated {
		status = "TRUNCATED"
		r.AddWarning("PHP configuration file count limit (200) reached")
	}
	skipTotal := st.skippedUnread + st.skippedOversize + st.skippedSymlink + st.skippedOther
	if skipTotal > 0 {
		r.AddWarning(fmt.Sprintf(
			"PHP configuration coverage incomplete: %d candidate(s) not inspected (unreadable=%d oversized=%d symlink_or_reparse=%d other=%d); paths recorded as php_ini_skip without secrets",
			skipTotal, st.skippedUnread, st.skippedOversize, st.skippedSymlink, st.skippedOther,
		))
	}
	detail := fmt.Sprintf(
		"Read %d PHP configuration candidate file(s) (%d primary php.ini, %d scan-dir fragments, %d sample/template names); extracted %d whitelisted setting observations; %d correlated to nearby binary installs; %d uncorrelated configuration-only candidates; %d skipped (unreadable/oversized/symlink/other); %d from operator --php-ini/--config-root/--deep-root; %d nearby binaries discovered from ini directories; settings are NOT verified as effective for any SAPI; php.ini is not proof of PHP version or active HTTP runtime; secrets and full file contents are not reported",
		st.inspected, st.primaries, st.fragments, st.templates, st.settings, st.correlated, st.uncorrelated, skipTotal, st.operatorInspected, st.nearbyFromIni,
	)
	r.AddCheck("configuration", status, detail)
}

type phpIniCandidate struct {
	path   string
	source string
	class  string
}

func phpIniEnvCandidates() []phpIniCandidate {
	var out []phpIniCandidate
	if prc := strings.TrimSpace(os.Getenv("PHPRC")); prc != "" {
		prc = expandPHPIniEnvPath(prc)
		fi, err := os.Lstat(prc)
		if err == nil && fi.Mode().IsRegular() && fi.Mode()&os.ModeSymlink == 0 {
			out = append(out, phpIniCandidate{path: prc, source: "PHPRC environment variable (process)", class: classifyPHPIniBasename(filepath.Base(prc))})
		} else if err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
			out = append(out, phpIniCandidate{path: filepath.Join(prc, "php.ini"), source: "PHPRC directory (process)", class: "primary_candidate"})
		}
	}
	if scan := strings.TrimSpace(os.Getenv("PHP_INI_SCAN_DIR")); scan != "" {
		for _, dir := range splitPHPIniScanDirs(scan) {
			dir = expandPHPIniEnvPath(strings.TrimSpace(dir))
			if dir == "" || dir == "#" {
				continue
			}
			fi, err := os.Lstat(dir)
			if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
				continue
			}
			matches, _ := filepath.Glob(filepath.Join(dir, "*.ini"))
			n := 0
			for _, path := range matches {
				if n >= maxPHPIniScanDirPerDir {
					break
				}
				out = append(out, phpIniCandidate{path: path, source: "PHP_INI_SCAN_DIR environment variable (process)", class: "scan_dir_fragment"})
				n++
			}
		}
	}
	return out
}

func splitPHPIniScanDirs(scan string) []string {
	// PHP uses platform PATH list separator; also tolerates an optional trailing #:path for scan dirs.
	sep := ":"
	if runtime.GOOS == "windows" {
		sep = ";"
	}
	return strings.Split(scan, sep)
}

func expandPHPIniEnvPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if runtime.GOOS == "windows" {
		return filepath.Clean(expandWindowsPercentEnv(os.ExpandEnv(p)))
	}
	return filepath.Clean(os.ExpandEnv(p))
}

func phpIniWellKnownPatterns() []string {
	if runtime.GOOS == "windows" {
		patterns := []string{
			`C:\php\php.ini`,
			`C:\php\php.ini-production`,
			`C:\php\php.ini-development`,
			`C:\xampp\php\php.ini`,
			`C:\wamp\bin\php\*\php.ini`,
			`C:\laragon\bin\php\*\php.ini`,
			`C:\inetpub\PHP\*\php.ini`,
			`C:\Program Files\PHP\*\php.ini`,
			`C:\Program Files (x86)\PHP\*\php.ini`,
			`C:\ProgramData\PHP\*\php.ini`,
			`C:\tools\php\php.ini`,
			`C:\tools\php\*\php.ini`,
		}
		if local := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); local != "" {
			base := filepath.Join(local, "Programs", "PHP")
			patterns = append(patterns,
				filepath.Join(base, "*", "php.ini"),
				filepath.Join(base, "*", "*", "php.ini"),
				filepath.Join(base, "*", "*", "*", "php.ini"),
				filepath.Join(base, "*", "php.ini-production"),
				filepath.Join(base, "*", "*", "*", "php.ini-production"),
				filepath.Join(base, "*", "php.ini-development"),
				filepath.Join(base, "*", "*", "*", "php.ini-development"),
			)
		}
		if pf := strings.TrimSpace(os.Getenv("ProgramFiles")); pf != "" {
			patterns = append(patterns,
				filepath.Join(pf, "PHP", "*", "php.ini"),
				filepath.Join(pf, "PHP", "*", "php.ini-production"),
			)
		}
		return patterns
	}
	return []string{
		"/etc/php/*/fpm/php.ini",
		"/etc/php/*/apache2/php.ini",
		"/etc/php/*/cgi/php.ini",
		"/etc/php/*/cli/php.ini",
		"/etc/php/*/mods-available/*.ini",
		"/etc/php/*/fpm/conf.d/*.ini",
		"/etc/php/*/cli/conf.d/*.ini",
		"/etc/php.ini",
		"/etc/php-fpm.d/*.conf",
		"/etc/php/*/fpm/pool.d/*.conf",
		"/usr/local/etc/php/php.ini",
		"/usr/local/etc/php/conf.d/*.ini",
		"/usr/php/*/etc/php.ini",
		"/usr/php/*/lib/php.ini",
		"/opt/php/*/etc/php.ini",
		"/opt/php/*/lib/php.ini",
		"/opt/php/*/php.ini",
		"/opt/plesk/php/*/etc/php.ini",
		"/opt/remi/php*/root/etc/php.ini",
		"/opt/remi/php*/root/etc/php.d/*.ini",
		"/opt/cpanel/ea-php*/root/etc/php.ini",
		"/opt/cpanel/ea-php*/root/etc/php.d/*.ini",
	}
}

func (st *phpIniScanState) observeSidecarsFromEvidence(r *Report) {
	seenDir := map[string]bool{}
	for _, e := range r.Evidence {
		switch e.Type {
		case "binary_path", "binary_static_version", "binary_path_inferred_version":
			dir := filepath.Dir(e.Location)
			if dir == "" || dir == "." {
				continue
			}
			key := normalizeInstallPath(dir)
			if seenDir[key] {
				continue
			}
			seenDir[key] = true
			for _, name := range []string{"php.ini", "php.ini-production", "php.ini-development", "php.ini-dist"} {
				st.observePHPIniFile(r, filepath.Join(dir, name), "sidecar next to discovered PHP binary", classifyPHPIniBasename(name), false)
			}
			// Common opt layout: binary in bin/ or sbin/, ini under ../etc/
			parent := filepath.Dir(dir)
			base := strings.ToLower(filepath.Base(dir))
			if base == "bin" || base == "sbin" || base == "nts" || base == "ts" || base == "x64" || base == "x86" {
				st.observePHPIniFile(r, filepath.Join(parent, "php.ini"), "nearby install-tree php.ini", "primary_candidate", false)
				st.observePHPIniFile(r, filepath.Join(parent, "etc", "php.ini"), "nearby install-tree etc/php.ini", "primary_candidate", false)
			}
		}
	}
}

// observePATHDirConfigs inspects php.ini names beside PATH directories that resolve
// to plain directories (including a single bounded junction/symlink hop chain).
// This covers layouts such as C:\Temp\PHP\current on PATH without drive-wide scans.
func (st *phpIniScanState) observePATHDirConfigs(r *Report) {
	sep := string(os.PathListSeparator)
	dirs := 0
	for _, dir := range strings.Split(os.Getenv("PATH"), sep) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		dirs++
		if dirs > maxPATHDirInspect {
			break
		}
		plan, ok := planPATHDirInspect(dir)
		if !ok {
			continue
		}
		source := "sidecar next to PATH directory"
		if plan.ViaReparse {
			source = "sidecar next to PATH directory (resolved junction/symlink)"
		}
		for _, name := range []string{"php.ini", "php.ini-production", "php.ini-development", "php.ini-dist"} {
			st.observePHPIniFile(r, filepath.Join(plan.Inspect, name), source, classifyPHPIniBasename(name), false)
		}
	}
}

func (st *phpIniScanState) observeWebServerIniRefs(r *Report) {
	for _, e := range r.Evidence {
		switch e.Type {
		case "configured_php_ini_path", "apache_php_handler_config", "iis_php_handler_config":
			if p := iisDetailField(e.Detail, "php_ini"); p != "" {
				st.observePHPIniFile(r, p, "web server configuration reference", classifyPHPIniBasename(filepath.Base(p)), false)
			}
			if e.Name == "PHPIniDir" {
				if p := iisDetailField(e.Detail, "php_ini"); p != "" {
					// PHPIniDir may be a directory
					fi, err := os.Lstat(p)
					if err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
						st.observePHPIniFile(r, filepath.Join(p, "php.ini"), "Apache PHPIniDir directory", "primary_candidate", false)
					}
				}
			}
		}
	}
}

func (st *phpIniScanState) observeOperatorPaths(r *Report, opts HostScanOptions) {
	nIni := 0
	for _, raw := range opts.PHPIniPaths {
		if nIni >= maxOperatorPHPIniPaths {
			r.AddWarning(fmt.Sprintf("Operator --php-ini limited to %d paths", maxOperatorPHPIniPaths))
			break
		}
		path := filepath.Clean(strings.TrimSpace(raw))
		if path == "" || path == "." {
			continue
		}
		nIni++
		before := st.inspected
		st.observePHPIniFile(r, path, "operator --php-ini", classifyPHPIniBasename(filepath.Base(path)), true)
		if st.inspected > before {
			st.operatorInspected++
		}
	}

	nRoot := 0
	for _, raw := range opts.ConfigRoots {
		if nRoot >= maxOperatorConfigRoots {
			r.AddWarning(fmt.Sprintf("Operator --config-root limited to %d directories", maxOperatorConfigRoots))
			break
		}
		root := filepath.Clean(strings.TrimSpace(raw))
		if root == "" || root == "." {
			continue
		}
		nRoot++
		st.observeConfigRoot(r, root)
	}
}

// observeConfigRoot inspects only common php.ini names at the root and one conf.d/*.ini layer.
// It does not walk arbitrary trees or entire drives.
func (st *phpIniScanState) observeConfigRoot(r *Report, root string) {
	fi, err := os.Lstat(root)
	if err != nil {
		st.recordSkip(r, root, "operator --config-root", "missing_or_inaccessible", true)
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		st.recordSkip(r, root, "operator --config-root", "symlink_or_reparse", true)
		return
	}
	if !fi.IsDir() {
		st.recordSkip(r, root, "operator --config-root", "not_a_directory", true)
		return
	}
	names := []string{"php.ini", "php.ini-production", "php.ini-development", "php.ini-dist"}
	added := 0
	for _, name := range names {
		if added >= maxConfigRootIniFiles || st.inspected >= maxPHPIniFiles {
			break
		}
		before := st.inspected
		st.observePHPIniFile(r, filepath.Join(root, name), "operator --config-root", classifyPHPIniBasename(name), false)
		if st.inspected > before {
			st.operatorInspected++
			added++
		}
	}
	confD := filepath.Join(root, "conf.d")
	cfi, err := os.Lstat(confD)
	if err != nil || !cfi.IsDir() || cfi.Mode()&os.ModeSymlink != 0 {
		return
	}
	matches, _ := filepath.Glob(filepath.Join(confD, "*.ini"))
	for _, path := range matches {
		if added >= maxConfigRootIniFiles || st.inspected >= maxPHPIniFiles {
			if st.inspected >= maxPHPIniFiles {
				st.truncated = true
			}
			r.AddWarning("Operator --config-root conf.d inspection capped")
			break
		}
		before := st.inspected
		st.observePHPIniFile(r, path, "operator --config-root conf.d", "scan_dir_fragment", false)
		if st.inspected > before {
			st.operatorInspected++
			added++
		}
	}
}

// observeDeepRoots inspects ini-like files found during --deep-root walks (weaker provenance).
func (st *phpIniScanState) observeDeepRoots(r *Report, outcomes []deepDiscoverOutcome) {
	for _, o := range outcomes {
		for _, path := range o.Inis {
			if st.inspected >= maxPHPIniFiles {
				st.truncated = true
				r.AddWarning("Operator --deep-root php.ini inspection capped at global configuration limit")
				return
			}
			before := st.inspected
			st.observePHPIniFile(r, path, "operator --deep-root", classifyPHPIniBasename(filepath.Base(path)), false)
			if st.inspected > before {
				st.operatorInspected++
			}
		}
	}
}

// ObservePHPIniFile is the shared entry for web-server callers (IIS -c, Apache PHPIniDir).
func ObservePHPIniFile(r *Report, path, source string) {
	if r == nil || strings.TrimSpace(path) == "" {
		return
	}
	st := newPHPIniScanState()
	st.observePHPIniFile(r, path, source, classifyPHPIniBasename(filepath.Base(path)), false)
}

func (st *phpIniScanState) observePHPIniFile(r *Report, path, source, class string, requireReportSkip bool) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" || path == "." {
		return
	}
	key := normalizeInstallPath(path)
	if st.seenFile[key] {
		return
	}
	// Skip if already recorded as php_ini_candidate on this report (cross-caller dedupe).
	for _, e := range r.Evidence {
		if e.Type == "php_ini_candidate" && normalizeInstallPath(e.Location) == key {
			st.seenFile[key] = true
			return
		}
	}
	if st.inspected >= maxPHPIniFiles {
		st.truncated = true
		return
	}

	// Existence probe: missing well-known paths stay silent; operator paths always report.
	fi, lerr := os.Lstat(path)
	if lerr != nil {
		if requireReportSkip || !os.IsNotExist(lerr) {
			st.recordSkip(r, path, source, classifyPHPIniSkipReason(lerr, nil, path), requireReportSkip || !os.IsNotExist(lerr))
		}
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		st.recordSkip(r, path, source, "symlink_or_reparse", true)
		return
	}
	if !fi.Mode().IsRegular() {
		st.recordSkip(r, path, source, "not_regular_file", true)
		return
	}
	if fi.Size() > maxPHPIniBytes {
		st.recordSkip(r, path, source, "oversized", true)
		return
	}

	b, err := readPHPIniContents(path, maxPHPIniBytes)
	if err != nil {
		st.recordSkip(r, path, source, classifyPHPIniSkipReason(err, fi, path), true)
		return
	}
	st.seenFile[key] = true
	st.inspected++
	switch class {
	case "sample_or_template":
		st.templates++
	case "scan_dir_fragment":
		st.fragments++
	default:
		st.primaries++
	}

	relatedBinary := correlatingBinaryForIni(r, path)
	if relatedBinary == "" {
		st.probeNearbyBinariesFromIni(r, path)
		relatedBinary = correlatingBinaryForIni(r, path)
	}
	if relatedBinary != "" {
		st.correlated++
	} else {
		st.uncorrelated++
	}
	detail := fmt.Sprintf("ini_class=%s; settings_not_verified_effective; not_php_version_authority", class)
	if relatedBinary != "" {
		detail += "; related_binary=" + relatedBinary
	} else {
		detail += "; correlated_install=none"
	}
	interp := "CONFIGURED_INI_CANDIDATE_NOT_PROOF_OF_VERSION_OR_ACTIVE_RUNTIME"
	if class == "sample_or_template" {
		interp = "SAMPLE_OR_TEMPLATE_INI_NOT_PROOF_ACTIVE_OR_EFFECTIVE"
	}
	r.AddEvidence(Evidence{
		Type:           "php_ini_candidate",
		Name:           filepath.Base(path),
		Source:         source,
		Location:       path,
		Detail:         detail,
		Interpretation: interp,
	})

	for _, ln := range strings.Split(string(b), "\n") {
		val := strings.TrimSpace(ln)
		if strings.HasPrefix(val, ";") || strings.HasPrefix(val, "#") {
			continue
		}
		m := iniSetting.FindStringSubmatch(ln)
		if len(m) != 3 {
			continue
		}
		st.settings++
		settingDetail := strings.TrimSpace(m[2])
		if relatedBinary != "" {
			settingDetail += "; related_binary=" + relatedBinary
		}
		settingDetail += "; ini_class=" + class
		r.AddEvidence(Evidence{
			Type:           "configuration_observation",
			Name:           strings.ToLower(m[1]),
			Source:         "static PHP configuration text",
			Location:       path,
			Detail:         settingDetail,
			Interpretation: "OBSERVED_NOT_EFFECTIVE_SETTING_NOT_VERIFIED_MITIGATION",
		})
	}
}

func classifyPHPIniSkipReason(err error, fi os.FileInfo, path string) string {
	if err == nil {
		return "unknown"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case os.IsNotExist(err):
		return "missing"
	case os.IsPermission(err) || strings.Contains(msg, "permission") || strings.Contains(msg, "access is denied"):
		return "unreadable"
	case strings.Contains(msg, "symbolic link") || strings.Contains(msg, "reparse"):
		return "symlink_or_reparse"
	case strings.Contains(msg, "exceeds") || strings.Contains(msg, "exceeded") || strings.Contains(msg, "safety limit") || strings.Contains(msg, "read limit"):
		return "oversized"
	case strings.Contains(msg, "not a regular"):
		return "not_regular_file"
	default:
		if fi != nil && fi.Size() > maxPHPIniBytes {
			return "oversized"
		}
		_ = path
		return "unreadable_or_rejected"
	}
}

func (st *phpIniScanState) recordSkip(r *Report, path, source, reason string, emit bool) {
	if !emit {
		return
	}
	path = filepath.Clean(strings.TrimSpace(path))
	key := normalizeInstallPath(path)
	if st.seenSkip[key] || st.seenFile[key] {
		return
	}
	st.seenSkip[key] = true
	switch reason {
	case "unreadable", "unreadable_or_rejected", "missing", "missing_or_inaccessible":
		st.skippedUnread++
	case "oversized":
		st.skippedOversize++
	case "symlink_or_reparse":
		st.skippedSymlink++
	default:
		st.skippedOther++
	}
	// Path and reason only — never file contents or secrets.
	r.AddEvidence(Evidence{
		Type:           "php_ini_skip",
		Name:           filepath.Base(path),
		Source:         source,
		Location:       path,
		Detail:         "skip_reason=" + reason + "; contents_not_inspected; secrets_not_reported",
		Interpretation: "CONFIG_CANDIDATE_NOT_INSPECTED_COVERAGE_INCOMPLETE",
	})
}

// probeNearbyBinariesFromIni looks for PHP executables beside a discovered php.ini
// (same directory, parent, parent/bin, parent/sbin) without inventing drive-wide scans.
func (st *phpIniScanState) probeNearbyBinariesFromIni(r *Report, iniPath string) {
	iniDir := filepath.Dir(iniPath)
	key := normalizeInstallPath(iniDir)
	if st.seenNearbyProbe[key] {
		return
	}
	st.seenNearbyProbe[key] = true

	dirs := []string{iniDir}
	parent := filepath.Dir(iniDir)
	if parent != "" && parent != iniDir && parent != "." {
		dirs = append(dirs, parent, filepath.Join(parent, "bin"), filepath.Join(parent, "sbin"))
		base := strings.ToLower(filepath.Base(iniDir))
		if base == "etc" || base == "conf" || base == "conf.d" {
			dirs = append(dirs, filepath.Join(parent, "bin"), filepath.Join(parent, "sbin"))
		}
	}

	names := []string{"php", "php.exe", "php-cgi", "php-cgi.exe", "php-fpm", "php-fpm.exe"}
	probes := 0
	discovered := 0
	for _, dir := range dirs {
		for _, name := range names {
			if probes >= maxNearbyBinaryProbes || discovered >= maxNearbyBinaryDiscover {
				return
			}
			probes++
			cand := filepath.Join(dir, name)
			if !isSafeRegularFile(cand) || !HandlerExecutableLooksLikePHP(cand) {
				continue
			}
			// Avoid re-adding if already present.
			already := false
			candKey := normalizeInstallPath(cand)
			for _, e := range r.Evidence {
				switch e.Type {
				case "binary_path", "binary_static_version", "binary_path_inferred_version":
					if normalizeInstallPath(e.Location) == candKey {
						already = true
					}
				}
			}
			if already {
				continue
			}
			AddBinaryVersionEvidence(r, cand, filepath.Base(cand), "nearby PHP binary beside discovered php.ini")
			st.nearbyFromIni++
			discovered++
		}
	}
}

func classifyPHPIniBasename(name string) string {
	low := strings.ToLower(strings.TrimSpace(name))
	switch {
	case low == "php.ini":
		return "primary_candidate"
	case strings.HasSuffix(low, ".conf") && strings.Contains(low, "pool"):
		return "fpm_pool_fragment"
	case strings.HasPrefix(low, "php.ini-") || strings.Contains(low, "php.ini-development") ||
		strings.Contains(low, "php.ini-production") || strings.HasSuffix(low, ".dist") ||
		strings.Contains(low, "php.ini-dist") || strings.Contains(low, ".default"):
		return "sample_or_template"
	case strings.HasSuffix(low, ".ini"):
		return "scan_dir_fragment"
	default:
		return "named_variant"
	}
}

func correlatingBinaryForIni(r *Report, iniPath string) string {
	iniDir := normalizeInstallPath(filepath.Dir(iniPath))
	parent := normalizeInstallPath(filepath.Dir(filepath.Dir(iniPath)))
	for _, e := range r.Evidence {
		switch e.Type {
		case "binary_path", "binary_static_version", "binary_path_inferred_version":
			binDir := normalizeInstallPath(filepath.Dir(e.Location))
			if binDir == iniDir || binDir == parent {
				return e.Location
			}
			// .../PHP/8.4.24/nts/x64/php.exe vs .../PHP/8.4.24/php.ini
			if strings.HasPrefix(binDir, iniDir+"/") || strings.HasPrefix(iniDir, binDir+"/") {
				return e.Location
			}
		}
	}
	return ""
}

// FirstUncorrelatedPrimaryIni returns the first primary php.ini path with no related binary.
func FirstUncorrelatedPrimaryIni(r *Report) string {
	if r == nil {
		return ""
	}
	for _, e := range r.Evidence {
		if e.Type != "php_ini_candidate" {
			continue
		}
		class := iisDetailField(e.Detail, "ini_class")
		if class == "" {
			class = classifyPHPIniBasename(e.Name)
		}
		if class != "primary_candidate" {
			continue
		}
		if iisDetailField(e.Detail, "related_binary") == "" {
			return e.Location
		}
	}
	return ""
}

// CountPHPIniSkips returns how many configuration candidates were not inspected.
func CountPHPIniSkips(r *Report) int {
	n := 0
	if r == nil {
		return 0
	}
	for _, e := range r.Evidence {
		if e.Type == "php_ini_skip" {
			n++
		}
	}
	return n
}

// ExtractDashCIniPath returns the path from a PHP -c argument list (IIS scriptProcessor args).
// Only the path is returned; never the remainder of the argument string.
func ExtractDashCIniPath(args string) string {
	args = strings.TrimSpace(args)
	if args == "" {
		return ""
	}
	fields := splitApacheArgs(args) // whitespace/quote-aware
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if f == "-c" && i+1 < len(fields) {
			return unquoteApache(fields[i+1])
		}
		if strings.HasPrefix(f, "-c") && len(f) > 2 {
			return unquoteApache(strings.TrimPrefix(f, "-c"))
		}
	}
	return ""
}
