package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	maxPHPIniFiles         = 200
	maxPHPIniBytes         = 2 << 20
	maxPHPIniScanDirPerDir = 32
)

// readPHPIniContents loads a candidate ini for inspection. Defaults to ReadRegular
// (no symlink follow). Tests may replace this with a deterministic stub; production
// code must leave it pointing at ReadRegular.
var readPHPIniContents = ReadRegular

// phpIniScanState collects bounded php.ini / conf.d candidates without claiming
// effective SAPI settings or exact PHP versions.
type phpIniScanState struct {
	seenFile   map[string]bool
	inspected  int
	truncated  bool
	templates  int
	primaries  int
	fragments  int
	settings   int
	correlated int
}

func newPHPIniScanState() *phpIniScanState {
	return &phpIniScanState{seenFile: map[string]bool{}}
}

// scanConfigs inventories php.ini-style files on Windows and Linux using well-known
// paths, env hints, sidecars next to discovered binaries, and web-server references.
func scanConfigs(r *Report) {
	st := newPHPIniScanState()
	for _, p := range phpIniEnvCandidates() {
		st.observePHPIniFile(r, p.path, p.source, p.class)
	}
	for _, pattern := range phpIniWellKnownPatterns() {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			st.observePHPIniFile(r, path, "well-known PHP configuration path", classifyPHPIniBasename(filepath.Base(path)))
		}
	}
	st.observeSidecarsFromEvidence(r)
	st.observeWebServerIniRefs(r)

	status := "PARTIAL"
	if st.inspected == 0 {
		status = "PARTIAL"
	}
	if st.truncated {
		status = "TRUNCATED"
		r.AddWarning("PHP configuration file count limit (200) reached")
	}
	r.AddCheck("configuration", status, fmt.Sprintf(
		"Read %d PHP configuration candidate file(s) (%d primary php.ini, %d scan-dir fragments, %d sample/template names); extracted %d whitelisted setting observations; %d correlated to nearby binary installs; settings are NOT verified as effective for any SAPI; php.ini is not proof of PHP version or active HTTP runtime; secrets and full file contents are not reported",
		st.inspected, st.primaries, st.fragments, st.templates, st.settings, st.correlated,
	))
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
			`C:\inetpub\PHP\*\php.ini`,
			`C:\Program Files\PHP\*\php.ini`,
			`C:\Program Files (x86)\PHP\*\php.ini`,
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
				st.observePHPIniFile(r, filepath.Join(dir, name), "sidecar next to discovered PHP binary", classifyPHPIniBasename(name))
			}
			// Common opt layout: binary in bin/ or sbin/, ini under ../etc/
			parent := filepath.Dir(dir)
			base := strings.ToLower(filepath.Base(dir))
			if base == "bin" || base == "sbin" || base == "nts" || base == "ts" || base == "x64" || base == "x86" {
				st.observePHPIniFile(r, filepath.Join(parent, "php.ini"), "nearby install-tree php.ini", "primary_candidate")
				st.observePHPIniFile(r, filepath.Join(parent, "etc", "php.ini"), "nearby install-tree etc/php.ini", "primary_candidate")
			}
		}
	}
}

func (st *phpIniScanState) observeWebServerIniRefs(r *Report) {
	for _, e := range r.Evidence {
		switch e.Type {
		case "configured_php_ini_path", "apache_php_handler_config", "iis_php_handler_config":
			if p := iisDetailField(e.Detail, "php_ini"); p != "" {
				st.observePHPIniFile(r, p, "web server configuration reference", classifyPHPIniBasename(filepath.Base(p)))
			}
			if e.Name == "PHPIniDir" {
				if p := iisDetailField(e.Detail, "php_ini"); p != "" {
					// PHPIniDir may be a directory
					fi, err := os.Lstat(p)
					if err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
						st.observePHPIniFile(r, filepath.Join(p, "php.ini"), "Apache PHPIniDir directory", "primary_candidate")
					}
				}
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
	// Reuse report-level dedupe via evidence scan would miss; callers typically run once.
	// Prefer attaching to a sticky state on the report via a lightweight pass:
	st.observePHPIniFile(r, path, source, classifyPHPIniBasename(filepath.Base(path)))
}

func (st *phpIniScanState) observePHPIniFile(r *Report, path, source, class string) {
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
	b, err := readPHPIniContents(path, maxPHPIniBytes)
	if err != nil {
		// Inaccessible, symlink/junction, missing, or oversized: no candidate and
		// no configuration_observation implying contents were inspected.
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
	if relatedBinary != "" {
		st.correlated++
	}
	detail := fmt.Sprintf("ini_class=%s; settings_not_verified_effective; not_php_version_authority", class)
	if relatedBinary != "" {
		detail += "; related_binary=" + relatedBinary
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
