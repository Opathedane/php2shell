package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var phpBin = regexp.MustCompile(`(?i)^(?:php(?:-cgi|-fpm)?[0-9]*(?:\.[0-9]+)?|php[0-9]+(?:\.[0-9]+)?(?:-fpm|-cgi)|lsphp[0-9]*)(?:\.exe)?$`)
var pkgPHP = regexp.MustCompile(`(?i)^(?:php[0-9.]*(?:-(?:cli|fpm|cgi|common|apache2|mysql|opcache))?|libapache2-mod-php[0-9.]*|php[0-9]{2}(?:-(?:cli|fpm|cgi|apache2|common))?|ea-php[0-9]+(?:-php(?:-fpm|-cgi|-cli)?)?|lsphp[0-9]+(?:-common)?)$`)
var versionNumber = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)
var iniSetting = regexp.MustCompile(`(?i)^\s*(session\.upload_progress\.enabled|session\.serialize_handler|expose_php|memory_limit|post_max_size|upload_max_filesize|fatal_error_backtraces)\s*=\s*([^\r\n;#]+)`)

func ScanHost(r *Report, opts HostScanOptions) {
	deepOutcomes := scanBinaries(r, opts)
	scanPackages(r)
	scanProcesses(r)
	// Web-server config first so PHPIniDir / IIS -c paths can feed php.ini inventory.
	scanApacheConfiguration(r)
	scanNginxConfiguration(r)
	scanPHPFPMConfiguration(r)
	CorrelateNginxFPMBackends(r)
	scanWindowsSpecific(r)
	scanConfigs(r, opts, deepOutcomes)
	if opts.Webroot != "" {
		scanWebRoot(r, opts.Webroot)
	} else {
		r.AddCheck("webroot", "NOT_REQUESTED", "Supply --webroot PATH to inspect file names beneath an authorized document root; no PHP files are executed")
	}
	if opts.Docker {
		scanDocker(r)
	} else {
		r.AddCheck("docker", "NOT_REQUESTED", "Supply --docker for local privileged Docker socket metadata only; no docker exec")
	}
	r.AddCheck("active_http_sapi_verification", "NOT_IMPLEMENTED", "Package/process/path observations cannot verify the PHP runtime actually serving HTTP traffic")
	r.AddCheck("php2shell_specific_compromise_detection", "NOT_VERIFIED", "No validated CVE-specific indicator pack is provided. Generic signed IOC matching cannot prove exploitation or exclude compromise")
}

func scanBinaries(r *Report, opts HostScanOptions) []deepDiscoverOutcome {
	found := 0
	seen := map[string]bool{}
	var deepOutcomes []deepDiscoverOutcome
	addPath := func(path, source string) bool {
		if found >= maxWindowsPHPDiscover {
			r.AddWarning("PHP binary discovery limited to 400 results")
			r.AddCheck("binary_paths", "TRUNCATED", "Path discovery limit reached; binaries not executed")
			return false
		}
		path = filepath.Clean(path)
		if !phpBin.MatchString(filepath.Base(path)) {
			return true
		}
		// Windows: keep rejecting file symlinks (isSafeRegularFile). Unix: resolve a
		// bounded file-symlink chain to a regular file so Homebrew/alternatives aliases
		// are not false negatives. Deduplicate by resolved path. Relevant resolve gaps
		// (access / hop budget) are recorded so coverage cannot claim "no PHP".
		inspectPath := path
		reportName := filepath.Base(path)
		reportSource := source
		if runtime.GOOS == "windows" {
			if !isSafeRegularFile(path) {
				return true
			}
		} else {
			res, err := resolvePHPBinCandidate(path)
			if err != nil {
				gap := classifyPHPBinResolveErr(err)
				if gap == phpBinResolveGapAccess || gap == phpBinResolveGapBound {
					ukey := "unresolved:" + normalizeInstallPath(path)
					if !seen[ukey] {
						seen[ukey] = true
						found++
						recordUnresolvedPHPBinCandidate(r, path, source, phpBinResolveGapReason(gap, err))
					}
				}
				return true
			}
			inspectPath = res.Resolved
			reportName = filepath.Base(res.Original)
			if res.ViaSymlink {
				reportSource = fmt.Sprintf("%s (via symlink %s)", source, res.Original)
			}
		}
		key := normalizeInstallPath(inspectPath)
		if seen[key] {
			if runtime.GOOS != "windows" && normalizeInstallPath(path) != key {
				noteResolvedPHPBinAliasPath(r, inspectPath, path)
			}
			return true
		}
		seen[key] = true
		found++
		AddBinaryVersionEvidence(r, inspectPath, reportName, reportSource)
		return true
	}

	if runtime.GOOS == "windows" {
		candidates, warnings := collectWindowsPHPBinaryCandidates(maxWindowsPHPDiscover)
		for _, w := range warnings {
			r.AddWarning(w)
		}
		for _, path := range candidates {
			source := "Windows well-known/LocalAppData/PATH static binary inspection"
			if strings.Contains(strings.ToLower(path), `\appdata\local\programs\php\`) {
				source = "Windows LocalAppData Programs\\PHP static binary inspection"
			} else if onPATHDirectory(path) {
				source = "Windows PATH directory static binary inspection"
			}
			if !addPath(path, source) {
				return deepOutcomes
			}
		}
	} else {
		for _, pattern := range linuxWellKnownPHPGlobs() {
			matches, _ := filepath.Glob(pattern)
			for _, path := range matches {
				if !addPath(path, "well-known path static binary inspection") {
					return deepOutcomes
				}
			}
		}
		remain := maxWindowsPHPDiscover - found
		if remain > 0 {
			for _, path := range discoverPHPBinsFromPATHEnv(os.Getenv("PATH"), remain) {
				if !addPath(path, "PATH directory static binary inspection") {
					return deepOutcomes
				}
			}
		}
	}

	// Operator-authorized custom roots: bounded binary walk (same caps as Programs\PHP).
	nRoot := 0
	for _, raw := range opts.ConfigRoots {
		if nRoot >= maxOperatorConfigRoots {
			r.AddWarning(fmt.Sprintf("Operator --config-root binary discovery limited to %d directories", maxOperatorConfigRoots))
			break
		}
		root := filepath.Clean(strings.TrimSpace(raw))
		if root == "" || root == "." {
			continue
		}
		nRoot++
		remain := maxWindowsPHPDiscover - found
		if remain <= 0 {
			break
		}
		foundUnder, warn := discoverPHPBinsUnderProgramsPHP(root, remain)
		if warn != "" {
			r.AddWarning("Operator --config-root " + root + ": " + warn)
		}
		for _, path := range foundUnder {
			if !addPath(path, "operator --config-root static binary inspection") {
				return deepOutcomes
			}
		}
	}

	// Optional Deep Discovery (--deep-root): recursive under explicitly authorized roots only.
	deepTruncated := false
	deepRootsUsed := 0
	if len(opts.DeepRoots) > 0 {
		deadline := time.Now().Add(deepDurationCap)
		nDeep := 0
		for _, raw := range opts.DeepRoots {
			if nDeep >= maxDeepRoots {
				r.AddWarning(fmt.Sprintf("Operator --deep-root limited to %d directories", maxDeepRoots))
				deepTruncated = true
				break
			}
			root, verr := validateDeepRoot(raw)
			if verr != nil {
				r.AddWarning(verr.Error())
				r.AddCheck("deep_discovery", "INCOMPLETE", verr.Error())
				deepTruncated = true
				continue
			}
			nDeep++
			deepRootsUsed++
			remain := maxWindowsPHPDiscover - found
			if remain <= 0 {
				r.AddWarning("Operator --deep-root binary discovery skipped: global binary limit already reached")
				deepTruncated = true
				break
			}
			outcome := deepDiscoverUnderRoot(root, deadline, remain, maxDeepIniCandidates)
			deepOutcomes = append(deepOutcomes, outcome)
			r.AddEvidence(Evidence{
				Type:           "deep_discovery_coverage",
				Name:           "deep-root",
				Source:         "operator --deep-root",
				Location:       outcome.Root,
				Detail:         deepTruncationDetail(outcome),
				Interpretation: "BOUNDED_OPERATOR_AUTHORIZED_DEEP_DISCOVERY_NOT_COMPLETE_HOST_COVERAGE",
			})
			if outcome.Truncated {
				deepTruncated = true
				r.AddWarning("Operator --deep-root truncated: " + deepTruncationDetail(outcome))
			} else if outcome.PermissionErrors > 0 {
				r.AddWarning(fmt.Sprintf("Operator --deep-root %s: %d permission error(s) during walk; inventory may be incomplete", outcome.Root, outcome.PermissionErrors))
				deepTruncated = true
			}
			for _, path := range outcome.Binaries {
				if !addPath(path, "operator --deep-root static binary inspection") {
					deepTruncated = true
					break
				}
			}
			if found >= maxWindowsPHPDiscover {
				break
			}
			if time.Now().After(deadline) {
				deepTruncated = true
				r.AddWarning(fmt.Sprintf("Operator --deep-root wall-clock budget (%s) exhausted", deepDurationCap))
				break
			}
		}
		status := "PARTIAL"
		detail := fmt.Sprintf("Deep Discovery inspected %d authorized root(s); binaries discovered via --deep-root use weaker evidence provenance than well-known/PATH/IIS sources; never executes PHP; not complete host coverage", deepRootsUsed)
		if deepTruncated {
			status = "TRUNCATED"
			detail += "; one or more roots stopped early (entry/depth/binary/duration/permission limits) — inventory remains incomplete"
		}
		r.AddCheck("deep_discovery", status, detail)
	}

	versioned, inferred, partialInspect := 0, 0, 0
	distinctDirs := map[string]struct{}{}
	for _, e := range r.Evidence {
		switch e.Type {
		case "binary_static_version":
			versioned++
			distinctDirs[normalizeInstallPath(filepath.Dir(e.Location))] = struct{}{}
			if strings.Contains(e.Detail, "inspect_coverage=partial") {
				partialInspect++
			}
		case "binary_path_inferred_version":
			inferred++
			distinctDirs[normalizeInstallPath(filepath.Dir(e.Location))] = struct{}{}
		case "binary_path":
			distinctDirs[normalizeInstallPath(filepath.Dir(e.Location))] = struct{}{}
		}
	}
	status := "PARTIAL"
	if deepTruncated {
		status = "TRUNCATED"
	}
	detail := fmt.Sprintf("Found %d PHP-like binary paths across %d install director(ies) (%d with verified static version markers, %d path-inferred); no binaries executed", found, len(distinctDirs), versioned, inferred)
	if runtime.GOOS == "windows" {
		detail += `; searched well-known dirs, %LOCALAPPDATA%\Programs\PHP (bounded junction resolve), all eligible PATH entries (not only the first match), IIS/Apache handler follow-up when present, operator --config-root, and optional --deep-root`
	} else {
		detail += "; common Unix paths, all eligible PATH entries, web-server handler follow-up when present, operator --config-root, and optional --deep-root"
	}
	detail += "; discovery scope is bounded — not complete host coverage; unsearched locations may contain additional PHP installations; absence of findings is not proof PHP is absent"
	if partialInspect > 0 {
		detail += fmt.Sprintf("; %d oversized/partial binary inspections (see warnings)", partialInspect)
	}
	if found == 0 {
		detail += "; inventory may miss per-user or nonstandard installs"
		r.AddWarning("No PHP binaries discovered in scanned locations; this does not prove PHP is absent on the host")
	}
	if len(distinctDirs) > 1 {
		detail += "; multiple install directories retained as separate records unless a current/alias path is content-corroborated"
	}
	if deepRootsUsed > 0 {
		detail += fmt.Sprintf("; Deep Discovery roots authorized=%d", deepRootsUsed)
	}
	r.AddCheck("binary_paths", status, detail)
	return deepOutcomes
}

func onPATHDirectory(binPath string) bool {
	dir := normalizeInstallPath(filepath.Clean(filepath.Dir(binPath)))
	sep := string(os.PathListSeparator)
	n := 0
	for _, p := range strings.Split(os.Getenv("PATH"), sep) {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n++
		if n > maxPATHDirInspect {
			break
		}
		if normalizeInstallPath(filepath.Clean(p)) == dir {
			return true
		}
		if plan, ok := planPATHDirInspect(p); ok && normalizeInstallPath(plan.Inspect) == dir {
			return true
		}
	}
	return false
}

func scanPackages(r *Report) {
	if runtime.GOOS != "linux" {
		r.AddCheck("packages", "NOT_SUPPORTED", "No passive native package database reader for this OS; no package commands executed")
		return
	}
	dpkgPath := "/var/lib/dpkg/status"
	apkPath := "/lib/apk/db/installed"
	found := 0
	supported := 0
	if b, err := ReadRegular(dpkgPath, 32<<20); err == nil {
		supported++
		for _, stanza := range bytes.Split(b, []byte("\n\n")) {
			fields := map[string]string{}
			for _, raw := range bytes.Split(stanza, []byte("\n")) {
				line := string(raw)
				if strings.HasPrefix(line, " ") {
					continue
				}
				key, val, ok := strings.Cut(line, ": ")
				if ok && (key == "Package" || key == "Status" || key == "Version") {
					fields[key] = val
				}
			}
			name := fields["Package"]
			if fields["Status"] != "install ok installed" || !pkgPHP.MatchString(name) {
				continue
			}
			if found >= 1000 {
				r.AddWarning("Package result count truncated at 1000")
				break
			}
			ver := PackagePHPVersion(name, fields["Version"])
			interp := "PACKAGE_VERSION_ONLY_VENDOR_BACKPORT_AND_ACTIVE_SAPI_UNVERIFIED"
			if ver == "" && fields["Version"] != "" {
				interp = "PACKAGE_METADATA_ONLY_NOT_PHP_RUNTIME_VERSION"
			}
			r.AddEvidence(Evidence{Type: "installed_package", Name: name, Version: ver, Source: "dpkg installed package metadata", Location: dpkgPath, Detail: "Package version: " + fields["Version"], Interpretation: interp})
			found++
		}
	} else if !os.IsNotExist(err) {
		r.AddWarning("Cannot read dpkg status database: " + err.Error())
	}
	if b, err := ReadRegular(apkPath, 24<<20); err == nil {
		supported++
		for _, stanza := range bytes.Split(b, []byte("\n\n")) {
			fields := map[string]string{}
			for _, raw := range bytes.Split(stanza, []byte("\n")) {
				s := string(raw)
				if len(s) > 2 && s[1] == ':' && (s[0] == 'P' || s[0] == 'V') {
					fields[s[:1]] = s[2:]
				}
			}
			if !pkgPHP.MatchString(fields["P"]) {
				continue
			}
			if found >= 1000 {
				r.AddWarning("Package result count truncated at 1000")
				break
			}
			ver := PackagePHPVersion(fields["P"], fields["V"])
			interp := "PACKAGE_VERSION_ONLY_VENDOR_BACKPORT_AND_ACTIVE_SAPI_UNVERIFIED"
			if ver == "" && fields["V"] != "" {
				interp = "PACKAGE_METADATA_ONLY_NOT_PHP_RUNTIME_VERSION"
			}
			r.AddEvidence(Evidence{Type: "installed_package", Name: fields["P"], Version: ver, Source: "apk installed package metadata", Location: apkPath, Detail: "Package version: " + fields["V"], Interpretation: interp})
			found++
		}
	} else if !os.IsNotExist(err) {
		r.AddWarning("Cannot read apk status database: " + err.Error())
	}
	if supported == 0 {
		// Not UNAVAILABLE: absence of dpkg/apk on RPM/other distros is expected coverage limit,
		// not a failed requested input — must not force exit code 2 on every RHEL/host without dpkg.
		r.AddCheck("packages", "NOT_SUPPORTED", "No readable dpkg/apk database on this host. RPM/yum/dnf/pacman package metadata is not inventoried in this release — binary/PATH/well-known discovery still runs; treat package coverage as incomplete on RHEL/CentOS/Fedora/SLES and verify vendor advisories separately")
	} else {
		r.AddCheck("packages", "PARTIAL", fmt.Sprintf("Read %d supported package databases; %d PHP-related packages; RPM/pacman and vendor alternatives not covered", supported, found))
	}
}

func scanProcesses(r *Report) {
	if runtime.GOOS != "linux" {
		r.AddCheck("processes", "NOT_SUPPORTED", "Linux /proc is required; no commands executed")
		return
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		r.AddCheck("processes", "UNAVAILABLE", "Cannot list /proc: "+err.Error())
		return
	}
	found, missing := 0, 0
	selfPID := scannerSelfPID()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if pid == selfPID {
			continue
		}
		b, err := ReadRegular(filepath.Join("/proc", e.Name(), "comm"), 4096)
		if err != nil {
			missing++
			continue
		}
		name := strings.TrimSpace(string(b))
		if !IsPHPRuntimeProcessName(name) {
			continue
		}
		if found >= 500 {
			r.AddWarning("Process result count truncated at 500")
			break
		}
		found++
		r.AddEvidence(Evidence{Type: "running_process", Name: name, Source: "/proc/PID/comm snapshot", Location: "PID=" + e.Name(), Interpretation: "PROCESS_NAME_ONLY_ACTIVE_HTTP_SAPI_AND_PATCH_STATUS_UNVERIFIED"})
	}
	r.AddCheck("processes", "PARTIAL", fmt.Sprintf("Observed %d matching process names; %d entries unreadable/disappeared; mod_php inside Apache and containers may not appear", found, missing))
}

func scanWebRoot(r *Report, root string) {
	fi, err := os.Lstat(root)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		r.AddCheck("webroot", "UNAVAILABLE", "No accessible regular directory at supplied --webroot")
		return
	}
	seen, phpFiles, errorsCount := 0, 0, 0
	samples := 0
	truncated := false
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			errorsCount++
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		seen++
		if seen > 25000 {
			truncated = true
			return filepath.SkipAll
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(d.Name()), ".php") {
			phpFiles++
			if samples < 25 {
				r.AddEvidence(Evidence{Type: "php_webroot_filename", Name: d.Name(), Source: "authorized webroot filename metadata", Location: path, Interpretation: "FILE_PRESENT_NOT_PROOF_IT_IS_SERVED_OR_VULNERABLE"})
				samples++
			}
		}
		return nil
	})
	if err != nil {
		errorsCount++
	}
	status := "PARTIAL"
	if truncated {
		status = "TRUNCATED"
		r.AddWarning("Webroot scan limited to 25,000 entries")
	}
	r.AddCheck("webroot", status, fmt.Sprintf("Checked %d entries, saw %d .php files (up to 25 shown), %d inaccessible entries; HTTP exposure not confirmed", seen, phpFiles, errorsCount))
}

func scanDocker(r *Report) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		r.AddCheck("docker", "NOT_SUPPORTED", "Optional Docker metadata requires Unix local socket")
		return
	}
	socket := "/var/run/docker.sock"
	fi, err := os.Lstat(socket)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		r.AddCheck("docker", "UNAVAILABLE", "No Docker Unix socket found; do not enable daemon access solely for this scan")
		return
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
	resp, err := client.Get("http://docker-local/containers/json?all=0")
	if err != nil {
		r.AddCheck("docker", "UNAVAILABLE", "Cannot read Docker metadata (socket may require privileged permissions): "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		r.AddCheck("docker", "UNAVAILABLE", fmt.Sprintf("Docker API status %d", resp.StatusCode))
		return
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20+1))
	if err != nil || len(b) > 2<<20 {
		r.AddCheck("docker", "INCOMPLETE", "Docker response unavailable/over 2MiB")
		return
	}
	var containers []struct {
		Names []string `json:"Names"`
		Image string   `json:"Image"`
		ID    string   `json:"Id"`
	}
	if json.Unmarshal(b, &containers) != nil {
		r.AddCheck("docker", "INCOMPLETE", "Invalid Docker JSON metadata")
		return
	}
	for i, c := range containers {
		if i >= 200 {
			r.AddWarning("Docker container results capped at 200")
			break
		}
		name := strings.Join(c.Names, ",")
		r.AddEvidence(Evidence{Type: "docker_container_metadata", Name: name, Source: "authorized local Docker read-only GET", Location: c.ID, Detail: c.Image, Interpretation: "IMAGE_NAME_ONLY_NO_RUNTIME_OR_PATCH_VERIFICATION"})
	}
	r.AddCheck("docker", "PARTIAL", fmt.Sprintf("Read metadata for %d running containers (first 200 shown); images and actual installed PHP not inspected", len(containers)))
}
