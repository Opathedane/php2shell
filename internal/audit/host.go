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
var iniSetting = regexp.MustCompile(`(?i)^\s*(session\.upload_progress\.enabled|expose_php)\s*=\s*([^\r\n;#]+)`)

func ScanHost(r *Report, webroot string, docker bool) {
	scanBinaries(r)
	scanPackages(r)
	scanProcesses(r)
	scanConfigs(r)
	scanWindowsSpecific(r)
	if webroot != "" {
		scanWebRoot(r, webroot)
	} else {
		r.AddCheck("webroot", "NOT_REQUESTED", "Supply --webroot PATH to inspect file names beneath an authorized document root; no PHP files are executed")
	}
	if docker {
		scanDocker(r)
	} else {
		r.AddCheck("docker", "NOT_REQUESTED", "Supply --docker for local privileged Docker socket metadata only; no docker exec")
	}
	r.AddCheck("active_http_sapi_verification", "NOT_IMPLEMENTED", "Package/process/path observations cannot verify the PHP runtime actually serving HTTP traffic")
	r.AddCheck("official_php2shell_version_rules", "NOT_CONFIGURED", "No upstream fix or CVE vulnerability rules applied; vendor backports and official advisories need manual verification")
	r.AddCheck("php2shell_specific_compromise_detection", "NOT_VERIFIED", "No validated CVE-specific indicator pack is provided. Generic signed IOC matching cannot prove exploitation or exclude compromise")
}

func scanBinaries(r *Report) {
	var paths []string
	if runtime.GOOS == "windows" {
		paths = []string{`C:\php\php.exe`, `C:\php\php-cgi.exe`, `C:\xampp\php\php.exe`, `C:\xampp\php\php-cgi.exe`, `C:\inetpub\PHP\*\php-cgi.exe`, `C:\Program Files\PHP\*\php.exe`}
	} else {
		paths = []string{`/usr/bin/php*`, `/usr/sbin/php-fpm*`, `/usr/local/bin/php*`, `/usr/local/sbin/php-fpm*`, `/opt/plesk/php/*/bin/php*`, `/opt/plesk/php/*/sbin/php-fpm*`, `/opt/remi/php*/root/usr/bin/php*`, `/opt/cpanel/ea-php*/root/usr/bin/php*`, `/etc/alternatives/php`}
	}
	found := 0
	seen := map[string]bool{}
	for _, pattern := range paths {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			if found >= 400 {
				r.AddWarning("PHP binary discovery limited to 400 results")
				r.AddCheck("binary_paths", "TRUNCATED", "Path discovery limit reached; binaries not executed")
				return
			}
			if !phpBin.MatchString(filepath.Base(path)) || seen[path] {
				continue
			}
			fi, err := os.Stat(path)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			seen[path] = true
			found++
			r.AddEvidence(Evidence{Type: "binary_path", Name: filepath.Base(path), Source: "well-known path metadata", Location: path, Interpretation: "PRESENT_VERSION_UNKNOWN_NOT_RUNTIME_VERIFIED"})
		}
	}
	r.AddCheck("binary_paths", "PARTIAL", fmt.Sprintf("Found %d PHP-like binary paths; only common installation paths checked, no binaries executed", found))
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
			ver := versionNumber.FindString(fields["Version"])
			r.AddEvidence(Evidence{Type: "installed_package", Name: name, Version: ver, Source: "dpkg installed package metadata", Location: dpkgPath, Detail: "Package version: " + fields["Version"], Interpretation: "PACKAGE_VERSION_ONLY_VENDOR_BACKPORT_AND_ACTIVE_SAPI_UNVERIFIED"})
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
			r.AddEvidence(Evidence{Type: "installed_package", Name: fields["P"], Version: versionNumber.FindString(fields["V"]), Source: "apk installed package metadata", Location: apkPath, Detail: "Package version: " + fields["V"], Interpretation: "PACKAGE_VERSION_ONLY_VENDOR_BACKPORT_AND_ACTIVE_SAPI_UNVERIFIED"})
			found++
		}
	} else if !os.IsNotExist(err) {
		r.AddWarning("Cannot read apk status database: " + err.Error())
	}
	if supported == 0 {
		r.AddCheck("packages", "UNAVAILABLE", "No readable dpkg/apk database; RPM/pacman/vendor packages not inventoried")
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
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := ReadRegular(filepath.Join("/proc", e.Name(), "comm"), 4096)
		if err != nil {
			missing++
			continue
		}
		name := strings.TrimSpace(string(b))
		if !strings.HasPrefix(strings.ToLower(name), "php") && !strings.HasPrefix(strings.ToLower(name), "lsphp") {
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

func scanConfigs(r *Report) {
	if runtime.GOOS == "windows" {
		r.AddCheck("configuration", "NOT_SUPPORTED", "Windows/IIS PHP configuration not yet inventoried; no effective-runtime settings inferred")
		return
	}
	patterns := []string{"/etc/php/*/fpm/php.ini", "/etc/php/*/apache2/php.ini", "/etc/php/*/cgi/php.ini", "/etc/php/*/cli/php.ini", "/etc/php.ini", "/etc/php-fpm.d/*.conf", "/etc/php/*/fpm/pool.d/*.conf", "/usr/local/etc/php/php.ini", "/usr/local/etc/php/conf.d/*.ini", "/opt/plesk/php/*/etc/php.ini"}
	inspected, seen := 0, map[string]bool{}
	truncated := false
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			if seen[path] {
				continue
			}
			seen[path] = true
			if inspected >= 200 {
				truncated = true
				break
			}
			b, err := ReadRegular(path, 2<<20)
			if err != nil {
				r.AddWarning("Configuration file skipped: " + path + " (" + err.Error() + ")")
				continue
			}
			inspected++
			for _, ln := range strings.Split(string(b), "\n") {
				val := strings.TrimSpace(ln)
				if strings.HasPrefix(val, ";") || strings.HasPrefix(val, "#") {
					continue
				}
				m := iniSetting.FindStringSubmatch(ln)
				if len(m) == 3 {
					r.AddEvidence(Evidence{Type: "configuration_observation", Name: strings.ToLower(m[1]), Source: "static PHP configuration text", Location: path, Detail: strings.TrimSpace(m[2]), Interpretation: "OBSERVED_NOT_EFFECTIVE_SETTING_NOT_VERIFIED_MITIGATION"})
				}
			}
		}
	}
	status := "PARTIAL"
	if truncated {
		status = "TRUNCATED"
		r.AddWarning("Configuration file count limit (200) reached")
	}
	r.AddCheck("configuration", status, fmt.Sprintf("Read %d static config files; effective per-SAPI/virtual-host settings not verified", inspected))
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
