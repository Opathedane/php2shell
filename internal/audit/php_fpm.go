package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	maxFPMPoolFiles      = 64
	maxFPMPoolBytes      = 1 << 20
	maxFPMPoolEvidence   = 128
	maxFPMIncludeDepth   = 2
)

var (
	reFPMSection = regexp.MustCompile(`(?i)^\s*\[([^\]]+)\]\s*$`)
	reFPMListen  = regexp.MustCompile(`(?i)^\s*listen\s*=\s*(.+?)\s*$`)
	reFPMInclude = regexp.MustCompile(`(?i)^\s*include\s*=\s*(.+?)\s*$`)
	reFPMComment = regexp.MustCompile(`([;#].*)$`)
)

// scanPHPFPMConfiguration invents no PHP installs; it records local pool listen endpoints
// for correlation with nginx/Apache FastCGI backends.
func scanPHPFPMConfiguration(r *Report) {
	if runtime.GOOS == "windows" {
		r.AddCheck("php_fpm_configuration", "NOT_APPLICABLE",
			"PHP-FPM pool configuration inventory is Unix-focused; Windows uses IIS FastCGI handlers")
		return
	}
	roots := accessibleFPMPoolRoots()
	if len(roots) == 0 {
		r.AddCheck("php_fpm_configuration", "NOT_APPLICABLE",
			"No well-known PHP-FPM pool configuration directories accessible")
		return
	}
	ApplyFPMPoolRootsInventory(r, roots)
}

func accessibleFPMPoolRoots() []string {
	patterns := []string{
		"/etc/php-fpm.d",
		"/usr/local/etc/php-fpm.d",
	}
	// Versioned Debian/Ubuntu pool dirs.
	if matches, err := filepath.Glob("/etc/php/*/fpm/pool.d"); err == nil {
		patterns = append(patterns, matches...)
	}
	var out []string
	seen := map[string]bool{}
	for _, raw := range patterns {
		fi, err := os.Lstat(raw)
		if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		key := normalizeInstallPath(raw)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, raw)
	}
	return out
}

// ApplyFPMPoolRootsInventory reads allowlisted PHP-FPM pool directories (and optional seed conf includes).
func ApplyFPMPoolRootsInventory(r *Report, roots []string) {
	state := &fpmScanState{
		rootSet: map[string]bool{},
	}
	for _, root := range roots {
		state.rootSet[normalizeInstallPath(root)] = true
	}
	// Seed: pool.d/*.conf and sibling php-fpm.conf include chains.
	for _, root := range roots {
		matches, _ := filepath.Glob(filepath.Join(root, "*.conf"))
		for _, path := range matches {
			state.readPoolFile(r, path, 0)
		}
		// Parent fpm dir may hold php-fpm.conf with include=pool.d/*.conf
		parent := filepath.Dir(root)
		for _, seed := range []string{
			filepath.Join(parent, "php-fpm.conf"),
			filepath.Join(root, "php-fpm.conf"),
		} {
			state.readPoolFile(r, seed, 0)
		}
	}
	status := "PARTIAL"
	if state.skippedFiles > 0 {
		status = "INCOMPLETE"
	}
	if state.truncated {
		status = "TRUNCATED"
	}
	r.AddCheck("php_fpm_configuration", status, fmt.Sprintf(
		"Read %d PHP-FPM pool/config files under %d allowlisted root(s); %d pool listen endpoints; %d skipped unreadable/symlink/oversized files; active serving runtime unverified; no php-fpm execution; includes limited to depth %d within allowlisted roots",
		state.inspectedFiles, len(roots), state.pools, state.skippedFiles, maxFPMIncludeDepth,
	))
}

type fpmScanState struct {
	rootSet        map[string]bool
	seenFile       map[string]bool
	seenSkipKey    map[string]bool
	seenPoolKey    map[string]bool
	inspectedFiles int
	skippedFiles   int
	pools          int
	truncated      bool
}

func (s *fpmScanState) initMaps() {
	if s.seenFile == nil {
		s.seenFile = map[string]bool{}
		s.seenSkipKey = map[string]bool{}
		s.seenPoolKey = map[string]bool{}
	}
}

func (s *fpmScanState) pathAllowed(path string) bool {
	norm := normalizeInstallPath(path)
	for root := range s.rootSet {
		if norm == root || strings.HasPrefix(norm, root+"/") {
			return true
		}
		// Allow php-fpm.conf in the parent of a pool.d root (Debian layout).
		parent := normalizeInstallPath(filepath.Dir(root))
		if norm == parent+"/php-fpm.conf" {
			return true
		}
	}
	return false
}

func (s *fpmScanState) readPoolFile(r *Report, path string, depth int) {
	s.initMaps()
	path = filepath.Clean(path)
	key := normalizeInstallPath(path)
	if s.seenFile[key] || s.seenSkipKey[key] {
		return
	}
	if s.inspectedFiles >= maxFPMPoolFiles {
		s.truncated = true
		return
	}
	if !s.pathAllowed(path) {
		return
	}
	b, err := ReadRegular(path, maxFPMPoolBytes)
	if err != nil {
		s.recordPoolSkip(r, path, err)
		return
	}
	s.seenFile[key] = true
	s.inspectedFiles++
	s.parseFPMFile(r, path, string(b), depth)
}

func (s *fpmScanState) recordPoolSkip(r *Report, path string, cause error) {
	s.initMaps()
	key := normalizeInstallPath(path)
	if s.seenSkipKey[key] {
		return
	}
	s.seenSkipKey[key] = true
	s.skippedFiles++
	reason := "unreadable_or_rejected"
	msg := ""
	if cause != nil {
		msg = cause.Error()
		low := strings.ToLower(msg)
		switch {
		case strings.Contains(low, "symbolic link") || strings.Contains(low, "symlink"):
			reason = "symlink_rejected"
		case strings.Contains(low, "exceeds") || strings.Contains(low, "exceeded"):
			reason = "oversized"
		case strings.Contains(low, "permission") || strings.Contains(low, "denied"):
			reason = "unreadable"
		case strings.Contains(low, "no such file"):
			s.skippedFiles--
			delete(s.seenSkipKey, key)
			return
		}
	}
	detail := fmt.Sprintf("path=%s; reason=%s; not_inspected; secrets_not_reported", path, reason)
	if msg != "" {
		detail += "; detail=" + msg
	}
	r.AddEvidence(Evidence{
		Type:           "php_fpm_config_skip",
		Name:           filepath.Base(path),
		Source:         "PHP-FPM pool configuration candidate (not inspected)",
		Location:       path,
		Detail:         detail,
		Interpretation: "CONFIG_CANDIDATE_NOT_INSPECTED",
	})
}

func (s *fpmScanState) parseFPMFile(r *Report, path, content string, depth int) {
	section := ""
	for _, raw := range strings.Split(content, "\n") {
		ln := strings.TrimSpace(reFPMComment.ReplaceAllString(raw, ""))
		if ln == "" {
			continue
		}
		if m := reFPMSection.FindStringSubmatch(ln); len(m) == 2 {
			section = strings.TrimSpace(m[1])
			continue
		}
		if m := reFPMInclude.FindStringSubmatch(ln); len(m) == 2 {
			if depth < maxFPMIncludeDepth {
				s.followInclude(r, path, strings.TrimSpace(m[1]), depth+1)
			}
			continue
		}
		if m := reFPMListen.FindStringSubmatch(ln); len(m) == 2 && section != "" && !strings.EqualFold(section, "global") {
			s.addPool(r, path, section, strings.TrimSpace(m[1]))
		}
	}
}

func (s *fpmScanState) followInclude(r *Report, fromPath, pattern string, depth int) {
	if pattern == "" || strings.Contains(pattern, "..") {
		return
	}
	base := filepath.Dir(fromPath)
	var candidates []string
	if filepath.IsAbs(pattern) {
		candidates, _ = filepath.Glob(pattern)
	} else {
		candidates, _ = filepath.Glob(filepath.Join(base, pattern))
	}
	for _, c := range candidates {
		// Expanding include into a directory: allow that directory as a transient root.
		if fi, err := os.Lstat(c); err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
			s.rootSet[normalizeInstallPath(c)] = true
			matches, _ := filepath.Glob(filepath.Join(c, "*.conf"))
			for _, m := range matches {
				s.readPoolFile(r, m, depth)
			}
			continue
		}
		s.rootSet[normalizeInstallPath(filepath.Dir(c))] = true
		s.readPoolFile(r, c, depth)
	}
}

func (s *fpmScanState) addPool(r *Report, configPath, poolName, listen string) {
	s.initMaps()
	if s.pools >= maxFPMPoolEvidence {
		s.truncated = true
		return
	}
	listen = strings.Trim(listen, `"'`)
	backend := normalizeFPMListen(listen)
	key := strings.ToLower(poolName) + "\x00" + backend
	if s.seenPoolKey[key] {
		return
	}
	s.seenPoolKey[key] = true
	s.pools++
	detail := fmt.Sprintf("pool=%s; listen=%s; scope=local_candidate; not_verified_serving_runtime", poolName, backend)
	r.AddEvidence(Evidence{
		Type:           "php_fpm_pool_config",
		Name:           poolName,
		Source:         "PHP-FPM pool configuration (static text)",
		Location:       configPath,
		Detail:         detail,
		Interpretation: "CONFIGURED_FPM_POOL_NOT_VERIFIED_SERVING_RUNTIME",
	})
}

func normalizeFPMListen(listen string) string {
	listen = strings.TrimSpace(listen)
	if strings.HasPrefix(listen, "/") || strings.HasPrefix(listen, "unix:") {
		path := strings.TrimPrefix(listen, "unix:")
		return "unix:" + filepath.Clean(path)
	}
	// host:port or port-only (defaults to *:port → treat as local bind)
	if !strings.Contains(listen, ":") {
		return "127.0.0.1:" + listen
	}
	host, port, kind := classifyNginxPassTarget(listen)
	if kind == "local_tcp" || isLocalPHPBackendHost(host) || host == "*" || host == "0.0.0.0" {
		if host == "*" || host == "0.0.0.0" {
			host = "127.0.0.1"
		}
		return host + ":" + port
	}
	if kind == "remote" {
		return host + ":" + port
	}
	return listen
}

// CorrelateNginxFPMBackends annotates nginx local FastCGI handlers when a matching
// PHP-FPM pool listen endpoint was inventoried. Never upgrades EffectiveWebRuntime.
func CorrelateNginxFPMBackends(r *Report) {
	if r == nil {
		return
	}
	pools := map[string]string{} // backend -> pool name
	for _, e := range r.Evidence {
		if e.Type != "php_fpm_pool_config" {
			continue
		}
		backend := fpmListenFromDetail(e.Detail)
		if backend != "" {
			pools[backend] = e.Name
		}
	}
	if len(pools) == 0 {
		return
	}
	for i := range r.Evidence {
		e := &r.Evidence[i]
		if e.Type != "nginx_php_handler_config" {
			continue
		}
		if !strings.Contains(e.Detail, "scope=local_candidate") {
			continue
		}
		backend := nginxBackendFromDetail(e.Detail)
		if backend == "" {
			continue
		}
		pool, ok := pools[backend]
		if !ok {
			// Try unix path normalization variants.
			pool, ok = pools[normalizeFPMListen(strings.TrimPrefix(backend, "unix:"))]
		}
		if !ok {
			continue
		}
		if strings.Contains(e.Detail, "correlated_fpm_pool=") {
			continue
		}
		e.Detail += fmt.Sprintf("; correlated_fpm_pool=%s; correlation=listen_endpoint_match_not_runtime_attestation", pool)
	}
}

func fpmListenFromDetail(detail string) string {
	for _, part := range strings.Split(detail, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "listen=") {
			return strings.TrimSpace(strings.TrimPrefix(part, "listen="))
		}
	}
	return ""
}

func nginxBackendFromDetail(detail string) string {
	for _, part := range strings.Split(detail, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "backend=") {
			return strings.TrimSpace(strings.TrimPrefix(part, "backend="))
		}
	}
	return ""
}

// ParseFPMPoolsForTest exposes pool parsing against explicit roots for regression tests.
func ParseFPMPoolsForTest(r *Report, roots ...string) {
	ApplyFPMPoolRootsInventory(r, roots)
}
