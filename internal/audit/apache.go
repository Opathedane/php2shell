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
	maxApacheConfigFiles     = 64
	maxApacheConfigBytes     = 2 << 20
	maxApacheVHostEvidence   = 128
	maxApacheHandlerEvidence = 128
	maxApacheIncludeDepth    = 1
)

// Well-known Apache HTTP Server config roots only (no filesystem-wide search).
var apacheConfigRoots = []string{
	"/etc/apache2",
	"/etc/httpd",
	"/usr/local/apache2/conf",
	"/usr/local/etc/httpd",
	"/usr/local/etc/apache24",
	`C:\Apache24\conf`,
	`C:\Apache2\conf`,
	`C:\Program Files\Apache Software Foundation\Apache2.4\conf`,
	`C:\Program Files (x86)\Apache Software Foundation\Apache2.4\conf`,
}

var (
	reApacheDirective = regexp.MustCompile(`(?i)^\s*(DocumentRoot|ServerName|ServerAlias|LoadModule|SetHandler|AddHandler|Action|ProxyPassMatch|ProxyPass|FcgidWrapper|Include|IncludeOptional|PHPIniDir)\s+(.+?)\s*$`)
	reApacheVHostOpen = regexp.MustCompile(`(?i)^\s*<VirtualHost\b([^>]*)>`)
	reApacheVHostClose = regexp.MustCompile(`(?i)^\s*</VirtualHost\s*>`)
	reApacheComment    = regexp.MustCompile(`#.*$`)
	rePHPModuleName    = regexp.MustCompile(`(?i)^php\d*_module$|^php_module$`)
	rePHPHandlerToken  = regexp.MustCompile(`(?i)(?:application/x-httpd-php|proxy:fcgi:|proxy:unix:|fcgi://|php-fpm|php-cgi|libphp|\.php\b)`)
	reRemoteFCGI       = regexp.MustCompile(`(?i)(?:fcgi|proxy:fcgi)://([^/\s|:]+)(?::(\d+))?`)
	reUnixFCGI         = regexp.MustCompile(`(?i)(?:proxy:)?unix:([^\s|]+)\|?`)
	reQuotedArg        = regexp.MustCompile(`^"([^"]*)"$|^'([^']*)'$`)
)

// scanApacheConfiguration performs bounded, passive Apache HTTP Server config inventory.
// It does not scan Tomcat/Catalina, execute binaries, follow unrestricted Includes, or probe networks.
func scanApacheConfiguration(r *Report) {
	roots := accessibleApacheRoots()
	if len(roots) == 0 {
		r.AddCheck("apache_configuration", "NOT_APPLICABLE",
			"No well-known Apache HTTP Server configuration directories accessible; Tomcat/Java containers are out of scope and are not treated as PHP evidence")
		return
	}
	ApplyApacheRootsInventory(r, roots)
}

func accessibleApacheRoots() []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range apacheConfigRoots {
		resolved := raw
		if runtime.GOOS != "windows" && isWindowsDrivePath(strings.ReplaceAll(raw, `\`, `/`)) {
			continue
		}
		if runtime.GOOS == "windows" {
			resolved = filepath.Clean(os.ExpandEnv(raw))
		}
		fi, err := os.Lstat(resolved)
		if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		key := normalizeInstallPath(resolved)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, resolved)
	}
	return out
}

// ApplyApacheRootsInventory reads allowlisted Apache config trees and records PHP-related
// VirtualHost / handler / module evidence. Intended for production ScanHost and tests.
func ApplyApacheRootsInventory(r *Report, roots []string) {
	state := &apacheScanState{
		roots:    roots,
		rootSet:  map[string]bool{},
		seenFile: map[string]bool{},
	}
	for _, root := range roots {
		state.rootSet[normalizeInstallPath(root)] = true
	}

	for _, root := range roots {
		for _, seed := range apacheSeedPatterns(root) {
			matches, _ := filepath.Glob(seed)
			for _, path := range matches {
				state.readConfigFile(r, path, 0)
			}
		}
	}

	status := "PARTIAL"
	if state.inaccessibleBinaries > 0 || state.remoteBackends > 0 {
		// Inaccessible local binaries or remote FPM/proxy backends cannot be fully assessed as local installs.
		status = "INCOMPLETE"
	}
	if state.truncated {
		status = "TRUNCATED"
	}
	r.AddCheck("apache_configuration", status, fmt.Sprintf(
		"Read %d Apache config files under %d well-known root(s); %d VirtualHost/DocumentRoot rows; %d PHP-related handler/proxy rows; %d mod_php LoadModule rows; %d remote PHP backends (not local installs); %d local handler binaries version-inspected; %d inaccessible; active serving runtime unverified; Apache merge/IfModule/.htaccess not fully simulated; Includes limited to depth %d within allowlisted roots; Tomcat not scanned; .php filenames require explicit --webroot",
		state.inspectedFiles, len(roots), state.vhosts, state.handlers, state.modules, state.remoteBackends, state.inspectedBinaries, state.inaccessibleBinaries, maxApacheIncludeDepth,
	))
}

type apacheScanState struct {
	roots                 []string
	rootSet               map[string]bool
	seenFile              map[string]bool
	inspectedFiles        int
	vhosts                int
	handlers              int
	modules               int
	remoteBackends        int
	inspectedBinaries     int
	inaccessibleBinaries  int
	localHandlers         int
	truncated              bool
	seenHandlerKey        map[string]bool
	seenVHostKey          map[string]bool
	seenModuleKey         map[string]bool
	seenRemoteKey         map[string]bool
	seenExe               map[string]bool
}

func (s *apacheScanState) initMaps() {
	if s.seenHandlerKey == nil {
		s.seenHandlerKey = map[string]bool{}
		s.seenVHostKey = map[string]bool{}
		s.seenModuleKey = map[string]bool{}
		s.seenRemoteKey = map[string]bool{}
		s.seenExe = map[string]bool{}
	}
}

func apacheSeedPatterns(root string) []string {
	return []string{
		filepath.Join(root, "apache2.conf"),
		filepath.Join(root, "httpd.conf"),
		filepath.Join(root, "httpd-vhosts.conf"),
		filepath.Join(root, "extra", "httpd-vhosts.conf"),
		filepath.Join(root, "sites-enabled", "*.conf"),
		filepath.Join(root, "sites-available", "*.conf"),
		filepath.Join(root, "conf.d", "*.conf"),
		filepath.Join(root, "conf.modules.d", "*.conf"),
		filepath.Join(root, "mods-enabled", "php*.conf"),
		filepath.Join(root, "mods-enabled", "php*.load"),
		filepath.Join(root, "mods-available", "php*.conf"),
		filepath.Join(root, "mods-available", "php*.load"),
	}
}

func (s *apacheScanState) readConfigFile(r *Report, path string, depth int) {
	s.initMaps()
	path = filepath.Clean(path)
	key := normalizeInstallPath(path)
	if s.seenFile[key] {
		return
	}
	if s.inspectedFiles >= maxApacheConfigFiles {
		s.truncated = true
		return
	}
	if !s.pathAllowed(path) {
		return
	}
	b, err := ReadRegular(path, maxApacheConfigBytes)
	if err != nil {
		return
	}
	s.seenFile[key] = true
	s.inspectedFiles++
	s.parseApacheConfig(r, path, string(b), depth)
}

func (s *apacheScanState) pathAllowed(path string) bool {
	norm := normalizeInstallPath(path)
	for root := range s.rootSet {
		if norm == root || strings.HasPrefix(norm, root+"/") {
			return true
		}
	}
	return false
}

func (s *apacheScanState) parseApacheConfig(r *Report, path, content string, depth int) {
	lines := flattenApacheLines(content)
	var (
		inVHost bool
		vServer string
		vRoot   string
		vAddr   string
	)
	flushVHost := func() {
		if !inVHost {
			return
		}
		if vRoot != "" || vServer != "" {
			s.addVHost(r, path, vServer, vRoot, vAddr)
		}
		inVHost, vServer, vRoot, vAddr = false, "", "", ""
	}
	for _, ln := range lines {
		if m := reApacheVHostOpen.FindStringSubmatch(ln); len(m) == 2 {
			flushVHost()
			inVHost = true
			vAddr = strings.TrimSpace(m[1])
			continue
		}
		if reApacheVHostClose.MatchString(ln) {
			flushVHost()
			continue
		}
		m := reApacheDirective.FindStringSubmatch(ln)
		if len(m) != 3 {
			continue
		}
		dir := strings.ToLower(m[1])
		args := strings.TrimSpace(m[2])
		switch dir {
		case "documentroot":
			doc := unquoteApache(args)
			if inVHost {
				vRoot = doc
			} else {
				s.addVHost(r, path, "_default_", doc, "global")
			}
		case "servername":
			if inVHost {
				vServer = unquoteApache(firstApacheArg(args))
			}
		case "serveralias":
			// recorded only via ServerName primary; aliases omitted to limit noise
		case "include", "includeoptional":
			if depth >= maxApacheIncludeDepth {
				continue
			}
			s.followInclude(r, path, unquoteApache(firstApacheArg(args)), depth+1)
		case "loadmodule":
			s.handleLoadModule(r, path, args)
		case "sethandler", "addhandler", "action", "proxypassmatch", "proxypass", "fcgidwrapper", "phpinidir":
			s.handlePHPDirective(r, path, dir, args, vServer, vRoot)
		}
	}
	flushVHost()
}

func (s *apacheScanState) followInclude(r *Report, fromPath, pattern string, depth int) {
	if pattern == "" || strings.Contains(pattern, "..") {
		return
	}
	base := filepath.Dir(fromPath)
	var candidates []string
	if filepath.IsAbs(pattern) || (runtime.GOOS == "windows" && isWindowsDrivePath(strings.ReplaceAll(pattern, `\`, `/`))) {
		candidates, _ = filepath.Glob(pattern)
	} else {
		candidates, _ = filepath.Glob(filepath.Join(base, pattern))
	}
	for _, p := range candidates {
		if s.pathAllowed(p) {
			s.readConfigFile(r, p, depth)
		}
	}
}

func (s *apacheScanState) addVHost(r *Report, configPath, serverName, docRoot, addr string) {
	s.initMaps()
	if s.vhosts >= maxApacheVHostEvidence {
		s.truncated = true
		return
	}
	serverName = strings.TrimSpace(serverName)
	docRoot = strings.TrimSpace(docRoot)
	if serverName == "" && docRoot == "" {
		return
	}
	key := normalizeInstallPath(docRoot) + "\x00" + strings.ToLower(serverName)
	if s.seenVHostKey[key] {
		return
	}
	s.seenVHostKey[key] = true
	s.vhosts++
	label := serverName
	if label == "" || label == "_default_" {
		label = "DocumentRoot"
	}
	detail := fmt.Sprintf("server_name=%s; document_root=%s; vhost=%s; php_filenames_require_explicit_webroot; apache_merge_not_fully_simulated",
		serverName, docRoot, strings.TrimSpace(addr))
	r.AddEvidence(Evidence{
		Type:           "apache_vhost_config",
		Name:           label,
		Source:         "Apache HTTP Server configuration (static text)",
		Location:       docRoot,
		Detail:         detail,
		Interpretation: "CONFIGURED_VHOST_PATH_NOT_PROOF_PHP_IS_SERVED_OR_ACTIVE_RUNTIME",
	})
	_ = configPath
}

func (s *apacheScanState) handleLoadModule(r *Report, configPath, args string) {
	s.initMaps()
	parts := splitApacheArgs(args)
	if len(parts) < 2 {
		return
	}
	modName, modPath := parts[0], parts[1]
	if !rePHPModuleName.MatchString(modName) && !strings.Contains(strings.ToLower(modPath), "libphp") {
		return
	}
	if s.modules >= maxApacheHandlerEvidence {
		s.truncated = true
		return
	}
	key := strings.ToLower(modName) + "\x00" + normalizeInstallPath(modPath)
	if s.seenModuleKey[key] {
		return
	}
	s.seenModuleKey[key] = true
	s.modules++
	r.AddEvidence(Evidence{
		Type:           "apache_php_module_config",
		Name:           modName,
		Source:         "Apache LoadModule (static text)",
		Location:       configPath,
		Detail:         fmt.Sprintf("module=%s; module_path=%s; sapi=mod_php; configured_not_verified_serving", modName, modPath),
		Interpretation: "CONFIGURED_MOD_PHP_MODULE_NOT_VERIFIED_SERVING_RUNTIME",
	})
}

func (s *apacheScanState) handlePHPDirective(r *Report, configPath, dir, args, vServer, vRoot string) {
	s.initMaps()
	if !rePHPHandlerToken.MatchString(dir + " " + args) && dir != "phpinidir" {
		return
	}
	if dir == "phpinidir" {
		// Path to php.ini directory/file only — configuration hint, not a SAPI binary.
		ini := unquoteApache(firstApacheArg(args))
		r.AddEvidence(Evidence{
			Type:           "apache_php_handler_config",
			Name:           "PHPIniDir",
			Source:         "Apache PHPIniDir (static text)",
			Location:       configPath,
			Detail:         fmt.Sprintf("directive=phpinidir; php_ini=%s; secrets_not_extracted", ini),
			Interpretation: "CONFIGURED_HANDLER_NOT_VERIFIED_SERVING_RUNTIME",
		})
		s.handlers++
		return
	}
	if s.handlers >= maxApacheHandlerEvidence {
		s.truncated = true
		return
	}

	backend, remote, localExe := classifyApachePHPBackend(dir, args)
	key := dir + "\x00" + backend + "\x00" + localExe + "\x00" + strings.ToLower(vServer)
	if s.seenHandlerKey[key] {
		return
	}
	s.seenHandlerKey[key] = true

	if remote {
		if s.seenRemoteKey[backend] {
			return
		}
		s.seenRemoteKey[backend] = true
		s.remoteBackends++
		s.handlers++
		detail := fmt.Sprintf("directive=%s; backend=%s; scope=remote; site=%s; document_root=%s; not_a_local_php_install; active_runtime_unverified",
			dir, backend, vServer, vRoot)
		r.AddEvidence(Evidence{
			Type:           "apache_remote_php_backend",
			Name:           dir,
			Source:         "Apache proxy/FastCGI target (static text)",
			Location:       configPath,
			Detail:         detail,
			Interpretation: "CONFIGURED_REMOTE_BACKEND_NOT_LOCAL_INSTALL_NOT_RUNTIME_VERIFIED",
		})
		r.AddWarning("Apache PHP backend appears remote and cannot be assessed as a local installation: " + backend)
		return
	}

	s.handlers++
	s.localHandlers++
	detail := fmt.Sprintf("directive=%s; backend=%s; site=%s; document_root=%s", dir, backend, vServer, vRoot)
	if localExe != "" {
		detail += "; handler_exe=" + localExe
	}
	r.AddEvidence(Evidence{
		Type:           "apache_php_handler_config",
		Name:           dir,
		Source:         "Apache PHP handler/proxy (static text)",
		Location:       configPath,
		Detail:         detail,
		Interpretation: "CONFIGURED_HANDLER_NOT_VERIFIED_SERVING_RUNTIME",
	})
	if localExe != "" {
		s.inspectHandlerBinary(r, localExe)
	}
}

func (s *apacheScanState) inspectHandlerBinary(r *Report, configured string) {
	s.initMaps()
	key := normalizeInstallPath(configured)
	if s.seenExe[key] {
		return
	}
	s.seenExe[key] = true
	target := configured
	if runtime.GOOS == "windows" {
		if resolved := ResolveConfiguredWindowsPath(configured); resolved != "" {
			target = resolved
		}
	} else {
		target = filepath.Clean(configured)
	}
	if !HandlerExecutableLooksLikePHP(target) && !HandlerExecutableLooksLikePHP(configured) {
		return
	}
	if !isSafeRegularFile(target) {
		s.inaccessibleBinaries++
		r.AddEvidence(Evidence{
			Type:           "binary_path",
			Name:           filepath.Base(configured),
			Source:         "Apache handler path (inaccessible or unresolved)",
			Location:       configured,
			Detail:         "configured_handler_binary_not_readable; version unknown; site patch status incomplete for this handler",
			Interpretation: "PRESENT_VERSION_UNKNOWN_NOT_RUNTIME_VERIFIED",
		})
		r.AddWarning("Apache PHP handler binary not accessible for version inspection: " + configured)
		return
	}
	s.inspectedBinaries++
	AddBinaryVersionEvidence(r, target, filepath.Base(target), "Apache handler static binary inspection")
}

// classifyApachePHPBackend extracts backend identity and whether it is remote.
func classifyApachePHPBackend(dir, args string) (backend string, remote bool, localExe string) {
	raw := strings.TrimSpace(args)
	low := strings.ToLower(raw)

	if strings.Contains(low, "unix:") {
		if m := reUnixFCGI.FindStringSubmatch(raw); len(m) == 2 {
			backend = "unix:" + m[1]
			return backend, false, ""
		}
	}
	if m := reRemoteFCGI.FindStringSubmatch(raw); len(m) >= 2 {
		host := strings.ToLower(m[1])
		port := ""
		if len(m) > 2 {
			port = m[2]
		}
		backend = host
		if port != "" {
			backend += ":" + port
		}
		if isLocalPHPBackendHost(host) {
			return "fcgi://" + backend, false, ""
		}
		return "fcgi://" + backend, true, ""
	}

	switch strings.ToLower(dir) {
	case "action", "fcgidwrapper", "sethandler", "addhandler":
		// Prefer last path-like argument that looks like a PHP binary.
		for _, p := range splitApacheArgs(raw) {
			p = unquoteApache(p)
			base := filepath.Base(strings.ReplaceAll(p, `\`, `/`))
			if HandlerExecutableLooksLikePHP(p) || strings.Contains(strings.ToLower(base), "php-cgi") {
				return p, false, p
			}
			if strings.HasPrefix(p, "/") || isWindowsDrivePath(strings.ReplaceAll(p, `\`, `/`)) {
				if strings.Contains(strings.ToLower(p), "php") {
					return p, false, p
				}
			}
		}
	}
	backend = summarizeApacheArgs(raw)
	return backend, false, ""
}

func isLocalPHPBackendHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	default:
		return false
	}
}

func flattenApacheLines(content string) []string {
	raw := strings.Split(content, "\n")
	var out []string
	var buf strings.Builder
	for _, ln := range raw {
		ln = reApacheComment.ReplaceAllString(ln, "")
		trim := strings.TrimSpace(ln)
		if trim == "" && buf.Len() == 0 {
			continue
		}
		if strings.HasSuffix(trim, `\`) {
			buf.WriteString(strings.TrimSuffix(trim, `\`))
			buf.WriteByte(' ')
			continue
		}
		buf.WriteString(trim)
		out = append(out, buf.String())
		buf.Reset()
	}
	if buf.Len() > 0 {
		out = append(out, buf.String())
	}
	return out
}

func unquoteApache(s string) string {
	s = strings.TrimSpace(s)
	if m := reQuotedArg.FindStringSubmatch(s); len(m) == 3 {
		if m[1] != "" {
			return m[1]
		}
		return m[2]
	}
	return s
}

func firstApacheArg(args string) string {
	parts := splitApacheArgs(args)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func splitApacheArgs(args string) []string {
	var out []string
	var b strings.Builder
	inQuote := byte(0)
	for i := 0; i < len(args); i++ {
		c := args[i]
		switch {
		case inQuote != 0:
			if c == inQuote {
				inQuote = 0
			} else {
				b.WriteByte(c)
			}
		case c == '"' || c == '\'':
			inQuote = c
		case c == ' ' || c == '\t':
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteByte(c)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func summarizeApacheArgs(args string) string {
	args = strings.TrimSpace(args)
	if len(args) > 160 {
		return args[:160] + "…"
	}
	return args
}

// ParseApacheConfigForTest exposes parsing against an explicit root for regression tests.
func ParseApacheConfigForTest(r *Report, root string) {
	ApplyApacheRootsInventory(r, []string{root})
}
