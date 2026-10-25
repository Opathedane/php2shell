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
	maxNginxConfigFiles      = 64
	maxNginxConfigBytes      = 2 << 20
	maxNginxIncludeDepth     = 3
	maxNginxHandlerEvidence  = 128
	maxNginxUpstreamEvidence = 64
	maxNginxSiteEvidence     = 128
)

// Well-known nginx config roots only (no filesystem-wide search; no Homebrew expansion).
var nginxConfigRoots = []string{
	"/etc/nginx",
	"/usr/local/etc/nginx",
	"/usr/local/nginx/conf",
}

var (
	reNginxComment     = regexp.MustCompile(`#.*$`)
	reNginxBlockOpen = regexp.MustCompile(`(?i)^\s*(http|server|location|upstream)\b([^;{]*)(?:\{\s*(.*))?$`)
	reNginxFastCGIPass = regexp.MustCompile(`(?i)^\s*fastcgi_pass\s+(.+?)\s*;\s*$`)
	reNginxInclude     = regexp.MustCompile(`(?i)^\s*include\s+(.+?)\s*;\s*$`)
	reNginxServerName  = regexp.MustCompile(`(?i)^\s*server_name\s+(.+?)\s*;\s*$`)
	reNginxRoot        = regexp.MustCompile(`(?i)^\s*root\s+(.+?)\s*;\s*$`)
	reNginxUpstreamSrv = regexp.MustCompile(`(?i)^\s*server\s+(.+?)\s*;\s*$`)
	reNginxUnixPass    = regexp.MustCompile(`(?i)^unix:(\S+)`)
	reNginxTCPPass     = regexp.MustCompile(`(?i)^(?:\[([^\]]+)\]|([^:/\s]+)):(\d+)\s*$`)
	reNginxPHPLocation = regexp.MustCompile(`(?i)(\.php\b|php)`)
)

// scanNginxConfiguration performs bounded, passive nginx config inventory for PHP FastCGI wiring.
// It never executes binaries, opens sockets, or follows unrestricted includes.
func scanNginxConfiguration(r *Report) {
	roots := accessibleNginxRoots()
	if len(roots) == 0 {
		r.AddCheck("nginx_configuration", "NOT_APPLICABLE",
			"No well-known nginx configuration directories accessible; PHP FastCGI wiring not inventoried from nginx")
		return
	}
	ApplyNginxRootsInventory(r, roots)
}

func accessibleNginxRoots() []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range nginxConfigRoots {
		if runtime.GOOS == "windows" {
			continue // nginx discovery is Unix-focused in this milestone
		}
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

// ApplyNginxRootsInventory reads allowlisted nginx config trees and records PHP-related
// FastCGI / upstream evidence. Intended for production ScanHost and tests.
func ApplyNginxRootsInventory(r *Report, roots []string) {
	state := &nginxScanState{
		roots:   roots,
		rootSet: map[string]bool{},
	}
	for _, root := range roots {
		state.rootSet[normalizeInstallPath(root)] = true
	}
	for _, root := range roots {
		for _, seed := range nginxSeedPatterns(root) {
			matches, _ := filepath.Glob(seed)
			for _, path := range matches {
				state.readConfigFile(r, path, 0)
			}
		}
	}
	// Emit upstream evidence after full parse so arbitrarily named groups referenced by
	// PHP FastCGI handlers are included; unrelated proxy upstreams stay silent.
	state.emitPHPRelatedUpstreams(r)
	status := "PARTIAL"
	if state.remoteBackends > 0 || state.ambiguousBackends > 0 || state.skippedFiles > 0 || state.variableBackends > 0 || state.unresolvedIncludes > 0 {
		status = "INCOMPLETE"
	}
	if state.truncated {
		status = "TRUNCATED"
	}
	r.AddCheck("nginx_configuration", status, fmt.Sprintf(
		"Read %d nginx config files under %d allowlisted root(s); %d server/root rows; %d PHP-related fastcgi_pass rows; %d upstream blocks; %d remote PHP backends (not local installs); %d ambiguous/variable backends; %d skipped unreadable/symlink-out-of-root/oversized files; %d unresolved PHP-relevant includes; active serving runtime unverified; Includes limited to depth %d within allowlisted roots; no network probes; LiteSpeed/OpenResty-only layouts not targeted",
		state.inspectedFiles, len(roots), state.sites, state.handlers, state.upstreams, state.remoteBackends, state.ambiguousBackends+state.variableBackends, state.skippedFiles, state.unresolvedIncludes, maxNginxIncludeDepth,
	))
}

type nginxScanState struct {
	roots               []string
	rootSet             map[string]bool
	seenFile            map[string]bool
	seenSkipKey         map[string]bool
	seenIncludeGapKey   map[string]bool
	inspectedFiles      int
	skippedFiles        int
	unresolvedIncludes  int
	sites               int
	handlers            int
	upstreams           int
	remoteBackends      int
	ambiguousBackends   int
	variableBackends    int
	truncated            bool
	seenHandlerKey      map[string]bool
	seenSiteKey         map[string]bool
	seenRemoteKey       map[string]bool
	seenUpstreamKey     map[string]bool
	upstreamsByName     map[string]*nginxUpstream
}

type nginxUpstream struct {
	name            string
	configPath      string
	servers         []string
	remote          bool
	local           bool
	mixed           bool
	referencedByPHP bool
}

type nginxParseCtx struct {
	serverName string
	root       string
	inServer   bool
	locPHP     bool // inside a location that looks PHP-related
	upstream   string
}

func (s *nginxScanState) initMaps() {
	if s.seenFile == nil {
		s.seenFile = map[string]bool{}
		s.seenSkipKey = map[string]bool{}
		s.seenIncludeGapKey = map[string]bool{}
		s.seenHandlerKey = map[string]bool{}
		s.seenSiteKey = map[string]bool{}
		s.seenRemoteKey = map[string]bool{}
		s.seenUpstreamKey = map[string]bool{}
		s.upstreamsByName = map[string]*nginxUpstream{}
	}
}

func nginxSeedPatterns(root string) []string {
	return []string{
		filepath.Join(root, "nginx.conf"),
		filepath.Join(root, "conf.d", "*.conf"),
		filepath.Join(root, "sites-enabled", "*"),
		filepath.Join(root, "sites-available", "*.conf"),
		filepath.Join(root, "http.d", "*.conf"),
	}
}

func (s *nginxScanState) pathAllowed(path string) bool {
	norm := normalizeInstallPath(path)
	for root := range s.rootSet {
		if norm == root || strings.HasPrefix(norm, root+"/") {
			return true
		}
	}
	return false
}

func (s *nginxScanState) readConfigFile(r *Report, path string, depth int) {
	s.initMaps()
	path = filepath.Clean(path)
	key := normalizeInstallPath(path)
	if s.seenFile[key] || s.seenSkipKey[key] {
		return
	}
	if s.inspectedFiles >= maxNginxConfigFiles {
		s.truncated = true
		return
	}
	if !s.pathAllowed(path) {
		return
	}
	b, readPath, err := s.readNginxConfigBytes(path)
	if err != nil {
		s.recordConfigSkip(r, path, err)
		return
	}
	s.seenFile[key] = true
	// Also mark resolved path so sites-enabled symlink + sites-available target share one parse.
	if rp := normalizeInstallPath(readPath); rp != key {
		s.seenFile[rp] = true
	}
	s.inspectedFiles++
	s.parseNginxConfig(r, readPath, string(b), depth)
}

// readNginxConfigBytes reads a regular config file. For a single-level symlink whose
// target remains inside an allowlisted root (Debian sites-enabled → sites-available),
// the target is read instead. Escaping or multi-hop links are skipped, not followed.
func (s *nginxScanState) readNginxConfigBytes(path string) (data []byte, readPath string, err error) {
	b, err := ReadRegular(path, maxNginxConfigBytes)
	if err == nil {
		return b, path, nil
	}
	fi, lerr := os.Lstat(path)
	if lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
		return nil, path, err
	}
	target, rerr := os.Readlink(path)
	if rerr != nil {
		return nil, path, rerr
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	target = filepath.Clean(target)
	if !s.pathAllowed(target) {
		return nil, path, fmt.Errorf("symlink target outside allowlisted nginx roots: %s", target)
	}
	// Reject nested symlinks: target must be a regular file.
	b, err = ReadRegular(target, maxNginxConfigBytes)
	if err != nil {
		return nil, path, err
	}
	return b, target, nil
}

func (s *nginxScanState) recordConfigSkip(r *Report, path string, cause error) {
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
			reason = "symlink_rejected_or_out_of_root"
		case strings.Contains(low, "exceeds") || strings.Contains(low, "exceeded"):
			reason = "oversized"
		case strings.Contains(low, "permission") || strings.Contains(low, "denied"):
			reason = "unreadable"
		case strings.Contains(low, "no such file"):
			// Glob race / disappeared — do not invent incomplete noise for missing optional globs.
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
		Type:           "nginx_config_skip",
		Name:           filepath.Base(path),
		Source:         "nginx configuration candidate (not inspected)",
		Location:       path,
		Detail:         detail,
		Interpretation: "CONFIG_CANDIDATE_NOT_INSPECTED",
	})
}

func (s *nginxScanState) parseNginxConfig(r *Report, path, content string, depth int) {
	lines := flattenNginxLines(content)
	var stack []nginxParseCtx
	cur := nginxParseCtx{}

	flushServer := func() {
		if !cur.inServer {
			return
		}
		if cur.serverName != "" || cur.root != "" {
			s.addSite(r, path, cur.serverName, cur.root)
		}
	}

	for _, ln := range lines {
		if strings.TrimSpace(ln) == "{" {
			continue // brace on its own line after server/location
		}
		if s.tryNginxInclude(r, path, ln, depth) {
			continue
		}
		if m := reNginxBlockOpen.FindStringSubmatch(ln); len(m) >= 2 {
			kind := strings.ToLower(m[1])
			args := strings.TrimSpace(m[2])
			rest := ""
			if len(m) > 3 {
				rest = strings.TrimSpace(m[3])
			}
			// Reject false positives like incomplete matches without block intent when
			// the line is a plain directive ending with ';' and no '{'.
			if !strings.Contains(ln, "{") && strings.HasSuffix(strings.TrimSpace(ln), ";") {
				s.handleNginxInnerLine(r, path, ln, depth, &cur)
				continue
			}
			stack = append(stack, cur)
			switch kind {
			case "server":
				cur = nginxParseCtx{inServer: true}
			case "location":
				parent := cur
				cur = parent
				cur.locPHP = reNginxPHPLocation.MatchString(args)
			case "upstream":
				name := unquoteNginx(firstNginxArg(args))
				cur = nginxParseCtx{upstream: name}
				if name != "" && s.upstreamsByName[name] == nil {
					s.upstreamsByName[name] = &nginxUpstream{name: name}
				}
			default:
				cur = nginxParseCtx{}
			}
			if rest != "" {
				s.consumeNginxInline(r, path, rest, depth, &stack, &cur, flushServer)
			}
			continue
		}
		if strings.TrimSpace(ln) == "}" {
			s.closeNginxBlock(r, path, &stack, &cur, flushServer)
			continue
		}
		s.handleNginxInnerLine(r, path, ln, depth, &cur)
	}
	// Unclosed server at EOF still counts if we saw markers.
	if cur.inServer {
		flushServer()
	}
}

// consumeNginxInline parses directives/blocks that appeared after `{` on the same line.
func (s *nginxScanState) consumeNginxInline(r *Report, path, rest string, depth int, stack *[]nginxParseCtx, cur *nginxParseCtx, flushServer func()) {
	inline := rest
	if strings.Contains(inline, "}") {
		inline = strings.ReplaceAll(inline, "}", " ; } ; ")
	}
	for _, part := range splitNginxStatements(inline) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == "}" {
			s.closeNginxBlock(r, path, stack, cur, flushServer)
			continue
		}
		if m := reNginxBlockOpen.FindStringSubmatch(part); len(m) >= 2 && strings.Contains(part, "{") {
			kind := strings.ToLower(m[1])
			args := strings.TrimSpace(m[2])
			inner := ""
			if len(m) > 3 {
				inner = strings.TrimSpace(m[3])
			}
			*stack = append(*stack, *cur)
			switch kind {
			case "server":
				*cur = nginxParseCtx{inServer: true}
			case "location":
				parent := *cur
				*cur = parent
				cur.locPHP = reNginxPHPLocation.MatchString(args)
			case "upstream":
				name := unquoteNginx(firstNginxArg(args))
				*cur = nginxParseCtx{upstream: name}
				if name != "" && s.upstreamsByName[name] == nil {
					s.upstreamsByName[name] = &nginxUpstream{name: name}
				}
			default:
				*cur = nginxParseCtx{}
			}
			if inner != "" {
				s.consumeNginxInline(r, path, inner, depth, stack, cur, flushServer)
			}
			continue
		}
		s.handleNginxInnerLine(r, path, part, depth, cur)
	}
}

func (s *nginxScanState) closeNginxBlock(r *Report, path string, stack *[]nginxParseCtx, cur *nginxParseCtx, flushServer func()) {
	if cur.upstream != "" {
		s.finalizeUpstream(r, path, cur.upstream)
	}
	if cur.inServer && (len(*stack) == 0 || !(*stack)[len(*stack)-1].inServer) {
		flushServer()
	}
	if len(*stack) > 0 {
		*cur = (*stack)[len(*stack)-1]
		*stack = (*stack)[:len(*stack)-1]
	} else {
		*cur = nginxParseCtx{}
	}
}

func (s *nginxScanState) tryNginxInclude(r *Report, path, ln string, depth int) bool {
	m := reNginxInclude.FindStringSubmatch(ln)
	if len(m) != 2 {
		return false
	}
	pattern := unquoteNginx(firstNginxArg(m[1]))
	if depth < maxNginxIncludeDepth {
		s.followInclude(r, path, pattern, depth+1)
	} else if nginxIncludeLooksPHPRelevant(pattern) {
		s.recordIncludeUnresolved(r, path, pattern, "include_depth_limit")
	}
	return true
}

func (s *nginxScanState) handleNginxInnerLine(r *Report, path, ln string, depth int, cur *nginxParseCtx) {
	if s.tryNginxInclude(r, path, ln, depth) {
		return
	}
	if cur.upstream != "" {
		if m := reNginxUpstreamSrv.FindStringSubmatch(ln); len(m) == 2 {
			s.recordUpstreamServer(cur.upstream, firstNginxArg(m[1]))
		}
		return
	}
	if m := reNginxServerName.FindStringSubmatch(ln); len(m) == 2 && cur.inServer {
		cur.serverName = unquoteNginx(firstNginxArg(m[1]))
		return
	}
	if m := reNginxRoot.FindStringSubmatch(ln); len(m) == 2 && cur.inServer {
		cur.root = unquoteNginx(firstNginxArg(m[1]))
		return
	}
	if m := reNginxFastCGIPass.FindStringSubmatch(ln); len(m) == 2 {
		target := strings.TrimSpace(m[1])
		if cur.locPHP || strings.Contains(strings.ToLower(target), "php") {
			s.handleFastCGIPass(r, path, target, cur.serverName, cur.root)
		}
	}
}

func (s *nginxScanState) followInclude(r *Report, fromPath, pattern string, depth int) {
	if pattern == "" {
		return
	}
	if strings.Contains(pattern, "..") {
		if nginxIncludeLooksPHPRelevant(pattern) {
			s.recordIncludeUnresolved(r, fromPath, pattern, "parent_path_rejected")
		}
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
		if !s.pathAllowed(c) {
			if nginxIncludeLooksPHPRelevant(pattern) || nginxIncludeLooksPHPRelevant(c) {
				s.recordIncludeUnresolved(r, fromPath, c, "outside_allowlisted_roots")
			}
			continue
		}
		s.readConfigFile(r, c, depth)
	}
}

// nginxIncludeLooksPHPRelevant identifies include patterns that can affect PHP
// FastCGI discovery completeness. Irrelevant system includes (mime.types, etc.)
// stay silent when blocked by allowlist/depth/safety caps.
func nginxIncludeLooksPHPRelevant(pattern string) bool {
	low := strings.ToLower(pattern)
	for _, tok := range []string{
		"php", "fpm", "fastcgi", "sites-", "sites_", "vhost", "pool",
		"conf.d", "http.d", "apps.d",
	} {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

func (s *nginxScanState) recordIncludeUnresolved(r *Report, fromPath, pattern, reason string) {
	s.initMaps()
	key := reason + "\x00" + normalizeInstallPath(fromPath) + "\x00" + strings.ToLower(pattern)
	if s.seenIncludeGapKey[key] {
		return
	}
	s.seenIncludeGapKey[key] = true
	s.unresolvedIncludes++
	detail := fmt.Sprintf("include=%s; from=%s; reason=%s; php_relevant_include_not_fully_followed; not_proof_absence_of_php",
		pattern, fromPath, reason)
	r.AddEvidence(Evidence{
		Type:           "nginx_include_unresolved",
		Name:           filepath.Base(pattern),
		Source:         "nginx include directive (bounded follow)",
		Location:       fromPath,
		Detail:         detail,
		Interpretation: "PHP_RELEVANT_INCLUDE_NOT_FULLY_FOLLOWED_COVERAGE_INCOMPLETE",
	})
}

func (s *nginxScanState) addSite(r *Report, configPath, serverName, root string) {
	s.initMaps()
	if s.sites >= maxNginxSiteEvidence {
		s.truncated = true
		return
	}
	if serverName == "" {
		serverName = "_default_"
	}
	key := normalizeInstallPath(configPath) + "\x00" + strings.ToLower(serverName) + "\x00" + normalizeInstallPath(root)
	if s.seenSiteKey[key] {
		return
	}
	s.seenSiteKey[key] = true
	s.sites++
	detail := fmt.Sprintf("server_name=%s; root=%s; not_proof_php_is_served", serverName, root)
	r.AddEvidence(Evidence{
		Type:           "nginx_site_config",
		Name:           serverName,
		Source:         "nginx server block (static text)",
		Location:       root,
		Detail:         detail + "; config=" + configPath,
		Interpretation: "CONFIGURED_VHOST_PATH_NOT_PROOF_PHP_IS_SERVED_OR_ACTIVE_RUNTIME",
	})
}

func (s *nginxScanState) recordUpstreamServer(name, raw string) {
	s.initMaps()
	u := s.upstreamsByName[name]
	if u == nil {
		u = &nginxUpstream{name: name}
		s.upstreamsByName[name] = u
	}
	tok := firstNginxArg(raw)
	u.servers = append(u.servers, tok)
	host, port, kind := classifyNginxPassTarget(tok)
	_ = port
	switch kind {
	case "remote":
		u.remote = true
	case "unix", "local_tcp":
		u.local = true
	default:
		// bare hostname in upstream server line
		if host != "" && !isLocalPHPBackendHost(host) {
			u.remote = true
		} else if isLocalPHPBackendHost(host) {
			u.local = true
		}
	}
	if u.remote && u.local {
		u.mixed = true
	}
}

func (s *nginxScanState) finalizeUpstream(r *Report, configPath, name string) {
	s.initMaps()
	u := s.upstreamsByName[name]
	if u == nil {
		return
	}
	if u.configPath == "" {
		u.configPath = configPath
	}
	// Defer evidence emission until emitPHPRelatedUpstreams so arbitrarily named
	// groups can be marked referencedByPHP by later fastcgi_pass lines.
}

func (s *nginxScanState) emitPHPRelatedUpstreams(r *Report) {
	s.initMaps()
	for name, u := range s.upstreamsByName {
		if u == nil {
			continue
		}
		phpNamed := strings.Contains(strings.ToLower(name), "php")
		if !phpNamed && !u.referencedByPHP {
			continue // unrelated proxy upstreams stay silent
		}
		if s.seenUpstreamKey[name] {
			continue
		}
		if s.upstreams >= maxNginxUpstreamEvidence {
			s.truncated = true
			return
		}
		s.seenUpstreamKey[name] = true
		s.upstreams++
		detail := fmt.Sprintf("upstream=%s; servers=%s", name, strings.Join(u.servers, ","))
		if u.referencedByPHP && !phpNamed {
			detail += "; referenced_by_php_fastcgi_pass"
		}
		interp := "CONFIGURED_UPSTREAM_NOT_PROOF_PHP_RUNTIME"
		if u.mixed {
			detail += "; scope=mixed_local_remote; ambiguous"
			s.ambiguousBackends++
		} else if u.remote && !u.local {
			detail += "; scope=remote; not_a_local_php_install"
		} else if u.local && !u.remote {
			detail += "; scope=local_candidate"
		}
		loc := u.configPath
		if loc == "" {
			loc = "nginx upstream"
		}
		r.AddEvidence(Evidence{
			Type:           "nginx_php_upstream_config",
			Name:           name,
			Source:         "nginx upstream block (static text)",
			Location:       loc,
			Detail:         detail,
			Interpretation: interp,
		})
	}
}

func (s *nginxScanState) handleFastCGIPass(r *Report, configPath, target, serverName, docRoot string) {
	s.initMaps()
	if s.handlers >= maxNginxHandlerEvidence {
		s.truncated = true
		return
	}
	target = unquoteNginx(strings.TrimSpace(target))
	if name := bareNginxUpstreamName(target); name != "" {
		if u := s.upstreamsByName[name]; u != nil {
			u.referencedByPHP = true
		}
	}
	backend, kind := normalizeNginxFastCGITarget(target, s.upstreamsByName)
	key := kind + "\x00" + backend + "\x00" + strings.ToLower(serverName)
	if s.seenHandlerKey[key] {
		return
	}
	s.seenHandlerKey[key] = true

	switch kind {
	case "remote":
		if s.seenRemoteKey[backend] {
			return
		}
		s.seenRemoteKey[backend] = true
		s.remoteBackends++
		s.handlers++
		detail := fmt.Sprintf("directive=fastcgi_pass; backend=%s; scope=remote; site=%s; root=%s; not_a_local_php_install; active_runtime_unverified",
			backend, serverName, docRoot)
		r.AddEvidence(Evidence{
			Type:           "nginx_remote_php_backend",
			Name:           "fastcgi_pass",
			Source:         "nginx fastcgi_pass (static text)",
			Location:       configPath,
			Detail:         detail,
			Interpretation: "CONFIGURED_REMOTE_BACKEND_NOT_LOCAL_INSTALL_NOT_RUNTIME_VERIFIED",
		})
		r.AddWarning("nginx PHP FastCGI backend appears remote and cannot be assessed as a local installation: " + backend)
	case "variable", "ambiguous":
		if kind == "variable" {
			s.variableBackends++
		} else {
			s.ambiguousBackends++
		}
		s.handlers++
		scope := "ambiguous"
		interp := "CONFIGURED_HANDLER_AMBIGUOUS_BACKEND_NOT_VERIFIED_SERVING_RUNTIME"
		if kind == "variable" {
			scope = "variable_unresolved"
			interp = "CONFIGURED_HANDLER_VARIABLE_BACKEND_NOT_RESOLVED_NOT_VERIFIED_SERVING_RUNTIME"
		}
		detail := fmt.Sprintf("directive=fastcgi_pass; backend=%s; scope=%s; site=%s; root=%s; active_runtime_unverified",
			backend, scope, serverName, docRoot)
		r.AddEvidence(Evidence{
			Type:           "nginx_php_handler_config",
			Name:           "fastcgi_pass",
			Source:         "nginx fastcgi_pass (static text)",
			Location:       configPath,
			Detail:         detail,
			Interpretation: interp,
		})
	default: // local unix / local tcp
		s.handlers++
		detail := fmt.Sprintf("directive=fastcgi_pass; backend=%s; scope=local_candidate; site=%s; root=%s",
			backend, serverName, docRoot)
		r.AddEvidence(Evidence{
			Type:           "nginx_php_handler_config",
			Name:           "fastcgi_pass",
			Source:         "nginx fastcgi_pass (static text)",
			Location:       configPath,
			Detail:         detail,
			Interpretation: "CONFIGURED_HANDLER_NOT_VERIFIED_SERVING_RUNTIME",
		})
	}
}

func nginxTargetHasVariable(target string) bool {
	return strings.Contains(target, "$")
}

// bareNginxUpstreamName returns a named upstream reference token, or empty when the
// target is a unix/TCP/variable endpoint rather than an upstream group name.
func bareNginxUpstreamName(target string) string {
	target = strings.TrimSpace(target)
	if target == "" || nginxTargetHasVariable(target) {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(target), "unix:") {
		return ""
	}
	if strings.Contains(target, "/") || strings.Contains(target, ":") {
		return ""
	}
	return target
}

func normalizeNginxFastCGITarget(target string, upstreams map[string]*nginxUpstream) (backend, kind string) {
	target = strings.TrimSpace(target)
	// Never guess endpoints that interpolate nginx variables.
	if nginxTargetHasVariable(target) {
		return summarizeApacheArgs(target), "variable"
	}
	if m := reNginxUnixPass.FindStringSubmatch(target); len(m) == 2 {
		return "unix:" + m[1], "unix"
	}
	if m := reNginxTCPPass.FindStringSubmatch(target); len(m) >= 4 {
		host := m[2]
		if m[1] != "" {
			host = m[1]
		}
		port := m[3]
		ep := host + ":" + port
		if isLocalPHPBackendHost(host) {
			return ep, "local_tcp"
		}
		return ep, "remote"
	}
	// Named upstream reference (no scheme).
	name := strings.TrimSpace(target)
	if u, ok := upstreams[name]; ok {
		if u.mixed || (u.remote && u.local) {
			return "upstream:" + name, "ambiguous"
		}
		if u.remote && !u.local {
			return "upstream:" + name, "remote"
		}
		if u.local {
			// Prefer first local-looking server as backend identity.
			for _, srv := range u.servers {
				if nginxTargetHasVariable(srv) {
					return "upstream:" + name, "variable"
				}
				b, k := normalizeNginxFastCGITarget(srv, nil)
				if k == "unix" || k == "local_tcp" {
					return b, k
				}
			}
			return "upstream:" + name, "local_tcp"
		}
		return "upstream:" + name, "ambiguous"
	}
	// Unresolved upstream name or opaque token — do not invent a local endpoint.
	if name != "" && !strings.Contains(name, "/") && !strings.Contains(name, ":") {
		return "upstream:" + name, "ambiguous"
	}
	return summarizeApacheArgs(target), "ambiguous"
}

func classifyNginxPassTarget(raw string) (host, port, kind string) {
	raw = strings.TrimSpace(raw)
	// Strip weight/fail_timeout params: "127.0.0.1:9000 weight=1"
	if i := strings.IndexAny(raw, " \t"); i > 0 {
		raw = raw[:i]
	}
	if m := reNginxUnixPass.FindStringSubmatch(raw); len(m) == 2 {
		return m[1], "", "unix"
	}
	if m := reNginxTCPPass.FindStringSubmatch(raw); len(m) >= 4 {
		host = m[2]
		if m[1] != "" {
			host = m[1]
		}
		port = m[3]
		if isLocalPHPBackendHost(host) {
			return host, port, "local_tcp"
		}
		return host, port, "remote"
	}
	return raw, "", "other"
}

func flattenNginxLines(content string) []string {
	raw := strings.Split(content, "\n")
	var out []string
	for _, ln := range raw {
		ln = reNginxComment.ReplaceAllString(ln, "")
		trim := strings.TrimSpace(ln)
		if trim == "" {
			continue
		}
		// Split rare "directive; directive;" single lines.
		for _, part := range splitNginxStatements(trim) {
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func splitNginxStatements(line string) []string {
	if !strings.Contains(line, ";") || strings.HasSuffix(line, "{") || line == "}" {
		return []string{line}
	}
	var out []string
	start := 0
	depth := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth != 0 {
				continue
			}
			part := strings.TrimSpace(line[start : i+1])
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	rest := strings.TrimSpace(line[start:])
	if rest != "" {
		out = append(out, rest)
	}
	if len(out) == 0 {
		return []string{line}
	}
	return out
}

func unquoteNginx(s string) string {
	return unquoteApache(s)
}

func firstNginxArg(args string) string {
	return firstApacheArg(args)
}

// ParseNginxConfigForTest exposes parsing against an explicit root for regression tests.
func ParseNginxConfigForTest(r *Report, root string) {
	ApplyNginxRootsInventory(r, []string{root})
}
