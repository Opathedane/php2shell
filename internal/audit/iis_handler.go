package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ParseIISScriptProcessor splits an IIS scriptProcessor or FastCGI fullPath value into
// executable and trailing arguments. Pipe separators inside double quotes are preserved.
func ParseIISScriptProcessor(raw string) (exe, args string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	exe, args = splitPipeOutsideQuotes(raw)
	exe = strings.Trim(exe, `"' `)
	args = strings.TrimSpace(args)
	return exe, args
}

func splitPipeOutsideQuotes(s string) (left, right string) {
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case '|':
			if !inQuote {
				return s[:i], s[i+1:]
			}
		}
	}
	return s, ""
}

// FormatIISHandlerDetail stores handler metadata for reporting and later path resolution.
// scriptProcessor arguments are not copied into reports (may contain secrets); only the
// executable path is retained, with a flag when arguments were present.
func FormatIISHandlerDetail(path, modules, scriptProcessor string) string {
	exe, args := ParseIISScriptProcessor(scriptProcessor)
	if exe == "" {
		exe = strings.TrimSpace(scriptProcessor)
		exe, _ = ParseIISScriptProcessor(exe)
	}
	detail := fmt.Sprintf("path=%s; modules=%s; handler_exe=%s", path, modules, normalizeWindowsConfigPath(exe))
	if strings.TrimSpace(args) != "" {
		detail += "; handler_args=redacted"
	}
	return detail
}

// HandlerExecutableFromDetail returns the configured handler executable path only (never arguments).
func HandlerExecutableFromDetail(detail string) string {
	for _, part := range strings.Split(detail, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "handler_exe=") {
			return strings.TrimPrefix(part, "handler_exe=")
		}
		if strings.HasPrefix(part, "handler=") {
			exe, _ := ParseIISScriptProcessor(strings.TrimPrefix(part, "handler="))
			return exe
		}
	}
	return ""
}

// ConfiguredWindowsHandlerPath returns the IIS-configured executable path using Windows semantics
// (no local filesystem resolution or environment expansion).
func ConfiguredWindowsHandlerPath(raw string) string {
	raw = strings.Trim(raw, `"' `)
	if raw == "" {
		return ""
	}
	return normalizeWindowsConfigPath(raw)
}

// HandlerExecutableLooksLikePHP returns true when the configured path basename resembles a PHP binary.
func HandlerExecutableLooksLikePHP(path string) bool {
	if path == "" {
		return false
	}
	return phpBin.MatchString(windowsPathBase(path))
}

// ResolveHandlerExecutablePath maps a configured IIS handler path to a local filesystem path for
// read-only inspection. It never executes the configured program.
func ResolveHandlerExecutablePath(configured string) string {
	return ResolveConfiguredWindowsPath(configured)
}

// ResolveConfiguredWindowsPath expands env vars in an IIS-configured path and maps it to a local
// filesystem path when possible. Drive-letter paths resolve only on Windows. Never executes.
func ResolveConfiguredWindowsPath(configured string) string {
	configured = ConfiguredWindowsHandlerPath(configured)
	if configured == "" || handlerPathBlocked(configured) {
		return ""
	}
	expanded := expandWindowsPercentEnv(configured)
	if runtime.GOOS == "windows" {
		expanded = os.ExpandEnv(expanded)
		return filepath.Clean(expanded)
	}
	return localPathFromWindowsConfig(expanded)
}

func normalizeWindowsConfigPath(p string) string {
	p = strings.ReplaceAll(p, `/`, `\`)
	for strings.Contains(p, `\\`) {
		p = strings.ReplaceAll(p, `\\`, `\`)
	}
	return p
}

func windowsPathBase(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, `/`, `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func localPathFromWindowsConfig(expanded string) string {
	if expanded == "" {
		return ""
	}
	slashy := strings.ReplaceAll(expanded, `\`, `/`)
	if isWindowsDrivePath(slashy) {
		return ""
	}
	if strings.HasPrefix(slashy, "/") {
		return filepath.Clean(slashy)
	}
	var parts []string
	for _, seg := range strings.Split(slashy, `/`) {
		if seg == "" || seg == "." {
			continue
		}
		if isWindowsDrivePath(seg) {
			return ""
		}
		parts = append(parts, seg)
	}
	if len(parts) == 0 {
		return ""
	}
	return filepath.Clean(strings.Join(parts, string(filepath.Separator)))
}

func isWindowsDrivePath(s string) bool {
	if len(s) < 2 || s[1] != ':' {
		return false
	}
	c := s[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func handlerPathBlocked(exe string) bool {
	lower := strings.ToLower(strings.ReplaceAll(exe, `\`, `/`))
	return strings.Contains(lower, "cmd.exe") || strings.Contains(lower, "powershell") || strings.Contains(lower, "wscript.exe")
}

// expandWindowsPercentEnv replaces %NAME% segments using the process environment.
func expandWindowsPercentEnv(path string) string {
	var b strings.Builder
	for i := 0; i < len(path); i++ {
		if path[i] != '%' {
			b.WriteByte(path[i])
			continue
		}
		end := i + 1
		for end < len(path) && path[end] != '%' {
			end++
		}
		if end >= len(path) {
			b.WriteByte('%')
			break
		}
		name := path[i+1 : end]
		if val, ok := os.LookupEnv(name); ok {
			b.WriteString(val)
		} else {
			b.WriteString(path[i : end+1])
		}
		i = end
	}
	return b.String()
}
