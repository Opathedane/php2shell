package audit

import (
	"fmt"
	"path/filepath"
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
func FormatIISHandlerDetail(path, modules, scriptProcessor string) string {
	exe, args := ParseIISScriptProcessor(scriptProcessor)
	if exe == "" {
		exe = strings.TrimSpace(scriptProcessor)
	}
	detail := fmt.Sprintf("path=%s; modules=%s; handler_exe=%s", path, modules, exe)
	if args != "" {
		detail += "; handler_args=" + args
	}
	if strings.TrimSpace(scriptProcessor) != "" && scriptProcessor != exe {
		detail += "; scriptprocessor_raw=" + scriptProcessor
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

// HandlerExecutableLooksLikePHP returns true when the path basename resembles a PHP binary.
func HandlerExecutableLooksLikePHP(exe string) bool {
	if exe == "" {
		return false
	}
	return phpBin.MatchString(filepath.Base(exe))
}
