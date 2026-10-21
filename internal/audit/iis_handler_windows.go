//go:build windows

package audit

import (
	"os"
	"strings"
)

// ResolveHandlerExecutablePath expands Windows environment variables in a configured
// handler path for read-only filesystem inspection. It never executes the path.
func ResolveHandlerExecutablePath(exe string) string {
	exe = strings.Trim(exe, `"' `)
	if exe == "" {
		return ""
	}
	lower := strings.ToLower(exe)
	if strings.Contains(lower, "cmd.exe") || strings.Contains(lower, "powershell") || strings.Contains(lower, "wscript") {
		return ""
	}
	return os.ExpandEnv(exe)
}
