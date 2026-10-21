//go:build !windows

package audit

import "strings"

// ResolveHandlerExecutablePath returns the configured path without environment expansion on non-Windows builds.
func ResolveHandlerExecutablePath(exe string) string {
	return strings.Trim(exe, `"' `)
}
