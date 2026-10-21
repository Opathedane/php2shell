package audit

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Exact PHP patch versions embedded as directory segments (e.g. ...\PHP\8.4.24\nts\x64\).
var pathPHPVersionSegment = regexp.MustCompile(`(?i)^(\d+)\.(\d+)\.(\d+)$`)

// VersionFromInstallPath extracts a PHP x.y.z version from well-known installer path
// segments. Returns empty when the path only uses aliases such as "current".
func VersionFromInstallPath(path string) (version string, source string) {
	cleaned := filepath.Clean(path)
	parts := strings.FieldsFunc(cleaned, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	var found []string
	for _, p := range parts {
		if pathPHPVersionSegment.MatchString(p) {
			found = append(found, p)
		}
	}
	if len(found) == 0 {
		return "", ""
	}
	// Prefer the last (deepest) exact version segment; official Windows layout uses
	// Programs\PHP\<version>\nts|ts\x64|x86\php.exe.
	return found[len(found)-1], "install_path_version_segment"
}

func pathContainsCurrentAlias(path string) bool {
	cleaned := strings.ToLower(filepath.Clean(path))
	parts := strings.FieldsFunc(cleaned, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	for _, p := range parts {
		if p == "current" {
			return true
		}
	}
	return false
}
