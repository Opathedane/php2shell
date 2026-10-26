package audit

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Exact PHP patch versions as directory segments: bare X.Y.Z (e.g. ...\PHP\8.4.24\nts\x64\)
// or WampServer-style phpX.Y.Z (e.g. ...\wamp64\bin\php\php7.4.33\php.exe).
// Capture group 1 is always the numeric x.y.z (never the "php" prefix).
var pathPHPVersionSegment = regexp.MustCompile(`(?i)^(?:php)?(\d+\.\d+\.\d+)$`)

// VersionFromInstallPath extracts a PHP x.y.z version from well-known installer path
// segments. Returns empty when the path only uses aliases such as "current".
// Inferred versions keep PATH_INFERRED / MEDIUM provenance via VersionFromBinary;
// they must not be treated as verified binary metadata or as the active HTTP runtime.
func VersionFromInstallPath(path string) (version string, source string) {
	cleaned := filepath.Clean(path)
	parts := strings.FieldsFunc(cleaned, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	var found []string
	for _, p := range parts {
		if m := pathPHPVersionSegment.FindStringSubmatch(p); len(m) == 2 {
			found = append(found, m[1])
		}
	}
	if len(found) == 0 {
		return "", ""
	}
	// Prefer the last (deepest) exact version segment; official Windows layout uses
	// Programs\PHP\<version>\nts|ts\x64|x86\php.exe. WampServer uses bin\php\phpX.Y.Z\.
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
