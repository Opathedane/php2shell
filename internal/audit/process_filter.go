package audit

import (
	"os"
	"path/filepath"
	"strings"
)

// IsScannerProcessName reports whether a process name belongs to this scanner
// (or a similarly named wrapper), not a PHP runtime.
func IsScannerProcessName(name string) bool {
	base := strings.ToLower(strings.TrimSpace(name))
	base = strings.TrimSuffix(base, ".exe")
	if base == "" {
		return false
	}
	// Exact product prefixes used by release binaries and local builds.
	if strings.HasPrefix(base, "php2shell") {
		return true
	}
	return false
}

// IsPHPRuntimeProcessName matches real PHP/LiteSpeed SAPIs and rejects the scanner.
func IsPHPRuntimeProcessName(name string) bool {
	if IsScannerProcessName(name) {
		return false
	}
	base := filepath.Base(strings.TrimSpace(name))
	low := strings.ToLower(base)
	if low == "w3wp.exe" {
		return true
	}
	return phpBin.MatchString(base)
}

func scannerSelfPID() int { return os.Getpid() }
