package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// isolatePHPIniHostDiscovery clears process env discovery sources and disables
// well-known path globs so operator-path regressions are deterministic across
// Linux/macOS/Windows CI images that may ship real PHP trees under /etc/php,
// Program Files, or PATH.
func isolatePHPIniHostDiscovery(t *testing.T) {
	t.Helper()
	empty := t.TempDir()
	t.Setenv("PATH", empty)
	t.Setenv("PHPRC", "")
	t.Setenv("PHP_INI_SCAN_DIR", "")
	t.Setenv("LOCALAPPDATA", filepath.Join(empty, "LocalAppData"))
	t.Setenv("ProgramFiles", filepath.Join(empty, "ProgramFiles"))
	orig := phpIniWellKnownPatternsFn
	phpIniWellKnownPatternsFn = func() []string { return nil }
	t.Cleanup(func() { phpIniWellKnownPatternsFn = orig })
}

// denyPHPIniRead stubs readPHPIniContents for one path using normalized path
// comparison (case/separator safe on Windows).
func denyPHPIniRead(t *testing.T, denied string) {
	t.Helper()
	deniedKey := normalizeInstallPath(denied)
	orig := readPHPIniContents
	t.Cleanup(func() { readPHPIniContents = orig })
	readPHPIniContents = func(path string, max int64) ([]byte, error) {
		if normalizeInstallPath(path) == deniedKey {
			return nil, os.ErrPermission
		}
		return ReadRegular(path, max)
	}
}
