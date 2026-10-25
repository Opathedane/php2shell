package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDiscoverPHPBinsUnderProgramsPHPAppDataLayout(t *testing.T) {
	root := t.TempDir()
	// Realistic official Windows installer layout:
	// %LOCALAPPDATA%\Programs\PHP\8.4.24\nts\x64\php.exe
	binDir := filepath.Join(root, "8.4.24", "nts", "x64")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	php := filepath.Join(binDir, "php.exe")
	// Embed a PHP version marker for static inspection (also used by end-to-end test).
	payload := []byte("MZ\x00\x00 padding PHP Version 8.4.24 Zend Engine more padding")
	if err := os.WriteFile(php, payload, 0644); err != nil {
		t.Fatal(err)
	}
	found, warn := discoverPHPBinsUnderProgramsPHP(root, 50)
	if warn != "" {
		t.Fatal(warn)
	}
	if len(found) != 1 || filepath.Clean(found[0]) != filepath.Clean(php) {
		t.Fatalf("found=%v", found)
	}
}

func TestDiscoverPHPBinsFromPATHEnv(t *testing.T) {
	dir := t.TempDir()
	name := "php"
	if runtime.GOOS == "windows" {
		name = "php.exe"
	}
	bin := filepath.Join(dir, name)
	if err := os.WriteFile(bin, []byte("PHP Version 8.4.24"), 0755); err != nil {
		t.Fatal(err)
	}
	sep := string(os.PathListSeparator)
	pathEnv := dir + sep + filepath.Join(t.TempDir(), "missing")
	got := discoverPHPBinsFromPATHEnv(pathEnv, 10)
	if len(got) != 1 || filepath.Clean(got[0]) != filepath.Clean(bin) {
		t.Fatalf("got=%v", got)
	}
}

func TestWindowsAppDataPHP8424BelowUpstreamFix(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "AppData", "Local", "Programs", "PHP", "8.4.24", "nts", "x64")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	php := filepath.Join(binDir, "php.exe")
	if err := os.WriteFile(php, []byte("header PHP Version 8.4.24 footer"), 0644); err != nil {
		t.Fatal(err)
	}

	r := NewReport("win11", "windows", "amd64")
	AddBinaryVersionEvidence(r, php, "php.exe", "Windows LocalAppData Programs\\PHP static binary inspection")
	if len(r.Evidence) != 1 || r.Evidence[0].Type != "binary_static_version" || r.Evidence[0].Version != "8.4.24" {
		t.Fatalf("evidence=%+v", r.Evidence)
	}
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	if len(r.PatchAssessments) != 1 {
		t.Fatal(r.PatchAssessments)
	}
	a := r.PatchAssessments[0]
	if a.Status != "BELOW_UPSTREAM_FIX" || a.MinimumFixed != "8.4.27" || a.ObservedVersion != "8.4.24" {
		t.Fatalf("%+v", a)
	}
	if r.VulnerabilityStatus != "BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED" {
		t.Fatal(r.VulnerabilityStatus)
	}
	label, vers := humanPHPDetected(r)
	if label != "Yes" || len(vers) != 1 || vers[0] != "8.4.24" {
		t.Fatalf("label=%q vers=%v", label, vers)
	}
	html := string(EncodeHTML(r))
	if !strings.Contains(html, "8.4.24") || !strings.Contains(html, "8.4.27") || !strings.Contains(html, "Update review required") {
		t.Fatal("report missing patch guidance")
	}
	// Installed CLI evidence must not be framed as verified active web runtime.
	rt, detail := humanRuntime(r)
	if rt == "Verified" {
		t.Fatal("must not claim verified web runtime from CLI binary alone")
	}
	if !strings.Contains(strings.ToLower(detail), "not verified") && rt != "Candidates identified" {
		t.Fatalf("runtime=%q detail=%q", rt, detail)
	}
}

func TestDiscoverSkipsSymlinkBinaries(t *testing.T) {
	// Windows PATH discovery still rejects file symlinks via isSafeRegularFile.
	// Unix resolves phpBin file symlinks — see unix_php_symlink_discover_test.go.
	if runtime.GOOS != "windows" {
		t.Skip("Unix PATH resolves PHP file symlinks; Windows policy covered below when symlinks are available")
	}
	root := t.TempDir()
	real := filepath.Join(root, "real-php.exe")
	if err := os.WriteFile(real, []byte("PHP Version 8.4.24"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "php.exe")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink creation often requires elevation on Windows: %v", err)
	}
	got := discoverPHPBinsFromPATHEnv(root, 10)
	if len(got) != 0 {
		t.Fatalf("Windows PATH must skip file symlink binaries: %v", got)
	}
}

func TestNoBinaryFindingsDoNotClaimSafe(t *testing.T) {
	r := NewReport("empty", "windows", "amd64")
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	// Bare report (no inventory coverage rows) stays coverage-limited — not a PHP-free claim.
	if r.Summary.PHPDiscovery != "NO_PHP_EVIDENCE_FOUND_COVERAGE_LIMITED" {
		t.Fatal(r.Summary.PHPDiscovery)
	}
	html := string(EncodeHTML(r))
	if strings.Contains(strings.ToLower(html), "php is absent") || strings.Contains(strings.ToLower(html), "host is safe") {
		t.Fatal("must not claim absence/safety")
	}
	label, _ := humanPHPDetected(r)
	if label == "Yes" {
		t.Fatal(label)
	}

	r2 := NewReport("empty-covered", "windows", "amd64")
	r2.AddCheck("packages", "NOT_SUPPORTED", "No passive native package database reader for this OS")
	r2.AddCheck("binary_paths", "PARTIAL", "Found 0")
	r2.AddCheck("windows_processes", "PARTIAL", "Observed 0")
	EvaluatePatchPosture(r2)
	FinalizeSummary(r2)
	if r2.Summary.PHPDiscovery != "NO_PHP_DETECTED_WITHIN_SCAN_COVERAGE" {
		t.Fatal(r2.Summary.PHPDiscovery)
	}
	html2 := strings.ToLower(string(EncodeHTML(r2)))
	for _, bad := range []string{"php is confirmed absent", "host is cleared", "no further action required", "marked safe"} {
		if strings.Contains(html2, bad) {
			t.Fatalf("coverage-complete no-PHP must still refuse absence/safety claims (%q)", bad)
		}
	}
	if !strings.Contains(html2, "does not prove") {
		t.Fatal("expected uncertainty disclaimer")
	}
}
