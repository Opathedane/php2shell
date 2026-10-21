package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestResolvePlainDirOrdinary(t *testing.T) {
	dir := t.TempDir()
	got, follows, err := resolvePlainDir(dir)
	if err != nil || follows != 0 || filepath.Clean(got) != filepath.Clean(dir) {
		t.Fatalf("got=%q follows=%d err=%v", got, follows, err)
	}
}

func TestResolvePlainDirSymlinkChain(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "8.4.24")
	if err := os.MkdirAll(real, 0755); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "current")
	if err := os.Symlink(real, current); err != nil {
		t.Skipf("symlink/junction required for this regression: %v", err)
	}
	got, follows, err := resolvePlainDir(current)
	if err != nil {
		t.Fatal(err)
	}
	if follows < 1 {
		t.Fatalf("expected reparse follow, follows=%d", follows)
	}
	if filepath.Clean(got) != filepath.Clean(real) {
		t.Fatalf("got=%q want=%q", got, real)
	}
}

func TestResolvePlainDirRejectsCycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Creating mutual directory junctions portably is awkward; exercise via two symlinks on Unix.
	}
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	if err := os.MkdirAll(filepath.Join(root, "real"), 0755); err != nil {
		t.Fatal(err)
	}
	// a -> b, b -> a
	if err := os.Symlink(b, a); err != nil {
		t.Skipf("symlink required: %v", err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Skipf("symlink required: %v", err)
	}
	_, _, err := resolvePlainDir(a)
	if err == nil || !strings.Contains(err.Error(), "cycle") && !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected cycle/exceeds error, got %v", err)
	}
}

func TestPATHDiscoversTempPHPCurrentOrdinaryDir(t *testing.T) {
	// Reproduces TestVM layout: C:\Temp\PHP\current\{php.exe,php.ini} as a plain directory on PATH.
	root := t.TempDir()
	current := filepath.Join(root, "Temp", "PHP", "current")
	if err := os.MkdirAll(current, 0755); err != nil {
		t.Fatal(err)
	}
	binName := "php"
	if runtime.GOOS == "windows" {
		binName = "php.exe"
	}
	bin := filepath.Join(current, binName)
	ini := filepath.Join(current, "php.ini")
	if err := os.WriteFile(bin, []byte("MZ padding PHP Version 8.4.24 zend"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ini, []byte("memory_limit = 128M\nexpose_php = Off\n"), 0644); err != nil {
		t.Fatal(err)
	}

	got := discoverPHPBinsFromPATHEnv(current, 10)
	if len(got) != 1 || filepath.Clean(got[0]) != filepath.Clean(bin) {
		t.Fatalf("PATH ordinary current must find binary: %v", got)
	}

	t.Setenv("PATH", current)
	r := NewReport("testvm", runtime.GOOS, "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 21, 30, 0, 0, time.UTC)
	for _, p := range discoverPHPBinsFromPATHEnv(os.Getenv("PATH"), 10) {
		AddBinaryVersionEvidence(r, p, filepath.Base(p), "Windows PATH directory static binary inspection")
	}
	scanConfigs(r, HostScanOptions{})
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	if label, _ := humanPHPDetected(r); !strings.HasPrefix(label, "Yes") {
		t.Fatalf("expected PHP detected, got %q evidence=%+v", label, r.Evidence)
	}
	sawIni := false
	for _, e := range r.Evidence {
		if e.Type == "php_ini_candidate" && normalizeInstallPath(e.Location) == normalizeInstallPath(ini) {
			sawIni = true
		}
	}
	if !sawIni {
		t.Fatalf("expected php.ini candidate beside PATH binary: %+v", r.Evidence)
	}
	html := string(EncodeHTML(r))
	csv, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, "8.4.24") {
		t.Fatal("HTML missing version")
	}
	if !strings.Contains(string(csv), "8.4.24") {
		t.Fatal("CSV missing version")
	}
}

func TestPATHDiscoversTempPHPCurrentViaSymlinkJunction(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "Temp", "PHP", "8.4.24")
	current := filepath.Join(root, "Temp", "PHP", "current")
	if err := os.MkdirAll(real, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, current); err != nil {
		t.Skipf("symlink/junction required (Developer Mode / privileges on Windows): %v", err)
	}
	binName := "php"
	if runtime.GOOS == "windows" {
		binName = "php.exe"
	}
	bin := filepath.Join(real, binName)
	ini := filepath.Join(real, "php.ini")
	_ = os.WriteFile(bin, []byte("PHP Version 8.4.24"), 0644)
	_ = os.WriteFile(ini, []byte("memory_limit = 64M\n"), 0644)

	// PATH points at the junction/symlink name (what Get-Command / where.exe expose).
	got := discoverPHPBinsFromPATHEnv(current, 10)
	if len(got) != 1 {
		t.Fatalf("PATH via current junction must find binary, got %v", got)
	}
	if filepath.Clean(got[0]) != filepath.Clean(bin) {
		t.Fatalf("expected resolved binary path %q, got %q", bin, got[0])
	}

	t.Setenv("PATH", current)
	r := NewReport("testvm-junc", runtime.GOOS, "amd64")
	for _, p := range got {
		AddBinaryVersionEvidence(r, p, filepath.Base(p), "Windows PATH directory static binary inspection")
	}
	scanConfigs(r, HostScanOptions{})
	sawIni := false
	for _, e := range r.Evidence {
		if e.Type == "php_ini_candidate" && normalizeInstallPath(e.Location) == normalizeInstallPath(ini) {
			sawIni = true
			if !strings.Contains(e.Source, "PATH") && !strings.Contains(e.Source, "sidecar") {
				// either PATH dir config or binary sidecar is fine
			}
		}
	}
	if !sawIni {
		t.Fatalf("php.ini on resolved target must be visible: %+v", r.Evidence)
	}
}

func TestOperatorPHPIniTempPHPCurrentConfigOnly(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "Temp", "PHP", "current")
	_ = os.MkdirAll(current, 0755)
	ini := filepath.Join(current, "php.ini")
	_ = os.WriteFile(ini, []byte("memory_limit = 256M\npassword=secret\n"), 0644)

	r := NewReport("ini-only-temp", runtime.GOOS, "amd64")
	scanConfigs(r, HostScanOptions{PHPIniPaths: []string{ini}})
	FinalizeSummary(r)
	label, vers := humanPHPDetected(r)
	if !strings.Contains(label, "configuration candidates") || len(vers) != 0 {
		t.Fatalf("label=%q vers=%v", label, vers)
	}
	for _, e := range r.Evidence {
		if strings.Contains(e.Detail, "secret") && e.Type != "php_ini_skip" {
			if strings.Contains(e.Detail, "password=secret") {
				t.Fatal("secret leaked")
			}
		}
	}
	html := string(EncodeHTML(r))
	if !strings.Contains(html, "configuration candidates") {
		t.Fatal("HTML must surface config-only")
	}
}

func TestProgramsPHPWalkResolvesCurrentJunction(t *testing.T) {
	root := t.TempDir()
	versioned := filepath.Join(root, "8.4.24", "nts", "x64")
	_ = os.MkdirAll(versioned, 0755)
	binName := "php"
	if runtime.GOOS == "windows" {
		binName = "php.exe"
	}
	bin := filepath.Join(versioned, binName)
	_ = os.WriteFile(bin, []byte("PHP Version 8.4.24"), 0644)
	current := filepath.Join(root, "current")
	if err := os.Symlink(filepath.Join(root, "8.4.24"), current); err != nil {
		t.Skipf("symlink required: %v", err)
	}
	found, warn := discoverPHPBinsUnderProgramsPHP(root, 50)
	if warn != "" && !strings.Contains(warn, "truncated") {
		t.Fatal(warn)
	}
	ok := false
	for _, p := range found {
		if filepath.Clean(p) == filepath.Clean(bin) {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("expected binary via current junction, found=%v", found)
	}
}
