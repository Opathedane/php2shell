package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// End-to-end regressions for non-standard php.ini locations, operator paths,
// configuration-only visibility, skip diagnostics, and nearby-binary probing.
// Customer-specific paths are still unknown; these fixtures model realistic layouts.

func TestOperatorPHPIniDiscoversNonStandardConfigOnly(t *testing.T) {
	root := t.TempDir()
	// Non-standard tree outside well-known patterns (custom Windows-like or Linux layout).
	custom := filepath.Join(root, "Apps", "CustomPHP", "runtime")
	if err := os.MkdirAll(custom, 0755); err != nil {
		t.Fatal(err)
	}
	ini := filepath.Join(custom, "php.ini")
	body := "memory_limit = 256M\nexpose_php = Off\nsession.upload_progress.enabled = On\npassword = must-not-leak\n"
	if err := os.WriteFile(ini, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	r := NewReport("op-ini", runtime.GOOS, "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 21, 0, 0, 0, time.UTC)
	scanConfigs(r, HostScanOptions{PHPIniPaths: []string{ini}})
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	found := false
	for _, e := range r.Evidence {
		if e.Type == "php_ini_candidate" && normalizeInstallPath(e.Location) == normalizeInstallPath(ini) {
			found = true
			if strings.Contains(strings.ToLower(e.Detail), "must-not-leak") {
				t.Fatalf("secret leaked in candidate: %+v", e)
			}
			if !strings.Contains(e.Detail, "correlated_install=none") {
				t.Fatalf("expected uncorrelated marker: %+v", e)
			}
		}
		if strings.Contains(strings.ToLower(e.Detail+e.Location), "must-not-leak") {
			t.Fatalf("secret leaked: %+v", e)
		}
	}
	if !found {
		t.Fatalf("operator --php-ini must surface candidate: %+v", r.Evidence)
	}
	if len(r.PatchAssessments) != 0 {
		t.Fatal("ini-only must not create patch assessments")
	}
	label, vers := humanPHPDetected(r)
	if !strings.HasPrefix(label, "PHP configuration candidates") || len(vers) != 0 {
		t.Fatalf("label=%q vers=%v", label, vers)
	}
	html := string(EncodeHTML(r))
	if !strings.Contains(html, "PHP configuration candidates (no confirmed install)") {
		t.Fatal("HTML must surface configuration-only section")
	}
	if !strings.Contains(html, filepath.Base(ini)) {
		t.Fatal("HTML must list ini basename")
	}
	rows := BuildFleetRows(r)
	if len(rows) != 1 || rows[0].PHPVersion != "" {
		t.Fatalf("%+v", rows)
	}
	if rows[0].ConfigCandidateCount == "0" {
		t.Fatal(rows[0])
	}
	if rows[0].ConfigPrimaryIniPath == "" {
		t.Fatal("fleet host row should carry primary ini path for visibility")
	}
	if !strings.Contains(rows[0].ConfigDiscoveryStatus, "UNCORRELATED") &&
		!strings.Contains(rows[0].ConfigDiscoveryStatus, "PRIMARY") {
		t.Fatal(rows[0].ConfigDiscoveryStatus)
	}
	if !strings.Contains(rows[0].LimitationsSummary, "uncorrelated") {
		t.Fatal(rows[0].LimitationsSummary)
	}
}

func TestOperatorConfigRootBoundedDiscovery(t *testing.T) {
	root := t.TempDir()
	confD := filepath.Join(root, "conf.d")
	if err := os.MkdirAll(confD, 0755); err != nil {
		t.Fatal(err)
	}
	ini := filepath.Join(root, "php.ini")
	frag := filepath.Join(confD, "opcache.ini")
	deep := filepath.Join(root, "nested", "deep", "php.ini")
	_ = os.MkdirAll(filepath.Dir(deep), 0755)
	_ = os.WriteFile(ini, []byte("memory_limit = 64M\n"), 0644)
	_ = os.WriteFile(frag, []byte("expose_php = Off\n"), 0644)
	_ = os.WriteFile(deep, []byte("memory_limit = 1M\n"), 0644)

	r := NewReport("cfg-root", runtime.GOOS, "amd64")
	scanConfigs(r, HostScanOptions{ConfigRoots: []string{root}})

	sawPrimary, sawFrag, sawDeep := false, false, false
	for _, e := range r.Evidence {
		if e.Type != "php_ini_candidate" {
			continue
		}
		switch normalizeInstallPath(e.Location) {
		case normalizeInstallPath(ini):
			sawPrimary = true
		case normalizeInstallPath(frag):
			sawFrag = true
		case normalizeInstallPath(deep):
			sawDeep = true
		}
	}
	if !sawPrimary || !sawFrag {
		t.Fatalf("expected root php.ini + conf.d fragment: primary=%v frag=%v evidence=%+v", sawPrimary, sawFrag, r.Evidence)
	}
	if sawDeep {
		t.Fatal("--config-root must not deep-walk nested trees")
	}
}

func TestNearbyBinaryDiscoveredFromIniDirectory(t *testing.T) {
	root := t.TempDir()
	ini := filepath.Join(root, "php.ini")
	binName := "php"
	if runtime.GOOS == "windows" {
		binName = "php.exe"
	}
	bin := filepath.Join(root, binName)
	_ = os.WriteFile(ini, []byte("memory_limit = 128M\n"), 0644)
	_ = os.WriteFile(bin, []byte("PHP Version 8.4.24\x00padding"), 0644)

	r := NewReport("nearby", runtime.GOOS, "amd64")
	scanConfigs(r, HostScanOptions{PHPIniPaths: []string{ini}})

	sawBin, related := false, false
	for _, e := range r.Evidence {
		switch e.Type {
		case "binary_static_version", "binary_path_inferred_version", "binary_path":
			if normalizeInstallPath(e.Location) == normalizeInstallPath(bin) {
				sawBin = true
			}
		case "php_ini_candidate":
			if strings.Contains(e.Detail, "related_binary=") {
				related = true
			}
		}
	}
	if !sawBin {
		t.Fatalf("expected nearby binary from ini dir: %+v", r.Evidence)
	}
	if !related {
		t.Fatalf("expected correlation after nearby probe: %+v", r.Evidence)
	}
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	label, _ := humanPHPDetected(r)
	if !strings.HasPrefix(label, "Yes") {
		t.Fatalf("nearby binary should confirm install evidence: %q", label)
	}
}

func TestPHPIniSkipCoverageVisibleInHTMLAndCSV(t *testing.T) {
	root := t.TempDir()
	denied := filepath.Join(root, "php.ini")
	_ = os.WriteFile(denied, []byte("memory_limit = 1M\nsecret=do-not-show\n"), 0644)

	orig := readPHPIniContents
	t.Cleanup(func() { readPHPIniContents = orig })
	readPHPIniContents = func(path string, max int64) ([]byte, error) {
		if filepath.Clean(path) == filepath.Clean(denied) {
			return nil, os.ErrPermission
		}
		return ReadRegular(path, max)
	}

	r := NewReport("skip-vis", runtime.GOOS, "amd64")
	scanConfigs(r, HostScanOptions{PHPIniPaths: []string{denied}})
	FinalizeSummary(r)

	skips := 0
	for _, e := range r.Evidence {
		if e.Type == "php_ini_skip" {
			skips++
			if strings.Contains(e.Detail, "do-not-show") {
				t.Fatal(e.Detail)
			}
		}
		if e.Type == "php_ini_candidate" {
			t.Fatal("denied path must not be a candidate")
		}
	}
	if skips == 0 {
		t.Fatal("expected php_ini_skip")
	}
	html := string(EncodeHTML(r))
	if !strings.Contains(html, "php_ini_skip") && !strings.Contains(html, "CONFIG_CANDIDATE_NOT_INSPECTED") {
		t.Fatal("HTML should show skip interpretation")
	}
	rows := BuildFleetRows(r)
	if !strings.Contains(rows[0].ConfigDiscoveryStatus, "COVERAGE") &&
		!strings.Contains(rows[0].LimitationsSummary, "skipped") {
		t.Fatalf("%+v", rows[0])
	}
	warn := false
	for _, w := range r.Warnings {
		if strings.Contains(w, "coverage incomplete") {
			warn = true
		}
	}
	if !warn {
		t.Fatalf("expected coverage warning: %v", r.Warnings)
	}
}

func TestLinuxStyleNonStandardConfigRootLayout(t *testing.T) {
	// Mimics /opt/app/php/etc/php.ini style without requiring /opt write access.
	root := t.TempDir()
	etc := filepath.Join(root, "opt", "app", "php", "etc")
	binDir := filepath.Join(root, "opt", "app", "php", "bin")
	_ = os.MkdirAll(etc, 0755)
	_ = os.MkdirAll(binDir, 0755)
	ini := filepath.Join(etc, "php.ini")
	_ = os.WriteFile(ini, []byte("upload_max_filesize = 20M\n"), 0644)

	r := NewReport("linux-layout", "linux", "amd64")
	scanConfigs(r, HostScanOptions{ConfigRoots: []string{etc}})
	FinalizeSummary(r)

	found := false
	for _, e := range r.Evidence {
		if e.Type == "php_ini_candidate" && normalizeInstallPath(e.Location) == normalizeInstallPath(ini) {
			found = true
		}
	}
	if !found {
		t.Fatal(r.Evidence)
	}
	label, vers := humanPHPDetected(r)
	if !strings.Contains(label, "configuration candidates") || len(vers) != 0 {
		t.Fatalf("%q %v", label, vers)
	}
}

func TestWindowsStyleNonStandardOperatorIni(t *testing.T) {
	// Mimics D:\Apps\PHP\php.ini style under a temp root (portable).
	root := t.TempDir()
	dir := filepath.Join(root, "Apps", "PHP", "8.3")
	_ = os.MkdirAll(dir, 0755)
	ini := filepath.Join(dir, "php.ini")
	_ = os.WriteFile(ini, []byte("post_max_size = 32M\n"), 0644)

	r := NewReport("win-layout", "windows", "amd64")
	scanConfigs(r, HostScanOptions{PHPIniPaths: []string{ini}})
	html := string(EncodeHTML(r))
	if !strings.Contains(html, "configuration candidates") && !strings.Contains(html, "php.ini") {
		t.Fatalf("HTML missing configuration visibility (%d bytes)", len(html))
	}
	steps := BuildFocusedNextSteps(r)
	joined := strings.Join(steps, " ")
	if !strings.Contains(joined, "uncorrelated php.ini") && !strings.Contains(joined, "--php-ini") {
		t.Fatalf("next steps should mention uncorrelated config: %v", steps)
	}
}
