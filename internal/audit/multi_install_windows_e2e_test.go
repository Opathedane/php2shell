package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMultiVersionWindowsPATHIISAndConfigRoot reproduces three independent PHP
// installs on one Windows-style host:
//  1. PATH-selected CLI under Temp\PHP\current (8.3.24)
//  2. IIS FastCGI handler under PHP\8.4.24 (php-cgi.exe)
//  3. Custom --config-root under CustomApps\php-8.2.34
// Expectations: three separate install groups/CSV rows, independent patch thresholds,
// php.ini correlated per install, no false alias merge, incomplete-coverage language,
// HTML+CSV both list all three. Binaries are never executed.
func TestMultiVersionWindowsPATHIISAndConfigRoot(t *testing.T) {
	root := t.TempDir()

	// --- Install 1: PATH-selected ---
	pathPHP := filepath.Join(root, "Temp", "PHP", "current")
	if err := os.MkdirAll(pathPHP, 0755); err != nil {
		t.Fatal(err)
	}
	pathBinName := "php"
	if runtime.GOOS == "windows" {
		pathBinName = "php.exe"
	}
	pathBin := filepath.Join(pathPHP, pathBinName)
	pathIni := filepath.Join(pathPHP, "php.ini")
	_ = os.WriteFile(pathBin, []byte("MZ\x00 PATH-selected PHP Version 8.3.24 marker"), 0644)
	_ = os.WriteFile(pathIni, []byte("memory_limit = 128M\n"), 0644)

	// --- Install 2: IIS handler (different tree, different version) ---
	iisPHP := filepath.Join(root, "PHP", "8.4.24")
	siteDir := filepath.Join(root, "websites", "prod", "app")
	_ = os.MkdirAll(iisPHP, 0755)
	_ = os.MkdirAll(siteDir, 0755)
	iisCGI := filepath.Join(iisPHP, "php-cgi.exe")
	iisIni := filepath.Join(iisPHP, "php.ini")
	_ = os.WriteFile(iisCGI, []byte("MZ\x00 IIS-handler PHP Version 8.4.24 marker"), 0644)
	_ = os.WriteFile(iisIni, []byte("memory_limit = 256M\n"), 0644)

	hostXML := `<?xml version="1.0"?><configuration><system.applicationHost><sites>` +
		`<site name="multiapp"><application path="/"><virtualDirectory path="/" physicalPath="` + siteDir + `"/>` +
		`</application></site></sites></system.applicationHost>` +
		`<system.webServer><fastCgi><application fullPath="` + iisCGI + `"/></fastCgi>` +
		`<handlers><add name="PHP_via_FastCGI" path="*.php" verb="*" modules="FastCgiModule" ` +
		`scriptProcessor="` + iisCGI + `|-c ` + iisIni + `"/></handlers>` +
		`</system.webServer></configuration>`

	// --- Install 3: custom root only (not on PATH, not IIS) ---
	customRoot := filepath.Join(root, "CustomApps", "php-8.2.34")
	_ = os.MkdirAll(customRoot, 0755)
	customBinName := "php"
	if runtime.GOOS == "windows" {
		customBinName = "php.exe"
	}
	customBin := filepath.Join(customRoot, customBinName)
	customIni := filepath.Join(customRoot, "php.ini")
	_ = os.WriteFile(customBin, []byte("MZ\x00 custom-root PHP Version 8.2.34 marker"), 0644)
	_ = os.WriteFile(customIni, []byte("memory_limit = 64M\n"), 0644)

	// PATH only exposes install 1 (first resolvable like Get-Command), plus a decoy empty dir.
	decoy := filepath.Join(root, "decoy-empty")
	_ = os.MkdirAll(decoy, 0755)
	t.Setenv("PATH", pathPHP+string(os.PathListSeparator)+decoy)
	// Avoid LocalAppData Programs\PHP picking up unrelated fixtures.
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "AppData", "Local"))

	r := NewReport("multi-win", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 21, 45, 0, 0, time.UTC)

	// Simulate Windows binary discovery sources that ScanHost would use on GOOS=windows.
	// On non-Windows CI we still exercise the same combination of PATH + IIS + config-root.
	for _, p := range discoverPHPBinsFromPATHEnv(os.Getenv("PATH"), 50) {
		AddBinaryVersionEvidence(r, p, filepath.Base(p), "Windows PATH directory static binary inspection")
	}
	ApplyIISApplicationHostInventory(r, filepath.Join(root, "applicationHost.config"), []byte(hostXML))
	// Authorized custom root binary + ini discovery (as ScanHost does via opts.ConfigRoots).
	foundCustom, warn := discoverPHPBinsUnderProgramsPHP(customRoot, 50)
	if warn != "" {
		t.Fatal(warn)
	}
	for _, p := range foundCustom {
		AddBinaryVersionEvidence(r, p, filepath.Base(p), "operator --config-root static binary inspection")
	}
	scanConfigs(r, HostScanOptions{ConfigRoots: []string{customRoot}})

	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	versions := map[string]bool{}
	for _, e := range r.Evidence {
		switch e.Type {
		case "binary_static_version", "binary_path_inferred_version":
			if e.Version != "" {
				versions[e.Version] = true
			}
		}
	}
	for _, want := range []string{"8.2.34", "8.3.24", "8.4.24"} {
		if !versions[want] {
			t.Fatalf("missing version %s in evidence versions=%v evidence=%+v", want, versions, r.Evidence)
		}
	}

	// php.ini correlated to each install directory where related_binary is set.
	iniHits := map[string]bool{}
	for _, e := range r.Evidence {
		if e.Type != "php_ini_candidate" {
			continue
		}
		related := iisDetailField(e.Detail, "related_binary")
		switch normalizeInstallPath(e.Location) {
		case normalizeInstallPath(pathIni), normalizeInstallPath(iisIni), normalizeInstallPath(customIni):
			iniHits[normalizeInstallPath(e.Location)] = true
			if related == "" {
				t.Fatalf("expected related_binary for %s: %+v", e.Location, e)
			}
		}
	}
	if len(iniHits) != 3 {
		t.Fatalf("expected 3 correlated php.ini candidates, got %d (%v) evidence=%+v", len(iniHits), iniHits, r.Evidence)
	}

	groups := GroupInstallations(r)
	if len(groups) < 3 {
		t.Fatalf("expected >=3 install groups, got %d: %+v", len(groups), groups)
	}
	groupVers := map[string]string{} // version -> minimum fixed
	for _, g := range groups {
		if g.Version == "" {
			continue
		}
		groupVers[g.Version] = g.MinimumFixed
	}
	if groupVers["8.4.24"] != "8.4.27" || groupVers["8.3.24"] != "8.3.36" || groupVers["8.2.34"] != "8.2.35" {
		t.Fatalf("independent thresholds missing: %+v", groupVers)
	}

	// Distinct install keys (no incorrect merge of independent same-host installs).
	keys := map[string]bool{}
	for _, g := range groups {
		if strings.HasPrefix(g.Key, "install:binary-dir:") {
			keys[g.Key] = true
		}
	}
	if len(keys) < 3 {
		t.Fatalf("expected 3 distinct binary-dir install keys, got %d: %v", len(keys), keys)
	}

	html := string(EncodeHTML(r))
	for _, ver := range []string{"8.2.34", "8.3.24", "8.4.24"} {
		if !strings.Contains(html, ver) {
			t.Fatalf("HTML missing version %s", ver)
		}
	}
	if !strings.Contains(html, "8.4.27") || !strings.Contains(html, "8.3.36") || !strings.Contains(html, "8.2.35") {
		t.Fatal("HTML missing per-branch upstream thresholds")
	}

	rows := BuildFleetRows(r)
	if len(rows) < 3 {
		t.Fatalf("CSV must emit one row per install, got %d: %+v", len(rows), rows)
	}
	rowVers := map[string]bool{}
	for _, row := range rows {
		if row.PHPVersion != "" {
			rowVers[row.PHPVersion] = true
		}
		if !strings.Contains(row.LimitationsSummary, "not complete host coverage") &&
			!strings.Contains(row.DiscoveryCompleteness, "PARTIAL") {
			t.Fatalf("expected incomplete-coverage signalling: %+v", row)
		}
	}
	for _, ver := range []string{"8.2.34", "8.3.24", "8.4.24"} {
		if !rowVers[ver] {
			t.Fatalf("fleet CSV missing version %s in %+v", ver, rows)
		}
	}

	// Rollup must preserve all three install rows.
	csvPath := filepath.Join(root, "multi.csv")
	data, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(csvPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "rollup.csv")
	if err := RollupFleetCSV(FleetRollupOptions{InputFiles: []string{csvPath}, Output: out}); err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	sumRows, err := ParseFleetCSV(sum)
	if err != nil {
		t.Fatal(err)
	}
	if len(sumRows) < 3 {
		t.Fatalf("rollup dropped installs: %+v", sumRows)
	}

	// Coverage language must not claim complete host inventory.
	sawCoverage := false
	for _, c := range r.Coverage {
		if c.Name == "binary_paths" && strings.Contains(c.Detail, "not complete host coverage") {
			sawCoverage = true
		}
	}
	// When this test does not call scanBinaries, coverage may be absent — still assert HTML/CSV limits.
	_ = sawCoverage
	_ = runtime.GOOS
}

func TestMultiPATHEntriesAllDiscoveredNotOnlyFirst(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "php-a")
	b := filepath.Join(root, "php-b")
	_ = os.MkdirAll(a, 0755)
	_ = os.MkdirAll(b, 0755)
	name := "php"
	if runtime.GOOS == "windows" {
		name = "php.exe"
	}
	binA := filepath.Join(a, name)
	binB := filepath.Join(b, name)
	_ = os.WriteFile(binA, []byte("PHP Version 8.3.24"), 0644)
	_ = os.WriteFile(binB, []byte("PHP Version 8.4.24"), 0644)

	pathEnv := a + string(os.PathListSeparator) + b
	got := discoverPHPBinsFromPATHEnv(pathEnv, 10)
	if len(got) != 2 {
		t.Fatalf("PATH must return every eligible entry, not only the first; got %v", got)
	}
}

func TestIndependentSameVersionDifferentTreesRemainSeparate(t *testing.T) {
	root := t.TempDir()
	left := filepath.Join(root, "D-drive", "PHP", "8.4.24")
	right := filepath.Join(root, "E-drive", "PHP", "8.4.24")
	_ = os.MkdirAll(left, 0755)
	_ = os.MkdirAll(right, 0755)
	binName := "php"
	if runtime.GOOS == "windows" {
		binName = "php.exe"
	}
	leftBin := filepath.Join(left, binName)
	rightBin := filepath.Join(right, binName)
	// Different content fingerprints — must not alias-merge.
	_ = os.WriteFile(leftBin, []byte("MZ left-install PHP Version 8.4.24 AAA"), 0644)
	_ = os.WriteFile(rightBin, []byte("MZ right-install PHP Version 8.4.24 BBB"), 0644)

	r := NewReport("same-ver", "windows", "amd64")
	AddBinaryVersionEvidence(r, leftBin, binName, "test-left")
	AddBinaryVersionEvidence(r, rightBin, binName, "test-right")
	EvaluatePatchPosture(r)
	groups := GroupInstallations(r)
	if len(groups) < 2 {
		t.Fatalf("independent same-version trees must stay separate: %+v", groups)
	}
	keys := map[string]bool{}
	for _, g := range groups {
		keys[g.Key] = true
	}
	if len(keys) < 2 {
		t.Fatalf("expected distinct install keys: %v", keys)
	}
}
