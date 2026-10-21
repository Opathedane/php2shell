package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeFakePHP(t *testing.T, path, version string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("MZ\x00padding PHP Version " + version + "\x00more")
	if runtime.GOOS != "windows" {
		payload = []byte("ELF\x00 PHP Version " + version + "\x00")
	}
	if err := os.WriteFile(path, payload, 0755); err != nil {
		t.Fatal(err)
	}
}

func phpName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

func TestValidateDeepRootRejectsUnsafe(t *testing.T) {
	if _, err := validateDeepRoot(""); err == nil {
		t.Fatal("expected empty reject")
	}
	if _, err := validateDeepRoot(`\\fileserver\share\php`); err == nil {
		t.Fatal("expected UNC reject")
	}
	if _, err := validateDeepRoot("//fileserver/share/php"); err == nil {
		t.Fatal("expected // UNC reject")
	}
	if runtime.GOOS == "windows" {
		if _, err := validateDeepRoot(`C:\`); err == nil {
			t.Fatal("expected volume root reject")
		}
	} else {
		if _, err := validateDeepRoot("/"); err == nil {
			t.Fatal("expected / reject")
		}
	}
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := validateDeepRoot(missing); err == nil {
		t.Fatal("expected missing reject")
	}
	file := filepath.Join(t.TempDir(), "not-dir")
	_ = os.WriteFile(file, []byte("x"), 0644)
	if _, err := validateDeepRoot(file); err == nil {
		t.Fatal("expected non-dir reject")
	}
}

func TestDeepDiscoverFindsNestedBinsAndInis(t *testing.T) {
	root := t.TempDir()
	binA := filepath.Join(root, "8.2", phpName("php"))
	binB := filepath.Join(root, "nested", "8.4.24", "nts", "x64", phpName("php"))
	binCGI := filepath.Join(root, "apps", "8.3.36", phpName("php-cgi"))
	iniDeep := filepath.Join(root, "nested", "8.4.24", "nts", "x64", "php.ini")
	iniTpl := filepath.Join(root, "nested", "8.4.24", "php.ini-development")
	writeFakePHP(t, binA, "8.2.28")
	writeFakePHP(t, binB, "8.4.24")
	writeFakePHP(t, binCGI, "8.3.36")
	_ = os.MkdirAll(filepath.Dir(iniDeep), 0755)
	_ = os.WriteFile(iniDeep, []byte("memory_limit = 128M\n"), 0644)
	_ = os.WriteFile(iniTpl, []byte("expose_php = Off\n"), 0644)

	out := deepDiscoverUnderRoot(root, time.Now().Add(time.Minute), 50, 50)
	if out.Truncated {
		t.Fatalf("unexpected truncation: %+v", out)
	}
	if len(out.Binaries) < 3 {
		t.Fatalf("expected >=3 binaries, got %v", out.Binaries)
	}
	sawIni, sawTpl := false, false
	for _, p := range out.Inis {
		switch normalizeInstallPath(p) {
		case normalizeInstallPath(iniDeep):
			sawIni = true
		case normalizeInstallPath(iniTpl):
			sawTpl = true
		}
	}
	if !sawIni || !sawTpl {
		t.Fatalf("expected nested ini + template: inis=%v", out.Inis)
	}
}

func TestDeepDiscoverFindsWhatConfigRootMisses(t *testing.T) {
	isolatePHPIniHostDiscovery(t)
	root := t.TempDir()
	deepIni := filepath.Join(root, "a", "b", "c", "php.ini")
	_ = os.MkdirAll(filepath.Dir(deepIni), 0755)
	_ = os.WriteFile(deepIni, []byte("memory_limit = 64M\n"), 0644)
	bin := filepath.Join(root, "a", "b", "c", phpName("php"))
	writeFakePHP(t, bin, "8.4.24")

	rCfg := NewReport("cfg", runtime.GOOS, "amd64")
	scanConfigs(rCfg, HostScanOptions{ConfigRoots: []string{root}}, nil)
	for _, e := range rCfg.Evidence {
		if e.Type == "php_ini_candidate" && normalizeInstallPath(e.Location) == normalizeInstallPath(deepIni) {
			t.Fatal("config-root must not find deeply nested ini")
		}
	}

	rDeep := NewReport("deep", runtime.GOOS, "amd64")
	outcomes := scanBinaries(rDeep, HostScanOptions{DeepRoots: []string{root}})
	scanConfigs(rDeep, HostScanOptions{DeepRoots: []string{root}}, outcomes)

	if len(outcomes) != 1 || len(outcomes[0].Inis) == 0 || len(outcomes[0].Binaries) == 0 {
		t.Fatalf("deep walk must record nested bin+ini in outcome: %+v", outcomes)
	}
	sawBin, sawIni := false, false
	for _, e := range rDeep.Evidence {
		if (e.Type == "binary_static_version" || e.Type == "binary_path" || e.Type == "binary_path_inferred_version") &&
			normalizeInstallPath(e.Location) == normalizeInstallPath(bin) {
			sawBin = true
			if !strings.Contains(e.Source, "--deep-root") {
				t.Fatalf("expected deep-root source, got %q", e.Source)
			}
		}
		if e.Type == "php_ini_candidate" && normalizeInstallPath(e.Location) == normalizeInstallPath(deepIni) {
			sawIni = true
			// May be recorded as sidecar after binary discovery; deep outcome already proved the walk.
		}
	}
	if !sawBin || !sawIni {
		t.Fatalf("deep-root must surface nested bin+ini: bin=%v ini=%v evidence=%+v", sawBin, sawIni, rDeep.Evidence)
	}
}

func TestDeepDiscoverThreeIndependentInstalls(t *testing.T) {
	isolatePHPIniHostDiscovery(t)
	root := t.TempDir()
	// Three independent trees (different content fingerprints).
	p82 := filepath.Join(root, "PHP", "8.2", phpName("php"))
	p84 := filepath.Join(root, "Temp", "PHP", "8.4.24", "nts", "x64", phpName("php"))
	p83 := filepath.Join(root, "Applications", "PHP", "8.3.36", phpName("php-cgi"))
	writeFakePHP(t, p82, "8.2.28")
	writeFakePHP(t, p84, "8.4.24")
	writeFakePHP(t, p83, "8.3.36")
	_ = os.WriteFile(filepath.Join(filepath.Dir(p84), "php.ini"), []byte("memory_limit = 256M\n"), 0644)

	r := NewReport("multi-deep", runtime.GOOS, "amd64")
	ScanHost(r, HostScanOptions{DeepRoots: []string{root}})
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	groups := GroupInstallations(r)
	keys := map[string]bool{}
	versions := map[string]bool{}
	for _, g := range groups {
		if strings.HasPrefix(g.Key, "install:binary-dir:") {
			keys[g.Key] = true
		}
		if g.Version != "" {
			versions[g.Version] = true
		}
	}
	if len(keys) < 3 {
		t.Fatalf("expected >=3 independent installs, got %d keys=%v groups=%+v", len(keys), keys, groups)
	}
	for _, want := range []string{"8.2.28", "8.4.24", "8.3.36"} {
		if !versions[want] {
			t.Fatalf("missing version %s in groups=%+v evidence versions check", want, groups)
		}
	}

	html := string(EncodeHTML(r))
	csvRows := BuildFleetRows(r)
	if len(csvRows) < 3 {
		t.Fatalf("expected >=3 CSV install rows, got %d", len(csvRows))
	}
	if !strings.Contains(html, "8.2.28") || !strings.Contains(html, "8.4.24") || !strings.Contains(html, "8.3.36") {
		snip := html
		if len(snip) > 800 {
			snip = snip[:800]
		}
		t.Fatalf("HTML missing versions: %s", snip)
	}
	for _, row := range csvRows {
		if row.InstallID == "host:no_comparable_install" {
			continue
		}
		if row.DiscoveryCompleteness == "" {
			t.Fatal("empty discovery_completeness")
		}
	}
}

func TestDeepDiscoverDisabledByDefault(t *testing.T) {
	isolatePHPIniHostDiscovery(t)
	root := t.TempDir()
	bin := filepath.Join(root, "hidden", phpName("php"))
	writeFakePHP(t, bin, "8.4.24")

	r := NewReport("no-deep", runtime.GOOS, "amd64")
	ScanHost(r, HostScanOptions{})
	for _, e := range r.Evidence {
		if normalizeInstallPath(e.Location) == normalizeInstallPath(bin) {
			t.Fatal("default scan must not deep-walk unauthorized trees")
		}
		if e.Type == "deep_discovery_coverage" {
			t.Fatal("deep coverage evidence without --deep-root")
		}
	}
	for _, c := range r.Coverage {
		if c.Name == "deep_discovery" {
			t.Fatal("deep_discovery coverage check without --deep-root")
		}
	}
}

func TestDeepDiscoverBinaryRemainCap(t *testing.T) {
	root := t.TempDir()
	writeFakePHP(t, filepath.Join(root, "a", phpName("php")), "8.1.0")
	writeFakePHP(t, filepath.Join(root, "b", phpName("php")), "8.2.0")
	out := deepDiscoverUnderRoot(root, time.Now().Add(time.Minute), 1, 50)
	if len(out.Binaries) > 1 {
		t.Fatalf("binary remain cap violated: %v", out.Binaries)
	}
	if !out.Truncated || out.TruncReason != "binary_limit" {
		t.Fatalf("expected binary_limit truncation, got %+v", out)
	}
}

func TestDeepDiscoverEntryLimitEnforced(t *testing.T) {
	prev := deepEntriesCap
	deepEntriesCap = 5
	t.Cleanup(func() { deepEntriesCap = prev })

	root := t.TempDir()
	for i := 0; i < 20; i++ {
		_ = os.WriteFile(filepath.Join(root, "pad"+itoa(i)+".txt"), []byte("x"), 0644)
	}
	writeFakePHP(t, filepath.Join(root, "deep", "nest", phpName("php")), "8.4.24")
	out := deepDiscoverUnderRoot(root, time.Now().Add(time.Minute), 50, 50)
	if !out.Truncated || out.TruncReason != "entry_limit" {
		t.Fatalf("expected entry_limit truncation, got %+v", out)
	}
	if out.EntriesInspected <= 5 {
		// Cap triggers when inspected > deepEntriesCap
	}
	if out.EntriesInspected > deepEntriesCap+3 {
		t.Fatalf("walk continued far past entry cap: entries=%d", out.EntriesInspected)
	}
}

func TestDeepDiscoverDepthLimitEnforced(t *testing.T) {
	prev := deepDepthCap
	deepDepthCap = 2
	t.Cleanup(func() { deepDepthCap = prev })

	root := t.TempDir()
	shallow := filepath.Join(root, "a", phpName("php"))
	deep := filepath.Join(root, "a", "b", "c", "d", phpName("php"))
	writeFakePHP(t, shallow, "8.2.28")
	writeFakePHP(t, deep, "8.4.24")

	out := deepDiscoverUnderRoot(root, time.Now().Add(time.Minute), 50, 50)
	sawShallow, sawDeep := false, false
	for _, b := range out.Binaries {
		switch normalizeInstallPath(b) {
		case normalizeInstallPath(shallow):
			sawShallow = true
		case normalizeInstallPath(deep):
			sawDeep = true
		}
	}
	if !sawShallow {
		t.Fatalf("shallow binary must be found: %+v", out)
	}
	if sawDeep {
		t.Fatalf("depth cap must hide deeply nested binary: %+v", out)
	}
	if !out.Truncated || out.TruncReason != "depth_budget" {
		t.Fatalf("expected depth_budget truncation, got %+v", out)
	}
}

func TestDeepDiscoverIniLimitEnforced(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		dir := filepath.Join(root, "v"+itoa(i))
		_ = os.MkdirAll(dir, 0755)
		_ = os.WriteFile(filepath.Join(dir, "php.ini"), []byte("memory_limit = 1M\n"), 0644)
	}
	out := deepDiscoverUnderRoot(root, time.Now().Add(time.Minute), 50, 2)
	if len(out.Inis) > 2 {
		t.Fatalf("ini remain cap violated: %v", out.Inis)
	}
	if !out.Truncated || out.TruncReason != "ini_limit" {
		t.Fatalf("expected ini_limit truncation, got %+v", out)
	}
}

func TestDeepDiscoverDurationCapConstantAndDeadline(t *testing.T) {
	if deepDurationCap != maxDeepDiscoverDuration || maxDeepDiscoverDuration != 90*time.Second {
		t.Fatalf("expected 90s deep duration default, got deepDurationCap=%s const=%s", deepDurationCap, maxDeepDiscoverDuration)
	}
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "x"), []byte("x"), 0644)
	out := deepDiscoverUnderRoot(root, time.Now().Add(-time.Second), 50, 50)
	if !out.Truncated || out.TruncReason != "duration" {
		t.Fatalf("expected duration truncation, got %+v", out)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [16]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

func TestDeepDiscoverNoPHPExecution(t *testing.T) {
	isolatePHPIniHostDiscovery(t)
	root := t.TempDir()
	bin := filepath.Join(root, phpName("php"))
	// Marker file that would change if executed as a script — we write a non-executable payload
	// and assert mtime/size unchanged after discovery (static inspect only reads).
	writeFakePHP(t, bin, "8.4.24")
	fiBefore, err := os.Lstat(bin)
	if err != nil {
		t.Fatal(err)
	}
	r := NewReport("noexec", runtime.GOOS, "amd64")
	ScanHost(r, HostScanOptions{DeepRoots: []string{root}})
	fiAfter, err := os.Lstat(bin)
	if err != nil {
		t.Fatal(err)
	}
	if fiBefore.Size() != fiAfter.Size() || !fiBefore.ModTime().Equal(fiAfter.ModTime()) {
		t.Fatal("binary metadata changed; possible execution or rewrite")
	}
	if fiAfter.Mode()&os.ModeSymlink != 0 {
		t.Fatal("unexpected symlink")
	}
}
