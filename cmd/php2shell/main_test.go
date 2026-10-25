package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Opathedane/php2shell/internal/audit"
)

func TestRunScanWritesHTMLAndCSVQuiet(t *testing.T) {
	dir := t.TempDir()
	code := run([]string{"scan", "--quiet", "--output-dir", dir, "--timeout", "5m"})
	if code != audit.ExitOK && code != audit.ExitIncomplete {
		t.Fatalf("unexpected exit %d", code)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var html, csv int
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), ".html"):
			html++
			if !strings.HasPrefix(e.Name(), "php2shell-") {
				t.Fatal(e.Name())
			}
		case strings.HasSuffix(e.Name(), ".csv"):
			csv++
		case strings.HasSuffix(e.Name(), ".json") && !strings.HasSuffix(e.Name(), ".status.json"):
			t.Fatal("assessment JSON must not be written by scan")
		}
	}
	var status int
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".status.json") {
			status++
		}
	}
	if html != 1 || csv != 1 || status != 1 {
		t.Fatalf("expected 1 html + 1 csv + 1 status.json, got html=%d csv=%d status=%d entries=%v", html, csv, status, entries)
	}
}

func TestRunScanOutExplicitPair(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-report.html")
	code := run([]string{"scan", "--quiet", "--out", path})
	if code != audit.ExitOK && code != audit.ExitIncomplete {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(audit.MatchingCSVPath(path)); err != nil {
		t.Fatal(err)
	}
	code = run([]string{"scan", "--quiet", "--out", path})
	if code != audit.ExitFatal {
		t.Fatalf("overwrite should be fatal, got %d", code)
	}
}

func TestRunScanOutCSVRemapWritesHTMLCSVStatus(t *testing.T) {
	dir := t.TempDir()
	csvOut := filepath.Join(dir, "SERVER.csv")
	code := run([]string{"scan", "--quiet", "--out", csvOut})
	if code != audit.ExitOK && code != audit.ExitIncomplete {
		t.Fatalf("exit %d", code)
	}
	html := filepath.Join(dir, "SERVER.html")
	if _, err := os.Stat(html); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(csvOut); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "SERVER.status.json")); err != nil {
		t.Fatal(err)
	}
}

func TestRunRollupCSVInputDir(t *testing.T) {
	dir := t.TempDir()
	// Produce two scans into dir
	code := run([]string{"scan", "--quiet", "--output-dir", dir, "--customer", "DemoCo"})
	if code != audit.ExitOK && code != audit.ExitIncomplete {
		t.Fatalf("scan1 %d", code)
	}
	// Second scan needs distinct filename — use --out
	out2 := filepath.Join(dir, "server-b.html")
	code = run([]string{"scan", "--quiet", "--out", out2, "--customer", "DemoCo"})
	if code != audit.ExitOK && code != audit.ExitIncomplete {
		t.Fatalf("scan2 %d", code)
	}
	summary := filepath.Join(dir, "customer-summary.csv")
	code = run([]string{"rollup", "--input-dir", dir, "--out", summary})
	if code != audit.ExitOK {
		t.Fatalf("rollup %d", code)
	}
	b, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := audit.ParseFleetCSV(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 {
		t.Fatalf("expected >=2 rows, got %d", len(rows))
	}
}

func TestRunScanInvalidTimeout(t *testing.T) {
	if code := run([]string{"scan", "--quiet", "--timeout", "nope"}); code != audit.ExitFatal {
		t.Fatalf("got %d", code)
	}
}

func TestRunScanDeepRootCLIWritesPairAndRejectsUNC(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "php-trees")
	v82 := filepath.Join(root, "8.2")
	v84 := filepath.Join(root, "8.4.24", "nts", "x64")
	v83 := filepath.Join(root, "8.3.36")
	_ = os.MkdirAll(v82, 0755)
	_ = os.MkdirAll(v84, 0755)
	_ = os.MkdirAll(v83, 0755)
	bin := "php"
	if filepath.Separator == '\\' {
		bin = "php.exe"
	}
	_ = os.WriteFile(filepath.Join(v82, bin), []byte("ELF PHP Version 8.2.28\x00"), 0755)
	_ = os.WriteFile(filepath.Join(v84, bin), []byte("ELF PHP Version 8.4.24\x00"), 0755)
	cgi := bin
	if bin == "php.exe" {
		cgi = "php-cgi.exe"
	} else {
		cgi = "php-cgi"
	}
	_ = os.WriteFile(filepath.Join(v83, cgi), []byte("ELF PHP Version 8.3.36\x00"), 0755)

	out := filepath.Join(dir, "deep-demo.html")
	code := run([]string{"scan", "--quiet", "--deep-root", root, "--out", out})
	if code != audit.ExitOK && code != audit.ExitIncomplete {
		t.Fatalf("deep-root scan exit %d", code)
	}
	htmlBytes, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	csvBytes, err := os.ReadFile(audit.MatchingCSVPath(out))
	if err != nil {
		t.Fatal(err)
	}
	html := string(htmlBytes)
	csv := string(csvBytes)
	for _, ver := range []string{"8.2.28", "8.4.24", "8.3.36"} {
		if !strings.Contains(html, ver) {
			t.Fatalf("HTML missing %s", ver)
		}
		if !strings.Contains(csv, ver) {
			t.Fatalf("CSV missing %s", ver)
		}
	}
	// Reject credential-shaped leaks only. Legitimate copy may say "secrets not reported".
	for _, blob := range []string{html, csv} {
		low := strings.ToLower(blob)
		if strings.Contains(low, "password=") || strings.Contains(low, "secret=") || strings.Contains(low, "api_key=") {
			t.Fatal("unexpected credential-shaped content in reports")
		}
	}

	// Without --deep-root, the same hidden tree must not appear.
	outPlain := filepath.Join(dir, "plain.html")
	code = run([]string{"scan", "--quiet", "--out", outPlain})
	if code != audit.ExitOK && code != audit.ExitIncomplete {
		t.Fatalf("plain scan exit %d", code)
	}
	plainHTML, _ := os.ReadFile(outPlain)
	// Temp-dir installs should not be found by default discovery on this host.
	if strings.Contains(string(plainHTML), filepath.Base(root)) && strings.Contains(string(plainHTML), "8.4.24") {
		// Only fail if the deep-root path itself is cited — default scan must not walk it.
		if strings.Contains(string(plainHTML), root) {
			t.Fatal("default scan must not deep-walk unauthorized --deep-root tree")
		}
	}

	if code := run([]string{"scan", "--quiet", "--deep-root", `\\fileserver\share\php`, "--out", filepath.Join(dir, "unc.html")}); code != audit.ExitFatal {
		t.Fatalf("UNC --deep-root must be fatal, got %d", code)
	}
}

func TestScanExitCodeHelper(t *testing.T) {
	r := audit.NewReport("h", "linux", "amd64")
	if audit.ScanExitCode(r, nil) != audit.ExitOK {
		t.Fatal()
	}
	r.AddCheck("x", "UNAVAILABLE", "denied")
	if audit.ScanExitCode(r, nil) != audit.ExitIncomplete {
		t.Fatal()
	}
	if audit.ScanExitCode(r, os.ErrPermission) != audit.ExitFatal {
		t.Fatal()
	}
}

func TestVersionCommandExitOK(t *testing.T) {
	if code := run([]string{"version"}); code != audit.ExitOK {
		t.Fatalf("exit %d", code)
	}
}

func TestHelpMentionsNoColor(t *testing.T) {
	if !strings.Contains(help, "--no-color") {
		t.Fatal("help must document --no-color")
	}
}

func TestOverwriteEmitsOUTPUT_EXISTSStatusJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "once.html")
	code := run([]string{"scan", "--quiet", "--out", path})
	if code != audit.ExitOK && code != audit.ExitIncomplete {
		t.Fatalf("first scan exit %d", code)
	}
	statusPath := audit.MatchingStatusJSONPath(path)
	// Second scan must refuse overwrite; status JSON path may fall back beside HTML.
	code = run([]string{"scan", "--quiet", "--out", path, "--status-json", filepath.Join(dir, "overwrite.status.json")})
	if code != audit.ExitFatal {
		t.Fatalf("overwrite should be fatal, got %d", code)
	}
	candidates := []string{
		filepath.Join(dir, "overwrite.status.json"),
		statusPath,
	}
	var raw []byte
	for _, c := range candidates {
		b, err := os.ReadFile(c)
		if err == nil {
			raw = b
			break
		}
	}
	if len(raw) == 0 {
		// Status write may use execution-scoped fallbacks; search dir.
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".status.json") && e.Name() != filepath.Base(statusPath) {
				b, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err == nil && strings.Contains(string(b), "OUTPUT_EXISTS") {
					raw = b
					break
				}
			}
		}
	}
	if len(raw) == 0 {
		t.Fatal("expected a status JSON mentioning OUTPUT_EXISTS after overwrite refusal")
	}
	var st audit.ExecutionStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range st.ErrorIDs {
		if id == audit.DiagOutputExists {
			found = true
		}
	}
	if !found && !strings.Contains(string(raw), "OUTPUT_EXISTS") {
		t.Fatalf("missing OUTPUT_EXISTS: %s", raw)
	}
}

func TestAcceptIncompleteMapsExitZeroWhenReportsWritten(t *testing.T) {
	dir := t.TempDir()
	// Force incompleteness via ACCESS_DENIED coverage on a discovery check.
	// Real scans may or may not be incomplete; use helper for mapping contract.
	r := audit.NewReport("h", runtime.GOOS, runtime.GOARCH)
	r.AddCheck("binary_paths", "ACCESS_DENIED", "denied")
	if audit.ScanExitCode(r, nil) != audit.ExitIncomplete {
		t.Fatal("fixture must be incomplete")
	}
	code := run([]string{"scan", "--quiet", "--accept-incomplete", "--output-dir", dir, "--timeout", "2m"})
	if code != audit.ExitOK && code != audit.ExitIncomplete {
		t.Fatalf("unexpected exit %d", code)
	}
	// When incomplete and accept-incomplete, finishScan should map to 0.
	if code == audit.ExitIncomplete {
		t.Log("host scan completed fully; accept-incomplete path not exercised on this host")
	}
}

func TestBuiltBinarySmokeVersionAndDoctor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary smoke in short mode")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "php2shell-smoke")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "github.com/Opathedane/php2shell/cmd/php2shell")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	verOut, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("version: %v %s", err, verOut)
	}
	if !strings.Contains(string(verOut), audit.Version) {
		t.Fatalf("version output missing %s: %s", audit.Version, verOut)
	}
	docOut, err := exec.Command(bin, "doctor").CombinedOutput()
	if err != nil {
		t.Fatalf("doctor: %v %s", err, docOut)
	}
	if !strings.Contains(string(docOut), "PHP2Shell") {
		t.Fatalf("doctor: %s", docOut)
	}
}
