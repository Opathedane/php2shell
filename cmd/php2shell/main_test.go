package main

import (
	"os"
	"path/filepath"
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
		case strings.HasSuffix(e.Name(), ".json"):
			t.Fatal("JSON must not be written by scan")
		}
	}
	if html != 1 || csv != 1 {
		t.Fatalf("expected 1 html + 1 csv, got html=%d csv=%d entries=%v", html, csv, entries)
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
