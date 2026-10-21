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
