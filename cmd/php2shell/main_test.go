package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Opathedane/php2shell/internal/audit"
)

func TestRunScanHTMLOnlyQuiet(t *testing.T) {
	dir := t.TempDir()
	code := run([]string{"scan", "--quiet", "--output-dir", dir, "--timeout", "5m"})
	if code != audit.ExitOK && code != audit.ExitIncomplete {
		t.Fatalf("unexpected exit %d", code)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one HTML report, got %+v", entries)
	}
	name := entries[0].Name()
	if !strings.HasPrefix(name, "php2shell-") || !strings.HasSuffix(name, ".html") {
		t.Fatal(name)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") || strings.HasSuffix(e.Name(), ".csv") {
			t.Fatal("JSON/CSV must not be written")
		}
	}
}

func TestRunScanOutExplicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-report.html")
	code := run([]string{"scan", "--quiet", "--out", path})
	if code != audit.ExitOK && code != audit.ExitIncomplete {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	code = run([]string{"scan", "--quiet", "--out", path})
	if code != audit.ExitFatal {
		t.Fatalf("overwrite should be fatal, got %d", code)
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
