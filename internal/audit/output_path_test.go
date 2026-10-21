package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSanitizeHostnameForFilename(t *testing.T) {
	cases := map[string]string{
		"":                 "unknown-host",
		"web01":            "web01",
		`BAD<>:"/\|?*NAME`: "BAD---------NAME",
		"host name":        "host-name",
	}
	for in, want := range cases {
		if got := SanitizeHostnameForFilename(in); got != want {
			t.Fatalf("SanitizeHostnameForFilename(%q)=%q want %q", in, got, want)
		}
	}
}

func TestUniqueReportPath(t *testing.T) {
	ts := time.Date(2026, 10, 21, 15, 4, 5, 0, time.UTC)
	got := UniqueReportPath(`/var/tmp/reports`, `web01`, ts)
	want := filepath.Join(`/var/tmp/reports`, `php2shell-web01-20261021T150405Z.html`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestResolveScanReportPathOutWins(t *testing.T) {
	ts := time.Now().UTC()
	p, err := ResolveScanReportPath(filepath.Join("custom", "report"), "ignored-dir", "host", ts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p, ".html") {
		t.Fatal(p)
	}
	if strings.Contains(p, "ignored-dir") {
		t.Fatal("output-dir should not apply when --out is set")
	}
}

func TestResolveScanReportPathOutputDir(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	p, err := ResolveScanReportPath("", dir, "srv01", ts)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "php2shell-srv01-20261021T120000Z.html")
	if p != want {
		t.Fatalf("got %q want %q", p, want)
	}
}

func TestDefaultReportDirWindowsStyle(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows ProgramData default")
	}
	dir := DefaultReportDir()
	if !strings.Contains(strings.ToLower(dir), "php2shell") || !strings.Contains(strings.ToLower(dir), "reports") {
		t.Fatal(dir)
	}
}

func TestMakeReportDirectoryFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-style file-as-dir probe")
	}
	dir := t.TempDir()
	blocker := filepath.Join(dir, "notadir")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "report.html")
	if err := Save(NewReport("h", "linux", "amd64"), path); err == nil {
		t.Fatal("expected failure creating under a file")
	}
}

func TestScanIncomplete(t *testing.T) {
	r := NewReport("h", "linux", "amd64")
	if ScanIncomplete(r) {
		t.Fatal("empty coverage should not be incomplete")
	}
	r.AddCheck("binaries", "COMPLETE", "ok")
	r.AddCheck("repositories", "PARTIAL", "normal repo status")
	if ScanIncomplete(r) {
		t.Fatal("PARTIAL alone must not force exit 2")
	}
	r.AddCheck("webroot", "UNAVAILABLE", "permission denied")
	if !ScanIncomplete(r) {
		t.Fatal("expected incomplete")
	}
	if ScanExitCode(r, nil) != ExitIncomplete {
		t.Fatal("expected exit 2")
	}
}
