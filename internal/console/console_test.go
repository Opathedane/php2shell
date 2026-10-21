package console

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Opathedane/php2shell/internal/audit"
)

func TestQuietSuppressesProgressAndSummary(t *testing.T) {
	var out, errBuf bytes.Buffer
	p := New(Options{Quiet: true, Stdout: &out, Stderr: &errBuf})
	p.Banner("1.0", "linux", "amd64", "host")
	p.Phase("host inventory")
	r := audit.NewReport("host", "linux", "amd64")
	p.Summary(r, "/tmp/report.html", time.Second, false)
	if out.Len() != 0 {
		t.Fatalf("quiet should silence stdout, got %q", out.String())
	}
	p.Error("boom")
	if !strings.Contains(errBuf.String(), "boom") {
		t.Fatal(errBuf.String())
	}
}

func TestNoANSIWhenNotTTY(t *testing.T) {
	var out bytes.Buffer
	p := New(Options{Stdout: &out, Stderr: &out, NoColor: true, ForceTTY: true})
	if p.ColorEnabled() {
		t.Fatal("NoColor should disable ANSI")
	}
	p.Banner("1.0", "linux", "amd64", "host")
	p.Phase("phase")
	if strings.Contains(out.String(), "\033[") {
		t.Fatalf("ANSI found: %q", out.String())
	}
}

func TestRedirectedStdoutNoColor(t *testing.T) {
	var out bytes.Buffer
	p := New(Options{Stdout: &out, Stderr: &out})
	if p.ColorEnabled() {
		t.Fatal("bytes.Buffer is not a TTY; colors should be off")
	}
}

func TestSummaryIncludesReportPathAndDisclaimer(t *testing.T) {
	var out bytes.Buffer
	p := New(Options{Stdout: &out, Stderr: &out, NoColor: true})
	r := audit.NewReport("host", "linux", "amd64")
	r.Summary.PHPDiscovery = "found"
	r.AddWarning("partial check")
	p.Summary(r, `/reports/php2shell-host.html`, 2*time.Second, true)
	s := out.String()
	if !strings.Contains(s, `/reports/php2shell-host.html`) {
		t.Fatal(s)
	}
	if !strings.Contains(s, "not a vulnerability or compromise clearance") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "exit code 2") {
		t.Fatal(s)
	}
	if strings.Contains(strings.ToLower(s), "system is secure") || strings.Contains(strings.ToLower(s), "no issues found") {
		t.Fatal("must not claim clean security result")
	}
}
