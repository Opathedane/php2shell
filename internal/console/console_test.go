package console

import (
	"bytes"
	"os"
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
	p.Summary(r, "/tmp/report.html", "/tmp/report.csv", time.Second, false)
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

func TestNoColorOptionDisablesANSIEvenWithForceTTY(t *testing.T) {
	var out, errBuf bytes.Buffer
	p := New(Options{Stdout: &out, Stderr: &errBuf, NoColor: true, ForceTTY: true})
	if p.ColorEnabled() || p.ErrColorEnabled() {
		t.Fatal("NoColor must disable stdout and stderr ANSI")
	}
	p.Warn("attention")
	p.Error("fatal")
	if strings.Contains(errBuf.String(), "\033[") {
		t.Fatalf("ANSI on stderr: %q", errBuf.String())
	}
}

func TestNOCOLOREnvDisablesANSI(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var out bytes.Buffer
	p := New(Options{Stdout: &out, Stderr: &out, ForceTTY: true})
	if p.ColorEnabled() {
		t.Fatal("NO_COLOR must disable ANSI")
	}
}

func TestSummaryIncludesReportPathAndDisclaimer(t *testing.T) {
	var out bytes.Buffer
	p := New(Options{Stdout: &out, Stderr: &out, NoColor: true})
	r := audit.NewReport("host", "linux", "amd64")
	r.Summary.PHPDiscovery = "found"
	r.AddWarning("partial check")
	p.Summary(r, `/reports/php2shell-host.html`, `/reports/php2shell-host.csv`, 2*time.Second, true)
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

func TestSummaryWindowsNoPHPOmitsLinuxPackageNote(t *testing.T) {
	var out bytes.Buffer
	p := New(Options{Stdout: &out, Stderr: &out, NoColor: true})
	r := audit.NewReport("win-empty", "windows", "amd64")
	r.AddCheck("packages", "NOT_SUPPORTED", "No passive native package database reader for this OS; no package commands executed")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0 PHP-like binary paths")
	r.AddCheck("windows_processes", "PARTIAL", "Observed 0 PHP/IIS process names")
	r.AddCheck("windows_iis_configuration", "NOT_APPLICABLE", "IIS configuration not present")
	audit.EvaluatePatchPosture(r)
	audit.FinalizeSummary(r)
	p.Summary(r, `C:\Reports\out.html`, `C:\Reports\out.csv`, time.Second, false)
	s := out.String()
	if strings.Contains(s, "dpkg/apk") || strings.Contains(s, "OS package DB not inventoried") {
		t.Fatalf("Windows console must not warn about Linux package DB: %s", s)
	}
	if !strings.Contains(s, "Overall priority:") {
		t.Fatal("expected overall priority line")
	}
	if !strings.Contains(s, "Recommended next:") {
		t.Fatal("expected recommended next step")
	}
	if !strings.Contains(s, "No PHP detected within scan coverage") && !strings.Contains(s, "No PHP-specific patch assessment") {
		t.Fatalf("expected clear no-PHP assessment: %s", s)
	}
	if strings.Contains(s, "\033[") {
		t.Fatal("ANSI leak")
	}
}

func TestSummaryLinuxPackageNoteWhenNotSupported(t *testing.T) {
	var out bytes.Buffer
	p := New(Options{Stdout: &out, Stderr: &out, NoColor: true})
	r := audit.NewReport("rhel", "linux", "amd64")
	r.AddCheck("packages", "NOT_SUPPORTED", "No readable dpkg/apk")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0")
	r.AddCheck("processes", "PARTIAL", "Observed 0")
	audit.EvaluatePatchPosture(r)
	audit.FinalizeSummary(r)
	p.Summary(r, "/tmp/out.html", "/tmp/out.csv", time.Second, false)
	if !strings.Contains(out.String(), "OS package DB not inventoried") {
		t.Fatal(out.String())
	}
}

func TestSummaryUsesGroupInstallationsAndHumanInvestigation(t *testing.T) {
	var out bytes.Buffer
	p := New(Options{Stdout: &out, Stderr: &out, NoColor: true})
	r := audit.NewReport("multi", "linux", "amd64")
	r.PatchAssessments = []audit.PatchAssessment{
		{
			InstallKey: "install:binary:/usr/bin/php8.2", ObservedVersion: "8.2.28",
			Status: "BELOW_UPSTREAM_FIX", Priority: "CRITICAL", RequiredAction: "Update PHP 8.2 toward 8.2.35",
			EvidenceType: "binary_static_version", Location: "/usr/bin/php8.2",
		},
		{
			InstallKey: "install:binary:/usr/bin/php8.4", ObservedVersion: "8.4.27",
			Status: "AT_OR_ABOVE_UPSTREAM_FIX", Priority: "VERIFY",
			EvidenceType: "binary_static_version", Location: "/usr/bin/php8.4",
		},
	}
	r.VulnerabilityStatus = "MULTIPLE_RUNTIMES_MIXED_PATCH_LEVELS_REVIEW_REQUIRED"
	r.ExploitationAttemptStatus = "NO_MATCHES_IN_SCOPE"
	r.PossibleCompromiseStatus = "NOT_ASSESSED"
	r.AddCheck("compromise_investigation", "ASSESSED_SCOPE_LIMITED", "offline logs assessed")
	audit.FinalizeSummary(r)
	p.Summary(r, "/tmp/out.html", "/tmp/out.csv", time.Second, false)
	s := out.String()
	if !strings.Contains(s, "Installation review:") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "PHP 8.2.28") || !strings.Contains(s, "PHP 8.4.27") {
		t.Fatalf("must list independent installations: %s", s)
	}
	if !strings.Contains(s, "Overall priority:") || !strings.Contains(s, "Recommended next:") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "attempts=No attempt patterns in assessed scope") {
		t.Fatalf("investigation should be humanized: %s", s)
	}
	if strings.Contains(s, "attempts=NO_MATCHES_IN_SCOPE") {
		t.Fatal("must not print raw investigation enums")
	}
}

func TestForceTTYEnablesColorWhenAllowed(t *testing.T) {
	_ = os.Unsetenv("NO_COLOR")
	t.Setenv("CI", "")
	t.Setenv("TERM", "xterm")
	var out bytes.Buffer
	p := New(Options{Stdout: &out, Stderr: &out, ForceTTY: true})
	if !p.ColorEnabled() {
		t.Fatal("ForceTTY should enable color when NO_COLOR unset")
	}
	p.Phase("demo")
	if !strings.Contains(out.String(), "\033[") {
		t.Fatal("expected ANSI with ForceTTY")
	}
}
