package console

import (
	"strings"
	"testing"
	"time"

	"github.com/Opathedane/php2shell/internal/audit"
)

func captureSummary(t *testing.T, r *audit.Report) string {
	t.Helper()
	audit.EvaluatePatchPosture(r)
	audit.FinalizeSummary(r)
	var b strings.Builder
	p := New(Options{Stdout: &b, Stderr: &b, NoColor: true})
	p.Summary(r, "/tmp/r.html", "/tmp/r.csv", time.Second, audit.ScanIncomplete(r))
	return b.String()
}

func assertCLIHTMLParity(t *testing.T, r *audit.Report) {
	t.Helper()
	cli := captureSummary(t, r)
	html := string(audit.EncodeHTML(r))
	prio := audit.OverallPriority(r)
	vuln := audit.HumanVulnerabilityLabelFor(r)
	php, _ := audit.HumanPHPDetected(r)

	if !strings.Contains(cli, "Overall priority:  "+prio) {
		t.Fatalf("CLI missing priority %q\n%s", prio, cli)
	}
	if !strings.Contains(html, "Overall priority: "+prio) {
		t.Fatalf("HTML missing priority %q", prio)
	}
	if !strings.Contains(cli, "Patch assessment:  "+vuln) {
		t.Fatalf("CLI missing patch label %q\n%s", vuln, cli)
	}
	if !strings.Contains(html, vuln) {
		t.Fatalf("HTML missing patch label %q", vuln)
	}
	if !strings.Contains(cli, php) {
		t.Fatalf("CLI missing PHP discovery %q", php)
	}
	if !strings.Contains(html, php) {
		t.Fatalf("HTML missing PHP discovery %q", php)
	}
	next := r.Summary.NextSteps
	if len(next) == 0 {
		t.Fatal("expected next steps after FinalizeSummary")
	}
	// CLI truncates; require a stable shared prefix of the first step.
	prefix := next[0]
	if len(prefix) > 80 {
		prefix = prefix[:80]
	}
	if !strings.Contains(cli, "Recommended next:") || !strings.Contains(cli, prefix) {
		t.Fatalf("CLI missing recommended next prefix %q\n%s", prefix, cli)
	}
	if !strings.Contains(html, "Recommended next steps") || !strings.Contains(html, next[0]) {
		t.Fatalf("HTML missing full first next step")
	}
}

func TestCLIHTMLParityWindowsNoPHP(t *testing.T) {
	r := audit.NewReport("win-empty", "windows", "amd64")
	r.AddCheck("packages", "NOT_SUPPORTED", "No passive native package database reader for this OS")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0")
	r.AddCheck("windows_processes", "PARTIAL", "Observed 0")
	r.AddCheck("windows_iis_configuration", "NOT_APPLICABLE", "IIS not present")
	assertCLIHTMLParity(t, r)
	cli := captureSummary(t, r)
	if strings.Contains(cli, "dpkg/apk") {
		t.Fatal("Windows CLI must not mention dpkg/apk")
	}
}

func TestCLIHTMLParityIncompleteInventory(t *testing.T) {
	r := audit.NewReport("partial", "linux", "amd64")
	r.AddCheck("packages", "UNAVAILABLE", "permission denied")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0")
	r.AddCheck("processes", "ACCESS_DENIED", "Cannot list /proc")
	assertCLIHTMLParity(t, r)
}

func TestCLIHTMLParityBelowThreshold(t *testing.T) {
	r := audit.NewReport("old", "linux", "amd64")
	r.AddCheck("packages", "PARTIAL", "ok")
	r.AddCheck("binary_paths", "PARTIAL", "ok")
	r.AddCheck("processes", "PARTIAL", "ok")
	r.AddEvidence(audit.Evidence{Type: "binary_static_version", Name: "php", Version: "8.4.24", Source: "static", Location: "/usr/bin/php"})
	assertCLIHTMLParity(t, r)
}

func TestCLIHTMLParityMixedInstalls(t *testing.T) {
	r := audit.NewReport("multi", "linux", "amd64")
	r.AddCheck("packages", "PARTIAL", "ok")
	r.AddCheck("binary_paths", "OK", "ok")
	r.AddCheck("processes", "PARTIAL", "ok")
	r.AddEvidence(audit.Evidence{Type: "binary_static_version", Name: "php", Version: "8.2.34", Source: "static", Location: "/usr/bin/php8.2"})
	r.AddEvidence(audit.Evidence{Type: "binary_static_version", Name: "php-fpm", Version: "8.4.27", Source: "static", Location: "/usr/sbin/php-fpm8.4"})
	assertCLIHTMLParity(t, r)
	html := string(audit.EncodeHTML(r))
	if r.VulnerabilityStatus == "MULTIPLE_RUNTIMES_MIXED_PATCH_LEVELS_REVIEW_REQUIRED" {
		if !strings.Contains(html, "Multiple PHP installations with mixed patch levels") {
			t.Fatal("expected mixed-install HTML detail")
		}
	}
	cli := captureSummary(t, r)
	if !strings.Contains(cli, "PHP 8.2.34") || !strings.Contains(cli, "PHP 8.4.27") {
		t.Fatalf("CLI must list both installs:\n%s", cli)
	}
}

func TestRedirectedWritersNeverColor(t *testing.T) {
	var out, errBuf strings.Builder
	p := New(Options{Stdout: &out, Stderr: &errBuf})
	if p.ColorEnabled() || p.ErrColorEnabled() {
		t.Fatal("redirected buffers must not enable ANSI")
	}
	p.Warn("w")
	p.Error("e")
	p.Phase("p")
	joined := out.String() + errBuf.String()
	if strings.Contains(joined, "\033[") {
		t.Fatalf("ANSI leak: %q", joined)
	}
}
