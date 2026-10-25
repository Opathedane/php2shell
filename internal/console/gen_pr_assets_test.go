package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Opathedane/php2shell/internal/audit"
)

// TestWritePRAssets regenerates docs/pr-assets/v2.7.4-ux samples when PHP2SHELL_WRITE_PR_ASSETS=1.
func TestWritePRAssets(t *testing.T) {
	if os.Getenv("PHP2SHELL_WRITE_PR_ASSETS") != "1" {
		t.Skip("set PHP2SHELL_WRITE_PR_ASSETS=1 to regenerate PR assets")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "docs", "pr-assets", "v2.7.4-ux")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatal(err)
	}

	{
		var b strings.Builder
		p := New(Options{Stdout: &b, Stderr: &b, NoColor: true})
		r := audit.NewReport("win-empty", "windows", "amd64")
		r.AddCheck("packages", "NOT_SUPPORTED", "No passive native package database reader for this OS; no package commands executed")
		r.AddCheck("binary_paths", "PARTIAL", "Found 0 PHP-like binary paths")
		r.AddCheck("windows_processes", "PARTIAL", "Observed 0 PHP/IIS process names")
		r.AddCheck("windows_iis_configuration", "NOT_APPLICABLE", "IIS configuration not present")
		audit.EvaluatePatchPosture(r)
		audit.FinalizeSummary(r)
		p.Banner(audit.Version, "windows", "amd64", "win-empty")
		p.Summary(r, `C:\ProgramData\PHP2Shell\Reports\php2shell-win-empty.html`, `C:\ProgramData\PHP2Shell\Reports\php2shell-win-empty.csv`, 1200*time.Millisecond, false)
		mustWrite(t, filepath.Join(outDir, "console-windows-no-php-after.txt"), []byte(b.String()))
		mustWrite(t, filepath.Join(outDir, "html-windows-no-php-after.html"), audit.EncodeHTML(r))
	}

	before := `PHP2Shell Assessment 2.7.3
Host: win-empty  OS: windows/amd64

Scan summary
  PHP discovery:     No PHP detected within scan coverage
  Patch assessment:  No PHP-specific patch assessment
  Serving runtime:   Not applicable — No PHP installation was detected within scan coverage.
  Observed versions: none in this scan scope (absence is not proof PHP is missing)
  Coverage note:    OS package DB not inventoried (no dpkg/apk). On RPM hosts, rely on binary/PATH discovery and vendor advisories.
  Duration:          1.2s
  HTML report:       C:\ProgramData\PHP2Shell\Reports\php2shell-win-empty.html
  CSV report:        C:\ProgramData\PHP2Shell\Reports\php2shell-win-empty.csv

Process completion is not a vulnerability or compromise clearance.
Open the HTML report for findings; use CSV for fleet consolidation.
`
	mustWrite(t, filepath.Join(outDir, "console-windows-no-php-before.txt"), []byte(before))

	{
		r := audit.NewReport("partial-empty", "linux", "amd64")
		r.AddCheck("packages", "UNAVAILABLE", "Cannot read dpkg status database: permission denied")
		r.AddCheck("binary_paths", "PARTIAL", "Found 0 PHP-like binary paths")
		r.AddCheck("processes", "ACCESS_DENIED", "Cannot list /proc")
		audit.EvaluatePatchPosture(r)
		audit.FinalizeSummary(r)
		mustWrite(t, filepath.Join(outDir, "html-incomplete-inventory.html"), audit.EncodeHTML(r))
	}

	{
		r := audit.NewReport("old-php", "linux", "amd64")
		r.AddCheck("packages", "PARTIAL", "ok")
		r.AddCheck("binary_paths", "PARTIAL", "ok")
		r.AddCheck("processes", "PARTIAL", "ok")
		r.AddEvidence(audit.Evidence{Type: "binary_static_version", Name: "php", Version: "8.4.24", Source: "static", Location: "/usr/bin/php"})
		audit.EvaluatePatchPosture(r)
		audit.FinalizeSummary(r)
		mustWrite(t, filepath.Join(outDir, "html-below-threshold.html"), audit.EncodeHTML(r))
		var b strings.Builder
		p := New(Options{Stdout: &b, Stderr: &b, NoColor: true})
		p.Summary(r, "/tmp/old.html", "/tmp/old.csv", time.Second, false)
		mustWrite(t, filepath.Join(outDir, "console-below-threshold-after.txt"), []byte(b.String()))
	}

	{
		r := audit.NewReport("multi", "linux", "amd64")
		r.AddCheck("packages", "PARTIAL", "ok")
		r.AddCheck("binary_paths", "OK", "ok")
		r.AddCheck("processes", "PARTIAL", "ok")
		r.AddEvidence(audit.Evidence{Type: "binary_static_version", Name: "php", Version: "8.2.34", Source: "static", Location: "/usr/bin/php8.2"})
		r.AddEvidence(audit.Evidence{Type: "binary_static_version", Name: "php-fpm", Version: "8.4.27", Source: "static", Location: "/usr/sbin/php-fpm8.4"})
		audit.EvaluatePatchPosture(r)
		audit.FinalizeSummary(r)
		mustWrite(t, filepath.Join(outDir, "html-multi-install.html"), audit.EncodeHTML(r))
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}
