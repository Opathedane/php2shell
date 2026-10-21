package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGenerateDemoFleetArtifacts writes synthetic HTML/CSV samples used for docs review.
// Artifacts land under testdata/demos/ when PHP2SHELL_WRITE_DEMOS=1; otherwise they use t.TempDir.
func TestGenerateDemoFleetArtifacts(t *testing.T) {
	outDir := t.TempDir()
	if os.Getenv("PHP2SHELL_WRITE_DEMOS") == "1" {
		outDir = filepath.Join("..", "..", "testdata", "demos")
		_ = os.MkdirAll(outDir, 0755)
	}

	type spec struct {
		file, host, osname, arch string
		build                    func(*Report)
	}
	specs := []spec{
		{
			file: "windows-php-8.4.24-below-fix", host: "win-app-01", osname: "windows", arch: "amd64",
			build: func(r *Report) {
				r.CustomerLabel = "DemoCustomer"
				path := `C:\Users\demo\AppData\Local\Programs\PHP\8.4.24\nts\x64\php.exe`
				r.AddEvidence(Evidence{
					Type: "binary_path_inferred_version", Name: "php.exe", Version: "8.4.24",
					Source: "Windows LocalAppData Programs\\PHP static binary inspection", Location: path,
					Detail: "install_path_version_segment; provenance=path_inferred; confidence=MEDIUM",
					Interpretation: "PATH_INFERRED_VERSION_NOT_BINARY_VERIFIED_NOT_RUNTIME_ATTESTATION",
				})
				r.AddEvidence(Evidence{
					Type: "binary_path_inferred_version", Name: "php-cgi.exe", Version: "8.4.24",
					Source: "Windows LocalAppData Programs\\PHP static binary inspection",
					Location: `C:\Users\demo\AppData\Local\Programs\PHP\8.4.24\nts\x64\php-cgi.exe`,
					Detail: "install_path_version_segment; provenance=path_inferred; confidence=MEDIUM",
					Interpretation: "PATH_INFERRED_VERSION_NOT_BINARY_VERIFIED_NOT_RUNTIME_ATTESTATION",
				})
			},
		},
		{
			file: "linux-php-8.4.27-at-threshold", host: "linux-web-01", osname: "linux", arch: "amd64",
			build: func(r *Report) {
				r.CustomerLabel = "DemoCustomer"
				r.AddEvidence(Evidence{
					Type: "binary_static_version", Name: "php-fpm8.4", Version: "8.4.27",
					Source: "well-known path static binary inspection", Location: "/usr/sbin/php-fpm8.4",
					Detail: "embedded_build_string; provenance=verified_binary_metadata; confidence=HIGH",
					Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
				})
				r.AddEvidence(Evidence{
					Type: "installed_package", Name: "php8.4-fpm", Version: "8.4.27",
					Source: "dpkg installed package metadata", Location: "/var/lib/dpkg/status",
					Interpretation: "PACKAGE_VERSION_ONLY_VENDOR_BACKPORT_AND_ACTIVE_SAPI_UNVERIFIED",
				})
			},
		},
		{
			file: "incomplete-discovery", host: "lab-unknown-01", osname: "linux", arch: "amd64",
			build: func(r *Report) {
				r.CustomerLabel = "DemoCustomer"
				r.AddEvidence(Evidence{
					Type: "binary_path", Name: "php", Source: "PATH", Location: "/opt/custom/php",
					Detail: "no version marker found", Interpretation: "PRESENT_VERSION_UNKNOWN_NOT_RUNTIME_VERIFIED",
				})
				r.AddCheck("binary_paths", "PARTIAL", "Found 1 PHP-like binary paths (0 with verified static version markers)")
			},
		},
	}

	var csvPaths []string
	for i, s := range specs {
		r := NewReport(s.host, s.osname, s.arch)
		r.GeneratedUTC = time.Date(2026, 10, 21, 18, 0, i, 0, time.UTC)
		s.build(r)
		EvaluatePatchPosture(r)
		FinalizeSummary(r)
		htmlPath := filepath.Join(outDir, s.file+".html")
		csvPath := filepath.Join(outDir, s.file+".csv")
		_ = os.Remove(htmlPath)
		_ = os.Remove(csvPath)
		if err := SaveReportPair(r, htmlPath, csvPath); err != nil {
			t.Fatal(err)
		}
		csvPaths = append(csvPaths, csvPath)
		if _, err := os.Stat(htmlPath); err != nil {
			t.Fatal(err)
		}
	}
	summary := filepath.Join(outDir, "customer-summary.csv")
	_ = os.Remove(summary)
	if err := RollupFleetCSV(FleetRollupOptions{InputFiles: csvPaths, Output: summary}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseFleetCSV(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 3 {
		t.Fatalf("summary rows=%d", len(rows))
	}
}
