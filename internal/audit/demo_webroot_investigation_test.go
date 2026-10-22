package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestGenerateWebrootInvestigationDemos writes synthetic webroot IR demos.
// Set PHP2SHELL_WRITE_DEMOS=1 to refresh testdata/demos/webroot-investigation/.
func TestGenerateWebrootInvestigationDemos(t *testing.T) {
	outRoot := filepath.Join(moduleRootDir(t), "testdata", "demos", "webroot-investigation")
	outDir := t.TempDir()
	if os.Getenv("PHP2SHELL_WRITE_DEMOS") == "1" {
		outDir = outRoot
		_ = os.MkdirAll(outDir, 0755)
	}

	demos := []struct {
		name, host string
		setup      func(webroot string)
		wantPoss   string
	}{
		{
			name: "positive-upload-php", host: "web-demo-01",
			wantPoss: "POSSIBLE_COMPROMISE_REVIEW",
			setup: func(webroot string) {
				up := filepath.Join(webroot, "uploads")
				_ = os.MkdirAll(up, 0755)
				f := filepath.Join(up, "drop.php")
				_ = os.WriteFile(f, []byte("<?php /* demo fixture; not executed */"), 0644)
				_ = os.Chtimes(f, time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC), time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC))
				_ = os.WriteFile(filepath.Join(webroot, "index.php"), []byte("<?php"), 0644)
			},
		},
		{
			name: "negative-benign-app", host: "app-demo-01",
			wantPoss: "NO_MATCHES_IN_SCOPE",
			setup: func(webroot string) {
				for _, name := range []string{"index.php", "src/App.php"} {
					p := filepath.Join(webroot, name)
					_ = os.MkdirAll(filepath.Dir(p), 0755)
					_ = os.WriteFile(p, []byte("<?php"), 0644)
					_ = os.Chtimes(p, time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC), time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC))
				}
			},
		},
		{
			name: "unusual-double-ext", host: "web-demo-02",
			wantPoss: "POSSIBLE_COMPROMISE_REVIEW",
			setup: func(webroot string) {
				f := filepath.Join(webroot, "img.php.jpg")
				_ = os.WriteFile(f, []byte("x"), 0644)
				_ = os.Chtimes(f, time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC), time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC))
			},
		},
	}

	for i, d := range demos {
		webroot := filepath.Join(outDir, d.name+"-tree")
		_ = os.RemoveAll(webroot)
		_ = os.MkdirAll(webroot, 0755)
		d.setup(webroot)

		r := NewReport(d.host, "linux", "amd64")
		r.CustomerLabel = "DemoCustomer"
		r.GeneratedUTC = time.Date(2026, 10, 22, 12, i, 0, 0, time.UTC)
		r.AddEvidence(Evidence{
			Type: "binary_static_version", Name: "php", Version: "8.4.24",
			Source: "demo fixture", Location: "/demo/php",
			Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
		})
		leads := ScanWebrootInvestigation(r, webroot, SuggestedInvestigateFromUTC, r.GeneratedUTC)
		FinalizeInvestigation(r, InvestigationOptions{
			Assessing: true, HasWebrootInvestigation: true, From: SuggestedInvestigateFromUTC,
		}, nil, nil, nil, leads)
		EvaluatePatchPosture(r)
		FinalizeSummary(r)

		if r.PossibleCompromiseStatus != d.wantPoss {
			t.Fatalf("%s possible=%s want %s leads=%d", d.name, r.PossibleCompromiseStatus, d.wantPoss, len(leads))
		}

		htmlPath := filepath.Join(outDir, d.name+".html")
		csvPath := filepath.Join(outDir, d.name+".csv")
		_ = os.Remove(htmlPath)
		_ = os.Remove(csvPath)
		if err := SaveReportPair(r, htmlPath, csvPath); err != nil {
			t.Fatal(err)
		}
		html, _ := os.ReadFile(htmlPath)
		if strings.Contains(string(html), "<?php /*") {
			t.Fatalf("%s leaked PHP source into HTML", d.name)
		}
	}
}
