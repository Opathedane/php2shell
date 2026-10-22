package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestGenerateProcessTelemetryDemos writes Windows/Linux offline EDR demo reports.
// Set PHP2SHELL_WRITE_DEMOS=1 to refresh testdata/demos/process-telemetry/*.html|csv.
func TestGenerateProcessTelemetryDemos(t *testing.T) {
	root := filepath.Join(moduleRootDir(t), "testdata", "demos", "process-telemetry")
	outDir := t.TempDir()
	if os.Getenv("PHP2SHELL_WRITE_DEMOS") == "1" {
		outDir = root
		_ = os.MkdirAll(outDir, 0755)
	}

	type caseSpec struct {
		name     string
		host     string
		osname   string
		procFile string
		errFile  string
		wantPoss string
		wantAtt  string
	}
	cases := []caseSpec{
		{
			name: "windows-mde-php-cmd", host: "win-web-01", osname: "windows",
			procFile: "mde-php-cmd.csv", wantPoss: "POSSIBLE_COMPROMISE_REVIEW", wantAtt: "NOT_ASSESSED",
		},
		{
			name: "windows-sysmon-w3wp", host: "iis-web-01", osname: "windows",
			procFile: "sysmon-w3wp-powershell.csv", wantPoss: "POSSIBLE_COMPROMISE_REVIEW", wantAtt: "NOT_ASSESSED",
		},
		{
			name: "linux-auditd-php-fpm", host: "linux-web-01", osname: "linux",
			procFile: "auditd-php-fpm-sh.log", wantPoss: "POSSIBLE_COMPROMISE_REVIEW", wantAtt: "NOT_ASSESSED",
		},
		{
			name: "linux-ecs-correlated", host: "linux-web-02", osname: "linux",
			procFile: "ecs-php-fpm-sh.jsonl", errFile: "error-correlated.log",
			wantPoss: "POSSIBLE_COMPROMISE_REVIEW", wantAtt: "SUSPECTED_ATTEMPTS_REVIEW",
		},
		{
			name: "windows-admin-negative", host: "win-admin-01", osname: "windows",
			procFile: "sysmon-admin-negative.csv", wantPoss: "NO_MATCHES_IN_SCOPE", wantAtt: "NOT_ASSESSED",
		},
	}

	for i, c := range cases {
		r := NewReport(c.host, c.osname, "amd64")
		r.CustomerLabel = "DemoCustomer"
		r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, i, 0, time.UTC)
		r.AddEvidence(Evidence{
			Type: "binary_static_version", Name: "php", Version: "8.4.24",
			Source: "demo fixture", Location: "/demo/php",
			Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
		})
		procPath := filepath.Join(root, c.procFile)
		_, leads := ScanProcessTelemetry(r, procPath)
		var errEv []InvestigationEvent
		if c.errFile != "" {
			errEv = ScanErrorLog(r, filepath.Join(root, c.errFile))
		}
		FinalizeInvestigation(r, InvestigationOptions{
			Assessing: true, HasProcessTelemetry: true,
			From: SuggestedInvestigateFromUTC,
		}, nil, errEv, leads, nil)
		EvaluatePatchPosture(r)
		FinalizeSummary(r)

		if r.PossibleCompromiseStatus != c.wantPoss {
			t.Fatalf("%s possible=%s want %s", c.name, r.PossibleCompromiseStatus, c.wantPoss)
		}
		if r.ExploitationAttemptStatus != c.wantAtt {
			t.Fatalf("%s attempts=%s want %s", c.name, r.ExploitationAttemptStatus, c.wantAtt)
		}

		htmlPath := filepath.Join(outDir, c.name+".html")
		csvPath := filepath.Join(outDir, c.name+".csv")
		_ = os.Remove(htmlPath)
		_ = os.Remove(csvPath)
		if err := SaveReportPair(r, htmlPath, csvPath); err != nil {
			t.Fatal(err)
		}
		html, err := os.ReadFile(htmlPath)
		if err != nil {
			t.Fatal(err)
		}
		s := string(html)
		if strings.Contains(s, "whoami") || strings.Contains(s, "-enc REDACTED") || strings.Contains(s, "/bin/sh -c id") {
			t.Fatalf("%s leaked sensitive command line into HTML", c.name)
		}
		if !strings.Contains(s, c.wantPoss) {
			t.Fatalf("%s HTML missing %s", c.name, c.wantPoss)
		}
	}
}
