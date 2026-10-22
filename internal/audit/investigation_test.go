package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func writeTemp(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInvestigationNotRequestedWithoutLogs(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	FinalizeInvestigation(r, InvestigationOptions{}, nil, nil, nil)
	FinalizeSummary(r)
	if r.ExploitationAttemptStatus != "NOT_ASSESSED" || r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("statuses want NOT_ASSESSED, got attempt=%s possible=%s", r.ExploitationAttemptStatus, r.PossibleCompromiseStatus)
	}
	if r.InvestigationCoverage != "NOT_REQUESTED" {
		t.Fatalf("coverage want NOT_REQUESTED, got %s", r.InvestigationCoverage)
	}
	html := string(EncodeHTML(r))
	if !strings.Contains(html, "Not assessed") {
		t.Fatal("HTML should show not assessed for investigation axes")
	}
	lower := strings.ToLower(html)
	if strings.Contains(lower, "confirmed compromised") && !strings.Contains(lower, "never claims") && !strings.Contains(lower, "never claim") {
		t.Fatal("HTML must not affirm confirmed compromise")
	}
	if strings.Contains(lower, "host is clean") && !strings.Contains(lower, "never claims a host is clean") {
		t.Fatal("HTML must not claim the host is clean")
	}
}

func TestInvestigationNegativeNoMatchesInScope(t *testing.T) {
	dir := t.TempDir()
	access := writeTemp(t, dir, "access.log", `127.0.0.1 - - [18/Oct/2026:12:00:00 +0000] "GET /index.php HTTP/1.1" 200 1234`+"\n")
	errlog := writeTemp(t, dir, "error.log", `[18-Oct-2026 12:00:01 UTC] PHP Notice: Something benign in /var/www/index.php on line 10`+"\n")

	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	acc := mustCollectAccess(t, r, access)
	errEv := ScanErrorLog(r, errlog)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, acc, errEv, nil)
	FinalizeSummary(r)

	if r.ExploitationAttemptStatus != "NO_MATCHES_IN_SCOPE" {
		t.Fatalf("attempt status: %s", r.ExploitationAttemptStatus)
	}
	if r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("possible compromise must stay NOT_ASSESSED without EDR, got %s", r.PossibleCompromiseStatus)
	}
	if r.InvestigationCoverage == "NOT_REQUESTED" || r.InvestigationCoverage == "INCOMPLETE" {
		t.Fatalf("unexpected coverage %s", r.InvestigationCoverage)
	}
	if r.InvestigationWindow == nil || !strings.HasPrefix(r.InvestigationWindow.FromUTC, "2026-10-17") {
		t.Fatalf("default window from: %+v", r.InvestigationWindow)
	}
}

func TestInvestigationPositiveErrorPatternsIndependentOfCompromise(t *testing.T) {
	dir := t.TempDir()
	errlog := writeTemp(t, dir, "error.log",
		`[18-Oct-2026 14:05:01 UTC] PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 3500032 bytes) in Unknown on line 0`+"\n"+
			`[Wed Oct 21 14:06:02.123456 2026] [core:notice] AH00052: child pid 1234 exit signal Segmentation fault (11)`+"\n",
	)
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	errEv := ScanErrorLog(r, errlog)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, errEv, nil)
	FinalizeSummary(r)

	if r.ExploitationAttemptStatus != "SUSPECTED_ATTEMPTS_REVIEW" {
		t.Fatalf("attempt status: %s findings=%+v", r.ExploitationAttemptStatus, r.InvestigationFindings)
	}
	if r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("possible compromise must remain independent NOT_ASSESSED, got %s", r.PossibleCompromiseStatus)
	}
	if r.CompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("legacy IOC compromise should stay NOT_ASSESSED without pack matches, got %s", r.CompromiseStatus)
	}
	html := string(EncodeHTML(r))
	if !strings.Contains(html, "php_oom_unknown_line0") && !strings.Contains(html, "Suspected exploitation") {
		t.Fatal("HTML should surface attempt leads")
	}
	csv, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(csv), FleetCSVSchemaV3) {
		t.Fatalf("fleet CSV should be v3: %s", string(csv)[:200])
	}
	if !strings.Contains(string(csv), "SUSPECTED_ATTEMPTS_REVIEW") || !strings.Contains(string(csv), "NOT_ASSESSED") {
		t.Fatalf("CSV should show independent statuses:\n%s", string(csv))
	}
}

func TestInvestigationFalsePositiveBenignOOMNotOnLine0(t *testing.T) {
	dir := t.TempDir()
	errlog := writeTemp(t, dir, "error.log",
		`[18-Oct-2026 14:05:01 UTC] PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 4096 bytes) in /var/www/app.php on line 88`+"\n",
	)
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	errEv := ScanErrorLog(r, errlog)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, errEv, nil)
	if r.ExploitationAttemptStatus != "NO_MATCHES_IN_SCOPE" {
		t.Fatalf("benign OOM in app.php must not match Unknown on line 0 pattern, got %s events=%d", r.ExploitationAttemptStatus, len(errEv))
	}
}

func TestInvestigationIncompleteUnusableLogs(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	r.ErrorLogs = []ErrorLogCoverage{{File: "/missing", Status: "UNAVAILABLE", Detail: "missing"}}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, nil, nil)
	if r.InvestigationCoverage != "INCOMPLETE" {
		t.Fatalf("coverage: %s", r.InvestigationCoverage)
	}
	if r.ExploitationAttemptStatus != "NOT_ASSESSED" {
		t.Fatalf("incomplete evidence must not become NO_MATCHES, got %s", r.ExploitationAttemptStatus)
	}
}

func TestInvestigationCorrelationLongPOSTAndOOM(t *testing.T) {
	dir := t.TempDir()
	longTarget := "/" + strings.Repeat("A", 2100)
	accessLine := `10.0.0.1 - - [18/Oct/2026:14:05:00 +0000] "POST ` + longTarget + ` HTTP/1.1" 200 10`
	access := writeTemp(t, dir, "access.log", accessLine+"\n")
	errlog := writeTemp(t, dir, "error.log",
		`[18-Oct-2026 14:05:30 UTC] PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 3500032 bytes) in Unknown on line 0`+"\n",
	)
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	acc := mustCollectAccess(t, r, access)
	if len(acc) == 0 {
		t.Fatalf("expected long POST anomaly; target runes=%d lineLen=%d", utf8.RuneCountInString(longTarget), len(accessLine))
	}
	errEv := ScanErrorLog(r, errlog)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, acc, errEv, nil)
	foundCorr := false
	for _, f := range r.InvestigationFindings {
		if f.Kind == "correlated_attempt_signals" {
			foundCorr = true
			if f.Confidence != "unconfirmed" {
				t.Fatalf("correlation confidence want unconfirmed, got %s", f.Confidence)
			}
			if !strings.Contains(f.Detail, "not causality") && !strings.Contains(f.Detail, "Temporal proximity only") {
				t.Fatalf("correlation must deny causality: %s", f.Detail)
			}
			if !strings.Contains(f.Detail, "php_oom_unknown_line0") || !strings.Contains(f.Detail, "access_long_post_target") {
				t.Fatalf("correlation must name contributing evidence: %s", f.Detail)
			}
			if !strings.Contains(f.Detail, "not body size") {
				t.Fatalf("correlation must clarify request-target vs body: %s", f.Detail)
			}
		}
		if strings.Contains(f.Detail, strings.Repeat("A", 50)) {
			t.Fatal("must not retain long request-target text in findings")
		}
	}
	if !foundCorr {
		t.Fatalf("expected correlation lead, findings=%+v", r.InvestigationFindings)
	}
	if r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatal("correlation must not set possible compromise")
	}
}

func TestInvestigationCorrelationRequiresTimestamps(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	access := []InvestigationEvent{{
		Kind: "access_long_post_target", Class: "heuristic", Confidence: "unconfirmed",
		Location: "access.log", Line: 1, // Time zero — must not correlate
	}}
	errors := []InvestigationEvent{{
		Kind: "php_oom_unknown_line0", Class: "verified_public_pattern", Confidence: "suspected",
		Location: "error.log", Line: 2, Time: time.Date(2026, 10, 18, 14, 5, 30, 0, time.UTC),
	}}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, access, errors, nil)
	for _, f := range r.InvestigationFindings {
		if f.Kind == "correlated_attempt_signals" {
			t.Fatal("untimed access anomaly must not create correlation")
		}
	}
}

func TestInvestigationWindowExcludesOutsideEvents(t *testing.T) {
	dir := t.TempDir()
	errlog := writeTemp(t, dir, "error.log",
		`[10-Oct-2026 14:05:01 UTC] PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 3500032 bytes) in Unknown on line 0`+"\n",
	)
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	errEv := ScanErrorLog(r, errlog)
	FinalizeInvestigation(r, InvestigationOptions{
		Assessing: true,
		From:      SuggestedInvestigateFromUTC,
	}, nil, errEv, nil)
	if r.ExploitationAttemptStatus != "NO_MATCHES_IN_SCOPE" {
		t.Fatalf("events before window must be excluded, got %s findings=%d", r.ExploitationAttemptStatus, len(r.InvestigationFindings))
	}
}

func TestFleetCSVV3RollupAcceptsV2(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.ExploitationAttemptStatus = "NO_MATCHES_IN_SCOPE"
	r.PossibleCompromiseStatus = "NOT_ASSESSED"
	r.InvestigationCoverage = "ASSESSED_SCOPE_LIMITED"
	r.InvestigationWindow = &InvestigationWindow{FromUTC: "2026-10-17T00:00:00Z", ToUTC: "2026-10-22T12:00:00Z"}
	FinalizeSummary(r)
	raw, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseFleetCSV(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].SchemaVersion != FleetCSVSchemaV3 {
		t.Fatalf("rows=%+v", rows)
	}
	if rows[0].ExploitationAttemptStatus != "NO_MATCHES_IN_SCOPE" || rows[0].PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("independent fields missing: %+v", rows[0])
	}
}

func TestFleetCSVParseV1V2AndRollupToV3(t *testing.T) {
	v1 := []byte("\xEF\xBB\xBFschema_version,scan_id,hostname,os,architecture,scan_timestamp_utc,scanner_version,customer_label,install_id,php_version,version_confidence,version_evidence,install_path,component_name,upstream_minimum_fixed,patch_status,remediation_priority,recommended_action,qualification,active_http_runtime_status,compromise_status,host_vulnerability_status,discovery_completeness,limitations_summary\n" +
		"php2shell-fleet-csv/v1,id1,h1,linux,amd64,2026-10-21T00:00:00Z,2.4.0,,host:no_comparable_install,,,php_not_observed_in_scope,,,NOT_VERIFIED,REVIEW,act,qual,NOT_VERIFIED,NOT_ASSESSED,NOT_VERIFIED,PARTIAL,limits\n")
	v2 := []byte("\xEF\xBB\xBFschema_version,scan_id,hostname,os,architecture,scan_timestamp_utc,scanner_version,customer_label,install_id,php_version,version_confidence,version_evidence,install_path,component_name,upstream_minimum_fixed,patch_status,remediation_priority,recommended_action,qualification,active_http_runtime_status,compromise_status,host_vulnerability_status,discovery_completeness,limitations_summary,config_discovery_status,config_candidate_count,config_setting_observation_count,config_correlated_to_install,config_primary_ini_path,config_ini_classes\n" +
		"php2shell-fleet-csv/v2,id2,h2,linux,amd64,2026-10-21T00:00:00Z,2.5.0,,host:no_comparable_install,,,php_not_observed_in_scope,,,NOT_VERIFIED,REVIEW,act,qual,NOT_VERIFIED,NOT_ASSESSED,NOT_VERIFIED,PARTIAL,limits,NONE,0,0,NO,,\n")
	for _, label := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"v1", v1, FleetCSVSchemaV1},
		{"v2", v2, FleetCSVSchemaV2},
	} {
		rows, err := ParseFleetCSV(label.raw)
		if err != nil {
			t.Fatalf("%s parse: %v", label.name, err)
		}
		if len(rows) != 1 || rows[0].SchemaVersion != label.want {
			t.Fatalf("%s: %+v", label.name, rows)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.csv"), v1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.csv"), v2, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "rolled.csv")
	if err := RollupFleetCSV(FleetRollupOptions{InputDir: dir, Output: out}); err != nil {
		t.Fatal(err)
	}
	rolled, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseFleetCSV(rolled)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d", len(rows))
	}
	for _, row := range rows {
		if row.SchemaVersion != FleetCSVSchemaV3 {
			t.Fatalf("rollup must emit v3, got %s", row.SchemaVersion)
		}
	}
}

func TestInvestigationHTMLEscapesMaliciousPaths(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.ExploitationAttemptStatus = "SUSPECTED_ATTEMPTS_REVIEW"
	r.PossibleCompromiseStatus = "NOT_ASSESSED"
	r.InvestigationCoverage = "ASSESSED_SCOPE_LIMITED"
	r.InvestigationFindings = []InvestigationFinding{{
		ID: "x", Class: "heuristic", Kind: "access_long_post_target", Confidence: "unconfirmed",
		Source: "test", Location: `<script>alert(1)</script>`, Detail: `=CMD("|calc")|"secret=pw"`,
	}}
	FinalizeSummary(r)
	html := string(EncodeHTML(r))
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatal("HTML must escape script tags from log paths")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatal("expected escaped script in HTML")
	}
	csv, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	// Fleet rows do not embed finding detail; limitations must still be spreadsheet-safe.
	if strings.Contains(string(csv), "=CMD") {
		t.Fatal("CSV must not pass through unsanitized formula-like finding text in row fields")
	}
}

func mustCollectAccess(t *testing.T, r *Report, path string) []InvestigationEvent {
	t.Helper()
	evs, err := ScanAccessLogCollect(r, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}
