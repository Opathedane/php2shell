package audit

import (
	"fmt"
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
	FinalizeInvestigation(r, InvestigationOptions{}, nil, nil, nil, nil)
	FinalizeSummary(r)
	if r.ExploitationAttemptStatus != "NOT_ASSESSED" || r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("statuses want NOT_ASSESSED, got attempt=%s possible=%s", r.ExploitationAttemptStatus, r.PossibleCompromiseStatus)
	}
	if r.InvestigationCoverage != "NOT_REQUESTED" {
		t.Fatalf("coverage want NOT_REQUESTED, got %s", r.InvestigationCoverage)
	}
	html := string(EncodeHTML(r))
	// Inventory-only scans omit the optional investigation executive card strip.
	if strings.Contains(html, `aria-label="Optional investigation"`) {
		t.Fatal("HTML must not show optional investigation executive cards when investigation was not requested")
	}
	if !strings.Contains(html, "not a clearance") {
		t.Fatal("HTML must retain clearance disclaimer")
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
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, acc, errEv, nil, nil)
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
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, errEv, nil, nil)
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
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, errEv, nil, nil)
	if r.ExploitationAttemptStatus != "NO_MATCHES_IN_SCOPE" {
		t.Fatalf("benign OOM in app.php must not match Unknown on line 0 pattern, got %s events=%d", r.ExploitationAttemptStatus, len(errEv))
	}
}

func TestInvestigationIncompleteUnusableLogs(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	r.ErrorLogs = []ErrorLogCoverage{{File: "/missing", Status: "UNAVAILABLE", Detail: "missing"}}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, nil, nil, nil)
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
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, acc, errEv, nil, nil)
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
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, access, errors, nil, nil)
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
	}, nil, errEv, nil, nil)
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

func TestOct25ReliaQuestErrorSequenceStrongerThanLoneOOM(t *testing.T) {
	dir := t.TempDir()
	// ReliaQuest-style sequence: OOM Unknown line 0 + zend_mm_heap + AH00052 Abort within seconds.
	errlog := writeTemp(t, dir, "error.log",
		`[18-Oct-2026 14:05:01 UTC] PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 3500032 bytes) in Unknown on line 0`+"\n"+
			`[18-Oct-2026 14:05:01 UTC] zend_mm_heap corrupted`+"\n"+
			`[Wed Oct 18 14:05:02.123456 2026] [core:notice] AH00052: child pid 4242 exit signal Abort (6)`+"\n",
	)
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	errEv := ScanErrorLog(r, errlog)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, errEv, nil, nil)

	var seq, loneOOM bool
	seqConf := ""
	for _, f := range r.InvestigationFindings {
		switch f.Kind {
		case "correlated_error_sequence":
			seq = true
			seqConf = f.Confidence
			if f.Confidence != "suspected" {
				t.Fatalf("multi-signal sequence confidence want suspected, got %s", f.Confidence)
			}
			if strings.Contains(strings.ToLower(f.Detail), "confirmed exploitation") &&
				!strings.Contains(f.Detail, "Not confirmed") {
				t.Fatalf("must not claim confirmed exploitation: %s", f.Detail)
			}
		case "php_oom_unknown_line0":
			loneOOM = true
		case "php_zend_mm_heap_corrupted", "apache_child_abort":
			// expected individual pattern leads
		}
	}
	if !seq {
		t.Fatalf("expected correlated_error_sequence, findings=%+v", r.InvestigationFindings)
	}
	if !loneOOM {
		t.Fatal("expected individual OOM finding alongside sequence")
	}
	if seqConf != "suspected" {
		t.Fatalf("sequence conf=%q", seqConf)
	}
	if r.ExploitationAttemptStatus != "SUSPECTED_ATTEMPTS_REVIEW" {
		t.Fatalf("attempt status: %s", r.ExploitationAttemptStatus)
	}
}

func TestOct25AbortAndHeapNegativeBenign(t *testing.T) {
	dir := t.TempDir()
	// Benign: OOM in app.php (not Unknown line 0); no heap; no Abort.
	errlog := writeTemp(t, dir, "error.log",
		`[18-Oct-2026 14:05:01 UTC] PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 4096 bytes) in /var/www/app.php on line 88`+"\n"+
			`[Wed Oct 18 14:05:02.123456 2026] [core:notice] AH00052: child pid 1 exit signal Segmentation fault (11)`+"\n",
	)
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	errEv := ScanErrorLog(r, errlog)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, errEv, nil, nil)
	for _, f := range r.InvestigationFindings {
		if f.Kind == "correlated_error_sequence" {
			t.Fatal("benign app.php OOM must not form ReliaQuest sequence with segfault alone")
		}
		if f.Kind == "php_zend_mm_heap_corrupted" || f.Kind == "apache_child_abort" {
			t.Fatalf("unexpected kind %s", f.Kind)
		}
	}
	// Segfault alone still surfaces as a research pattern (Datadog), not a sequence.
	if r.ExploitationAttemptStatus != "SUSPECTED_ATTEMPTS_REVIEW" {
		t.Fatalf("segfault alone still warrants review, got %s", r.ExploitationAttemptStatus)
	}
}

func TestOct25POST5xxCorrelationOnlyNotStandalone(t *testing.T) {
	dir := t.TempDir()
	access := writeTemp(t, dir, "access.log",
		`10.0.0.1 - - [18/Oct/2026:14:05:00 +0000] "POST /wp-login.php HTTP/1.1" 500 10`+"\n",
	)
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	acc := mustCollectAccess(t, r, access)
	hasPOST5xx := false
	for _, ev := range acc {
		if ev.Kind == "access_post_server_error" {
			hasPOST5xx = true
		}
	}
	if !hasPOST5xx {
		t.Fatal("expected access_post_server_error event collected")
	}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, acc, nil, nil, nil)
	for _, f := range r.InvestigationFindings {
		if f.Kind == "access_post_server_error" {
			t.Fatal("POST 5xx must not surface as standalone finding")
		}
	}
	if r.ExploitationAttemptStatus != "NO_MATCHES_IN_SCOPE" {
		t.Fatalf("POST 5xx alone must not elevate attempts, got %s", r.ExploitationAttemptStatus)
	}

	// With nearby OOM, correlation may assist review but stays unconfirmed without PID/same-request proof.
	r2 := NewReport("host", "linux", "amd64")
	r2.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	errlog := writeTemp(t, dir, "error.log",
		`[18-Oct-2026 14:05:30 UTC] PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 3500032 bytes) in Unknown on line 0`+"\n",
	)
	acc2 := mustCollectAccess(t, r2, access)
	errEv := ScanErrorLog(r2, errlog)
	FinalizeInvestigation(r2, InvestigationOptions{Assessing: true}, acc2, errEv, nil, nil)
	found := false
	for _, f := range r2.InvestigationFindings {
		if f.Kind == "correlated_attempt_signals" {
			found = true
			if f.Confidence != "unconfirmed" {
				t.Fatalf("POST 5xx + OOM time-only correlation want unconfirmed, got %s", f.Confidence)
			}
			if !strings.Contains(f.Detail, "access_post_server_error") {
				t.Fatalf("must name POST 5xx evidence: %s", f.Detail)
			}
			if !strings.Contains(f.Detail, "Temporal proximity only") && !strings.Contains(f.Detail, "not proof of one shared request") {
				t.Fatalf("must deny same-request proof: %s", f.Detail)
			}
		}
	}
	if !found {
		t.Fatalf("expected POST 5xx ↔ OOM correlation, findings=%+v", r2.InvestigationFindings)
	}
}

func TestOct25MissingPIDStillNotConfirmed(t *testing.T) {
	dir := t.TempDir()
	// Two-kind temporal pair (OOM + heap) without shared WorkerPID → unconfirmed, not suspected.
	errlog := writeTemp(t, dir, "error.log",
		`[18-Oct-2026 14:05:01 UTC] PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 3500032 bytes) in Unknown on line 0`+"\n"+
			`[18-Oct-2026 14:05:01 UTC] zend_mm_heap corrupted`+"\n",
	)
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	errEv := ScanErrorLog(r, errlog)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, errEv, nil, nil)
	found := false
	for _, f := range r.InvestigationFindings {
		if f.Kind == "correlated_error_sequence" {
			found = true
			if f.Confidence != "unconfirmed" {
				t.Fatalf("two-kind without shared PID want unconfirmed, got %s detail=%s", f.Confidence, f.Detail)
			}
			if !strings.Contains(f.Detail, "Temporal proximity only") && !strings.Contains(f.Detail, "unconfirmed") {
				t.Fatalf("missing-PID / time-only limitation must be explicit: %s", f.Detail)
			}
		}
	}
	if !found {
		t.Fatalf("expected two-kind sequence finding, findings=%+v", r.InvestigationFindings)
	}
	if r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("error sequence alone must not set possible compromise, got %s", r.PossibleCompromiseStatus)
	}
}

func TestOct25CrossFileSequenceRefused(t *testing.T) {
	// Same-time OOM and Abort from independent error-log files must not join.
	oom := InvestigationEvent{
		Kind: "php_oom_unknown_line0", Class: "verified_public_pattern", Confidence: "suspected",
		Location: "/var/log/host-a/php.log", Line: 1,
		Time: time.Date(2026, 10, 18, 14, 5, 1, 0, time.UTC),
	}
	abort := InvestigationEvent{
		Kind: "apache_child_abort", Class: "verified_public_pattern", Confidence: "suspected",
		Location: "/var/log/host-b/apache.log", Line: 2, WorkerPID: "4242",
		Time: time.Date(2026, 10, 18, 14, 5, 2, 0, time.UTC),
	}
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	r.ErrorLogs = []ErrorLogCoverage{
		{File: oom.Location, Status: "PATTERNS_REVIEWED_COVERAGE_LIMITED"},
		{File: abort.Location, Status: "PATTERNS_REVIEWED_COVERAGE_LIMITED"},
	}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, []InvestigationEvent{oom, abort}, nil, nil)
	for _, f := range r.InvestigationFindings {
		if f.Kind == "correlated_error_sequence" {
			t.Fatalf("independent error-log files must not form a sequence: %+v", f)
		}
	}
}

func TestOct25DuplicateEntriesDoNotMultiplySequence(t *testing.T) {
	dir := t.TempDir()
	// Flood of duplicate OOM/heap/abort lines in-window should yield one sequence finding.
	var b strings.Builder
	for i := 0; i < 5; i++ {
		b.WriteString(`[18-Oct-2026 14:05:01 UTC] PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 3500032 bytes) in Unknown on line 0` + "\n")
		b.WriteString(`[18-Oct-2026 14:05:01 UTC] zend_mm_heap corrupted` + "\n")
		b.WriteString(`[Wed Oct 18 14:05:02.123456 2026] [core:notice] AH00052: child pid 4242 exit signal Abort (6)` + "\n")
	}
	errlog := writeTemp(t, dir, "error.log", b.String())
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	errEv := ScanErrorLog(r, errlog)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, errEv, nil, nil)
	seqCount := 0
	for _, f := range r.InvestigationFindings {
		if f.Kind == "correlated_error_sequence" {
			seqCount++
			if f.Confidence != "suspected" {
				t.Fatalf("3-kind ReliaQuest sequence want suspected, got %s", f.Confidence)
			}
		}
	}
	if seqCount != 1 {
		t.Fatalf("duplicate flood must emit exactly one sequence finding, got %d", seqCount)
	}
}

func TestOct25POST5xxFloodDedup(t *testing.T) {
	dir := t.TempDir()
	var acc strings.Builder
	for i := 0; i < 20; i++ {
		acc.WriteString(fmt.Sprintf(`10.0.0.1 - - [18/Oct/2026:14:05:%02d +0000] "POST /api HTTP/1.1" 500 10`+"\n", i%60))
	}
	access := writeTemp(t, dir, "access.log", acc.String())
	errlog := writeTemp(t, dir, "error.log",
		`[18-Oct-2026 14:05:30 UTC] PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 3500032 bytes) in Unknown on line 0`+"\n",
	)
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, mustCollectAccess(t, r, access), ScanErrorLog(r, errlog), nil, nil)
	corrCount := 0
	for _, f := range r.InvestigationFindings {
		if f.Kind == "correlated_attempt_signals" {
			corrCount++
			if f.Confidence != "unconfirmed" {
				t.Fatalf("want unconfirmed, got %s", f.Confidence)
			}
		}
	}
	if corrCount != 1 {
		t.Fatalf("POST 5xx flood must collapse to one correlation per error line, got %d", corrCount)
	}
}

func TestOct25UntimedErrorCannotSequence(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	r.ErrorLogs = []ErrorLogCoverage{{File: "error.log", Status: "PATTERNS_REVIEWED_COVERAGE_LIMITED"}}
	events := []InvestigationEvent{
		{Kind: "php_oom_unknown_line0", Class: "verified_public_pattern", Confidence: "suspected", Location: "error.log", Line: 1}, // Time zero
		{Kind: "php_zend_mm_heap_corrupted", Class: "verified_public_pattern", Confidence: "suspected", Location: "error.log", Line: 2,
			Time: time.Date(2026, 10, 18, 14, 5, 1, 0, time.UTC)},
		{Kind: "apache_child_abort", Class: "verified_public_pattern", Confidence: "suspected", Location: "error.log", Line: 3, WorkerPID: "9",
			Time: time.Date(2026, 10, 18, 14, 5, 2, 0, time.UTC)},
	}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, events, nil, nil)
	for _, f := range r.InvestigationFindings {
		if f.Kind == "correlated_error_sequence" {
			// Untimed OOM excluded → only heap+abort (no OOM) → no ReliaQuest sequence.
			t.Fatalf("untimed OOM must not participate in sequence: %+v", f)
		}
	}
}

func TestOct25SamePIDCrashLinesElevateSequence(t *testing.T) {
	// Shared WorkerPID on ≥2 distinct crash/abort kinds elevates; still not same-request proof.
	oom := InvestigationEvent{
		Kind: "php_oom_unknown_line0", Class: "verified_public_pattern", Confidence: "suspected",
		Location: "error.log", Line: 1, Time: time.Date(2026, 10, 18, 14, 5, 1, 0, time.UTC),
	}
	sf := InvestigationEvent{
		Kind: "apache_child_segfault", Class: "verified_public_pattern", Confidence: "suspected",
		Location: "error.log", Line: 2, WorkerPID: "777",
		Time: time.Date(2026, 10, 18, 14, 5, 2, 0, time.UTC),
	}
	ab := InvestigationEvent{
		Kind: "apache_child_abort", Class: "verified_public_pattern", Confidence: "suspected",
		Location: "error.log", Line: 3, WorkerPID: "777",
		Time: time.Date(2026, 10, 18, 14, 5, 3, 0, time.UTC),
	}
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	r.ErrorLogs = []ErrorLogCoverage{{File: "error.log", Status: "PATTERNS_REVIEWED_COVERAGE_LIMITED"}}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, []InvestigationEvent{oom, sf, ab}, nil, nil)
	found := false
	for _, f := range r.InvestigationFindings {
		if f.Kind == "correlated_error_sequence" {
			found = true
			if f.Confidence != "suspected" {
				t.Fatalf("shared WorkerPID across distinct crash kinds want suspected, got %s", f.Confidence)
			}
			if !strings.Contains(f.Detail, "PID 777") {
				t.Fatalf("must disclose shared PID: %s", f.Detail)
			}
			if !strings.Contains(f.Detail, "not proof every pattern shared") && !strings.Contains(f.Detail, "still not proof") {
				t.Fatalf("must still deny full same-request proof: %s", f.Detail)
			}
			if !strings.Contains(f.Detail, "distinct crash/abort") {
				t.Fatalf("must distinguish distinct-kind PID corroboration: %s", f.Detail)
			}
		}
	}
	if !found {
		t.Fatal("expected sequence with shared PID")
	}
}

func TestOct25DuplicateSameKindPIDDoesNotElevate(t *testing.T) {
	// OOM + repeated Abort for the same worker PID must stay unconfirmed (duplicates ≠ independent corroboration).
	events := []InvestigationEvent{
		{Kind: "php_oom_unknown_line0", Class: "verified_public_pattern", Confidence: "suspected",
			Location: "error.log", Line: 1, Time: time.Date(2026, 10, 18, 14, 5, 1, 0, time.UTC)},
		{Kind: "apache_child_abort", Class: "verified_public_pattern", Confidence: "suspected",
			Location: "error.log", Line: 2, WorkerPID: "4242",
			Time: time.Date(2026, 10, 18, 14, 5, 2, 0, time.UTC)},
		{Kind: "apache_child_abort", Class: "verified_public_pattern", Confidence: "suspected",
			Location: "error.log", Line: 3, WorkerPID: "4242",
			Time: time.Date(2026, 10, 18, 14, 5, 3, 0, time.UTC)},
	}
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	r.ErrorLogs = []ErrorLogCoverage{{File: "error.log", Status: "PATTERNS_REVIEWED_COVERAGE_LIMITED"}}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, events, nil, nil)
	found := false
	for _, f := range r.InvestigationFindings {
		if f.Kind == "correlated_error_sequence" {
			found = true
			if f.Confidence != "unconfirmed" {
				t.Fatalf("duplicate same-kind Abort PID must not elevate to suspected, got %s detail=%s", f.Confidence, f.Detail)
			}
		}
	}
	if !found {
		t.Fatal("expected two-kind unconfirmed sequence")
	}
}

func TestOct25IncompleteLogsNotFalseClearance(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	r.ErrorLogs = []ErrorLogCoverage{{File: "/missing", Status: "UNAVAILABLE", Detail: "missing"}}
	r.Logs = []LogCoverage{{File: "/missing-access", Status: "UNAVAILABLE", Detail: "missing"}}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, nil, nil, nil)
	if r.InvestigationCoverage != "INCOMPLETE" {
		t.Fatalf("coverage: %s", r.InvestigationCoverage)
	}
	if r.ExploitationAttemptStatus != "NOT_ASSESSED" {
		t.Fatalf("unusable logs must not become NO_MATCHES clearance, got %s", r.ExploitationAttemptStatus)
	}
}
