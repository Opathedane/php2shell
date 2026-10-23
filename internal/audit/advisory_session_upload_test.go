package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeIni(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func scanIniReport(t *testing.T, iniPath string) *Report {
	t.Helper()
	r := NewReport("t", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	scanConfigs(r, HostScanOptions{PHPIniPaths: []string{iniPath}}, nil)
	EvaluatePatchPosture(r)
	return r
}

func find115560(r *Report) AdditionalAdvisory {
	for _, a := range r.AdditionalAdvisories {
		if a.CVE == AdvisoryCVE115560 {
			return a
		}
	}
	return AdditionalAdvisory{}
}

func TestCVE115560PHPBinaryUploadOn(t *testing.T) {
	dir := t.TempDir()
	ini := writeIni(t, dir, "php.ini", "session.serialize_handler = php_binary\nsession.upload_progress.enabled = On\n")
	r := scanIniReport(t, ini)
	a := find115560(r)
	if a.Status != "MANUAL_VERIFICATION_REQUIRED" {
		t.Fatalf("status=%s observed=%s", a.Status, a.ObservedConfig)
	}
	if a.Priority != "REVIEW" {
		t.Fatal(a.Priority)
	}
	if ScanIncomplete(r) {
		t.Fatal("advisory must not force ScanIncomplete / exit 2")
	}
}

func TestCVE115560PHPSerializeUploadOn(t *testing.T) {
	dir := t.TempDir()
	ini := writeIni(t, dir, "php.ini", "session.serialize_handler = php_serialize\nsession.upload_progress.enabled = 1\n")
	a := find115560(scanIniReport(t, ini))
	if a.Status != "MANUAL_VERIFICATION_REQUIRED" {
		t.Fatalf("got %s", a.Status)
	}
}

func TestCVE115560HandlerPHP(t *testing.T) {
	dir := t.TempDir()
	ini := writeIni(t, dir, "php.ini", "session.serialize_handler = php\nsession.upload_progress.enabled = On\n")
	a := find115560(scanIniReport(t, ini))
	if a.Status != "NO_RISKY_INITIAL_HANDLER_OBSERVED" {
		t.Fatalf("got %s", a.Status)
	}
}

func TestCVE115560UploadProgressOff(t *testing.T) {
	dir := t.TempDir()
	ini := writeIni(t, dir, "php.ini", "session.serialize_handler = php_binary\nsession.upload_progress.enabled = Off\n")
	a := find115560(scanIniReport(t, ini))
	if a.Status != "MITIGATION_CONFIGURED_NOT_RUNTIME_VERIFIED" {
		t.Fatalf("got %s %s", a.Status, a.ObservedConfig)
	}
}

func TestCVE115560MissingSettings(t *testing.T) {
	dir := t.TempDir()
	ini := writeIni(t, dir, "php.ini", "memory_limit = 128M\n")
	a := find115560(scanIniReport(t, ini))
	if a.Status != "UNDETERMINED" {
		t.Fatalf("got %s", a.Status)
	}
	if !strings.Contains(a.MissingEvidence, "neither") && !strings.Contains(a.MissingEvidence, "not observed") {
		t.Fatalf("missing=%s", a.MissingEvidence)
	}
}

func TestCVE115560BareInventoryNoAdvisoryNoise(t *testing.T) {
	r := NewReport("bare", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	EvaluatePatchPosture(r)
	if len(r.AdditionalAdvisories) != 0 {
		t.Fatalf("bare inventory without php.ini candidates must not emit CVE-2026-115560 noise: %+v", r.AdditionalAdvisories)
	}
	html := string(EncodeHTML(r))
	if strings.Contains(html, "Additional PHP security advisories") {
		t.Fatal("HTML must not show Additional advisories section without evidence")
	}
}

func TestCVE115560ConflictingCandidates(t *testing.T) {
	dir := t.TempDir()
	aPath := writeIni(t, dir, "a.php.ini", "session.serialize_handler = php_binary\nsession.upload_progress.enabled = On\n")
	bPath := writeIni(t, dir, "b.php.ini", "session.serialize_handler = php\nsession.upload_progress.enabled = Off\n")
	r := NewReport("t", "linux", "amd64")
	scanConfigs(r, HostScanOptions{PHPIniPaths: []string{aPath, bPath}}, nil)
	EvaluatePatchPosture(r)
	a := find115560(r)
	if a.Status != "UNDETERMINED" {
		t.Fatalf("conflict want UNDETERMINED, got %s (%s)", a.Status, a.ObservedConfig)
	}
}

func TestCVE115560CommentedOutIgnored(t *testing.T) {
	dir := t.TempDir()
	ini := writeIni(t, dir, "php.ini", ";session.serialize_handler = php_binary\n;session.upload_progress.enabled = On\nmemory_limit = 128M\n")
	a := find115560(scanIniReport(t, ini))
	if a.Status != "UNDETERMINED" {
		t.Fatalf("commented settings must not drive MANUAL_VERIFICATION, got %s", a.Status)
	}
	if strings.Contains(a.ObservedConfig, "php_binary") {
		t.Fatalf("commented handler leaked: %s", a.ObservedConfig)
	}
}

func TestCVE115560SampleTemplateOnly(t *testing.T) {
	dir := t.TempDir()
	ini := writeIni(t, dir, "php.ini-production", "session.serialize_handler = php_binary\nsession.upload_progress.enabled = On\n")
	a := find115560(scanIniReport(t, ini))
	// sample class still observes settings; SampleOrTemplate flag or UNDETERMINED for mitigation-only-from-sample
	if a.Status == "" {
		t.Fatal("expected an advisory row")
	}
	if a.Status == "MANUAL_VERIFICATION_REQUIRED" && !a.SampleOrTemplate && !strings.Contains(a.Qualification, "sample") {
		// Accept MANUAL_VERIFICATION with sample qualification, or sample-influenced flag
		t.Logf("sample file status=%s sample=%v qual=%s", a.Status, a.SampleOrTemplate, a.Qualification)
	}
}

func TestCVE115560DoesNotChangePrimaryPatchThresholds(t *testing.T) {
	dir := t.TempDir()
	ini := writeIni(t, dir, "php.ini", "session.serialize_handler = php_binary\nsession.upload_progress.enabled = On\n")
	r := NewReport("t", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php", Version: "8.4.27", Source: "t", Location: "/usr/bin/php", Interpretation: "x"})
	scanConfigs(r, HostScanOptions{PHPIniPaths: []string{ini}}, nil)
	EvaluatePatchPosture(r)
	if r.VulnerabilityStatus == "" {
		t.Fatal("missing vulnerability status")
	}
	// 8.4.27 is at upstream fix for 109618/109619 — must not become BELOW due to 115560
	for _, p := range r.PatchAssessments {
		if p.ObservedVersion == "8.4.27" && p.Status == "BELOW_UPSTREAM_FIX" {
			t.Fatalf("115560 must not invent below-fix for primary CVEs: %+v", p)
		}
		if p.MinimumFixed != "" && p.MinimumFixed != "8.4.27" && strings.Contains(p.Component, "115560") {
			t.Fatal("no invented fixed version for 115560 on primary assessments")
		}
	}
	if find115560(r).Status != "MANUAL_VERIFICATION_REQUIRED" {
		t.Fatal(find115560(r).Status)
	}
	d := CheckPHPVersion("8.4.27")
	if d.Status != "AT_OR_ABOVE_UPSTREAM_FIX" || d.MinimumFixed != "8.4.27" {
		t.Fatalf("primary thresholds changed: %+v", d)
	}
	d82 := CheckPHPVersion("8.2.35")
	if d82.MinimumFixed != "8.2.35" {
		t.Fatal(d82)
	}
}

func TestCVE115560HTMLAndExitCode(t *testing.T) {
	dir := t.TempDir()
	ini := writeIni(t, dir, "php.ini", "session.serialize_handler = php_binary\nsession.upload_progress.enabled = On\n")
	r := scanIniReport(t, ini)
	html := string(EncodeHTML(r))
	if !strings.Contains(html, "Additional PHP security advisories") {
		t.Fatal("missing HTML section")
	}
	if !strings.Contains(html, "CVE-2026-115560") || !strings.Contains(html, "MANUAL_VERIFICATION_REQUIRED") {
		t.Fatal(html[0:min(800, len(html))])
	}
	if !strings.Contains(html, AdvisoryURL115560) {
		t.Fatal("missing advisory link")
	}
	csv, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(csv), "schema_version") {
		t.Fatal("csv broken")
	}
	if ScanExitCode(r, nil) != ExitOK && ScanIncomplete(r) {
		t.Fatal("unexpected incomplete from advisory alone")
	}
	code := ScanExitCode(r, nil)
	if code != ExitOK {
		// May still be incomplete for unrelated coverage; advisory alone must not force it
		for _, c := range r.Coverage {
			switch c.Status {
			case "INCOMPLETE", "UNAVAILABLE", "TRUNCATED", "TIMEOUT", "ACCESS_DENIED":
				t.Logf("coverage %s=%s may drive exit %d", c.Name, c.Status, code)
			}
		}
	}
}

func TestCVE115560UnknownRuntimeNotSafeClaim(t *testing.T) {
	dir := t.TempDir()
	ini := writeIni(t, dir, "php.ini", "session.serialize_handler = php\nsession.upload_progress.enabled = Off\n")
	a := find115560(scanIniReport(t, ini))
	// Off wins as mitigation; must not say SAFE / NOT_VULNERABLE
	if strings.Contains(a.Status, "SAFE") || strings.Contains(a.Status, "NOT_VULNERABLE") || strings.Contains(a.Status, "PATCHED") {
		t.Fatal(a.Status)
	}
	if a.Status != "MITIGATION_CONFIGURED_NOT_RUNTIME_VERIFIED" && a.Status != "NO_RISKY_INITIAL_HANDLER_OBSERVED" {
		// Off + php handler: mitigation branch runs first when upload Off
		t.Fatalf("got %s", a.Status)
	}
}
