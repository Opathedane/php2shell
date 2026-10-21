package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPHPIniAloneNeverConfirmsInstallVersionOrVuln(t *testing.T) {
	dir := t.TempDir()
	ini := filepath.Join(dir, "php.ini")
	if err := os.WriteFile(ini, []byte("memory_limit = 128M\nsession.upload_progress.enabled = On\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r := NewReport("ini-only", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 22, 0, 0, 0, time.UTC)
	st := newPHPIniScanState()
	st.observePHPIniFile(r, ini, "test", "primary_candidate")
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	if len(r.PatchAssessments) != 0 {
		t.Fatalf("php.ini must not create patch assessments: %+v", r.PatchAssessments)
	}
	label, vers := humanPHPDetected(r)
	if strings.HasPrefix(label, "Yes") && len(vers) > 0 {
		t.Fatalf("ini-only must not confirm PHP versions: label=%q vers=%v", label, vers)
	}
	rt, _ := humanRuntime(r)
	if rt == "Verified" {
		t.Fatal(rt)
	}
	rows := BuildFleetRows(r)
	if len(rows) != 1 {
		t.Fatal(rows)
	}
	if rows[0].PHPVersion != "" {
		t.Fatalf("fleet php_version must be empty for ini-only: %+v", rows[0])
	}
	if rows[0].VersionEvidence != "php_not_observed_in_scope" && rows[0].InstallID != "host:no_comparable_install" {
		t.Fatalf("%+v", rows[0])
	}
	if rows[0].ConfigCandidateCount == "0" || rows[0].ConfigDiscoveryStatus == "NONE" {
		t.Fatalf("expected config discovery fields: %+v", rows[0])
	}
	if rows[0].SchemaVersion != FleetCSVSchemaV2 {
		t.Fatal(rows[0].SchemaVersion)
	}
	if rows[0].ActiveHTTPRuntimeStatus == "VERIFIED" {
		t.Fatal(rows[0].ActiveHTTPRuntimeStatus)
	}
}

func TestPHPIniConflictingCandidatesDoNotPickVersion(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	_ = os.MkdirAll(a, 0755)
	_ = os.MkdirAll(b, 0755)
	iniA := filepath.Join(a, "php.ini")
	iniB := filepath.Join(b, "php.ini")
	_ = os.WriteFile(iniA, []byte("memory_limit = 64M\n"), 0644)
	_ = os.WriteFile(iniB, []byte("memory_limit = 512M\n"), 0644)

	r := NewReport("conflict", "linux", "amd64")
	st := newPHPIniScanState()
	st.observePHPIniFile(r, iniA, "test-a", "primary_candidate")
	st.observePHPIniFile(r, iniB, "test-b", "primary_candidate")
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	memVals := map[string]bool{}
	for _, e := range r.Evidence {
		if e.Type == "configuration_observation" && e.Name == "memory_limit" {
			memVals[strings.Fields(e.Detail)[0]] = true
		}
	}
	if len(memVals) < 2 {
		t.Fatalf("expected both conflicting observations, got %v evidence=%+v", memVals, r.Evidence)
	}
	if len(r.PatchAssessments) != 0 {
		t.Fatal(r.PatchAssessments)
	}
	rows := BuildFleetRows(r)
	if rows[0].ConfigCandidateCount != "2" {
		t.Fatal(rows[0].ConfigCandidateCount)
	}
	if !strings.Contains(rows[0].ConfigDiscoveryStatus, "PRIMARY") && rows[0].ConfigDiscoveryStatus != "CANDIDATES_OBSERVED" {
		// two primaries → PRIMARY_CANDIDATES_OBSERVED
		if rows[0].ConfigDiscoveryStatus != "PRIMARY_CANDIDATES_OBSERVED" {
			t.Fatal(rows[0].ConfigDiscoveryStatus)
		}
	}
}

func TestPHPIniSymlinkAndUnreadableSkipped(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real.ini")
	_ = os.WriteFile(real, []byte("memory_limit = 32M\n"), 0644)
	link := filepath.Join(root, "php.ini")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks not supported:", err)
	}
	denied := filepath.Join(root, "denied.ini")
	_ = os.WriteFile(denied, []byte("memory_limit = 1M\n"), 0000)

	r := NewReport("skip", "linux", "amd64")
	st := newPHPIniScanState()
	st.observePHPIniFile(r, link, "symlink", "primary_candidate")
	st.observePHPIniFile(r, denied, "denied", "primary_candidate")
	st.observePHPIniFile(r, filepath.Join(root, "missing.ini"), "missing", "primary_candidate")

	for _, e := range r.Evidence {
		if e.Type == "php_ini_candidate" {
			t.Fatalf("symlink/unreadable/missing must not yield candidate: %+v", e)
		}
	}
	_ = os.Chmod(denied, 0644) // cleanup for temp dir removal
}

func TestPHPIniDiscoveryLimitTruncated(t *testing.T) {
	root := t.TempDir()
	r := NewReport("trunc", "linux", "amd64")
	st := newPHPIniScanState()
	// Force limit without creating 200 real files: set inspected near cap then add one more.
	st.inspected = maxPHPIniFiles
	path := filepath.Join(root, "php.ini")
	_ = os.WriteFile(path, []byte("memory_limit = 8M\n"), 0644)
	st.observePHPIniFile(r, path, "over-limit", "primary_candidate")
	if !st.truncated {
		t.Fatal("expected truncated")
	}
	if len(r.Evidence) != 0 {
		t.Fatal("should not inspect beyond cap")
	}
}

func TestFleetCSVV2ConfigFieldsAndV1RollupCompat(t *testing.T) {
	root := t.TempDir()
	phpDir := filepath.Join(root, "PHP", "8.4.24")
	_ = os.MkdirAll(phpDir, 0755)
	bin := filepath.Join(phpDir, "php-cgi.exe")
	ini := filepath.Join(phpDir, "php.ini")
	_ = os.WriteFile(bin, []byte("PHP Version 8.4.24"), 0644)
	_ = os.WriteFile(ini, []byte("memory_limit = 128M\n"), 0644)

	r := NewReport("fleet-v2", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 22, 0, 0, 0, time.UTC)
	r.CustomerLabel = "DemoCustomer"
	AddBinaryVersionEvidence(r, bin, "php-cgi.exe", "test")
	scanConfigs(r)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	data, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), FleetCSVSchemaV2) {
		t.Fatal(string(data)[:200])
	}
	rows, err := ParseFleetCSV(data)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].ConfigCorrelatedToInstall != "YES" {
		t.Fatalf("%+v", rows[0])
	}
	if rows[0].ConfigPrimaryIniPath == "" || rows[0].ConfigCandidateCount == "0" {
		t.Fatalf("%+v", rows[0])
	}
	if !strings.Contains(rows[0].ConfigIniClasses, "primary_candidate") {
		t.Fatal(rows[0].ConfigIniClasses)
	}

	// Legacy v1 file still parses and rollups into v2 output.
	v1path := filepath.Join(root, "legacy-v1.csv")
	v1 := "\xef\xbb\xbfschema_version,scan_id,hostname,os,architecture,scan_timestamp_utc,scanner_version,customer_label,install_id,php_version,version_confidence,version_evidence,install_path,component_name,upstream_minimum_fixed,patch_status,remediation_priority,recommended_action,qualification,active_http_runtime_status,compromise_status,host_vulnerability_status,discovery_completeness,limitations_summary\n" +
		"php2shell-fleet-csv/v1,abc,legacy-host,linux,amd64,2026-10-21T18:00:00Z,2.4.0,DemoCustomer,install:binary-dir:/usr/bin,8.4.27,HIGH,verified_binary_metadata,/usr/bin/php,php,8.4.27,AT_OR_ABOVE_UPSTREAM_FIX,VERIFY,verify,qual,NOT_VERIFIED,NOT_ASSESSED,UPSTREAM_FIX_LEVEL_OBSERVED_ACTIVE_RUNTIME_UNVERIFIED,PARTIAL,limits\n"
	if err := os.WriteFile(v1path, []byte(v1), 0644); err != nil {
		t.Fatal(err)
	}
	v2path := filepath.Join(root, "new-v2.csv")
	if err := os.WriteFile(v2path, data, 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "rollup.csv")
	if err := RollupFleetCSV(FleetRollupOptions{InputFiles: []string{v1path, v2path}, Output: out}); err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	sumRows, err := ParseFleetCSV(sum)
	if err != nil {
		t.Fatal(err)
	}
	if len(sumRows) < 2 {
		t.Fatalf("%+v", sumRows)
	}
	for _, row := range sumRows {
		if row.SchemaVersion != FleetCSVSchemaV2 {
			t.Fatalf("rollup should normalize to v2: %+v", row)
		}
	}
}

func TestHumanPHPDetectedIniIsArtifactOnly(t *testing.T) {
	r := NewReport("art", "linux", "amd64")
	r.AddEvidence(Evidence{
		Type: "php_ini_candidate", Name: "php.ini", Source: "t", Location: "/tmp/php.ini",
		Detail: "ini_class=primary_candidate", Interpretation: "CONFIGURED_INI_CANDIDATE_NOT_PROOF_OF_VERSION_OR_ACTIVE_RUNTIME",
	})
	label, vers := humanPHPDetected(r)
	if label != "Possible PHP-related artifacts only" {
		t.Fatalf("got %q vers=%v", label, vers)
	}
	if len(vers) != 0 {
		t.Fatal(vers)
	}
}
