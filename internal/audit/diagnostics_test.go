package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMatchingStatusJSONPath(t *testing.T) {
	if MatchingStatusJSONPath(`/tmp/a.html`) != `/tmp/a.status.json` {
		t.Fatal(MatchingStatusJSONPath(`/tmp/a.html`))
	}
	if MatchingStatusJSONPath(`C:\x\SERVER.htm`) != `C:\x\SERVER.status.json` {
		t.Fatal(MatchingStatusJSONPath(`C:\x\SERVER.htm`))
	}
}

func TestResolveScanReportPathCSVRemap(t *testing.T) {
	html, err := ResolveScanReportPath(`/data/SERVER.csv`, "", "host", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(strings.ToLower(html), "server.html") {
		t.Fatalf("csv remap want .html, got %s", html)
	}
	if MatchingCSVPath(html) == html {
		t.Fatal("csv sibling must differ")
	}
}

func TestWriteExecutionStatusJSONAndQuietLine(t *testing.T) {
	dir := t.TempDir()
	html := filepath.Join(dir, "rep.html")
	stPath := MatchingStatusJSONPath(html)
	r := NewReport("h", "linux", "amd64")
	r.AddCheck("webroot", "UNAVAILABLE", "missing")
	st := BuildExecutionStatus(ExecutionStatusOptions{
		ExecutionID: "abc", Started: time.Now().Add(-time.Second), Ended: time.Now(),
		GOOS: "linux", GOARCH: "amd64", Hostname: "h",
		ExitCode: ExitIncomplete, ReportsWritten: true,
		HTMLPath: html, CSVPath: MatchingCSVPath(html), StatusJSONPath: stPath,
		Incomplete: true, Report: r,
	})
	if st.ExecutionStatus != "COMPLETED_INCOMPLETE" {
		t.Fatalf("status=%s", st.ExecutionStatus)
	}
	if err := WriteExecutionStatusJSON(stPath, st); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(stPath)
	if err != nil {
		t.Fatal(err)
	}
	var got ExecutionStatus
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != "php2shell-execution-status/v1" || got.ToolVersion != Version {
		t.Fatalf("%+v", got)
	}
	line := FormatQuietStatusLine(st)
	if !strings.Contains(line, "COMPLETED_INCOMPLETE") || !strings.Contains(line, "exit=2") {
		t.Fatal(line)
	}
	// refuse overwrite
	if err := WriteExecutionStatusJSON(stPath, st); err == nil {
		t.Fatal("expected overwrite refusal")
	}
}

func TestIISAbsentNotIncomplete(t *testing.T) {
	r := NewReport("w", "windows", "amd64")
	r.AddCheck("windows_iis_configuration", "NOT_APPLICABLE", "IIS absent")
	if ScanIncomplete(r) {
		t.Fatal("NOT_APPLICABLE IIS must not force exit 2")
	}
	r.AddCheck("windows_iis_configuration", "ACCESS_DENIED", "denied")
	if !ScanIncomplete(r) {
		t.Fatal("ACCESS_DENIED must force exit 2")
	}
}

func TestPackagesNotSupportedNotIncomplete(t *testing.T) {
	r := NewReport("h", "linux", "amd64")
	r.AddCheck("packages", "NOT_SUPPORTED", "no dpkg/apk")
	if ScanIncomplete(r) {
		t.Fatal("packages NOT_SUPPORTED must not force exit 2")
	}
}

func TestClassifySaveError(t *testing.T) {
	id, _ := ClassifySaveError(errString("output exists, refusing overwrite: x"))
	if id != DiagOutputExists {
		t.Fatal(id)
	}
	id, _ = ClassifySaveError(errString("open report: permission denied"))
	if id != DiagAccessDenied {
		t.Fatal(id)
	}
	id, _ = ClassifySaveError(errString("Access is denied."))
	if id != DiagAccessDenied {
		t.Fatal(id)
	}
}

func TestDefaultRemediationAccessDenied(t *testing.T) {
	st := &ExecutionStatus{ExecutionStatus: "FAILED", ErrorIDs: []string{DiagAccessDenied}}
	msg := defaultRemediation(st)
	if !strings.Contains(strings.ToLower(msg), "write access") && !strings.Contains(strings.ToLower(msg), "grant") {
		t.Fatal(msg)
	}
	if strings.Contains(strings.ToLower(msg), "password") || strings.Contains(msg, "/Users/") {
		t.Fatal("must not expose sensitive path heuristics")
	}
}

func TestPersistExecutionStatusJSONFallbackMachineDetectable(t *testing.T) {
	dir := t.TempDir()
	html := filepath.Join(dir, "rep.html")
	if err := os.WriteFile(html, []byte("<html/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Primary path is an existing directory named *.status.json — write fails.
	primary := filepath.Join(dir, "locked.status.json")
	if err := os.Mkdir(primary, 0o755); err != nil {
		t.Fatal(err)
	}
	st := BuildExecutionStatus(ExecutionStatusOptions{
		ExecutionID: "exec1", Started: time.Now().Add(-time.Second), Ended: time.Now(),
		GOOS: "linux", GOARCH: "amd64", Hostname: "h",
		ExitCode: ExitOK, ReportsWritten: true,
		HTMLPath: html, CSVPath: MatchingCSVPath(html), StatusJSONPath: primary,
	})
	written, usedFallback, err := PersistExecutionStatusJSON(st, primary, html, "exec1")
	if err != nil {
		t.Fatal(err)
	}
	if !usedFallback || !st.StatusJSONWritten {
		t.Fatalf("want fallback write, written=%s fallback=%v status=%+v", written, usedFallback, st)
	}
	if !containsID(st.ErrorIDs, DiagOutputWriteFailed) {
		t.Fatalf("fallback must record OUTPUT_WRITE_FAILED for automation, got %v", st.ErrorIDs)
	}
	b, err := os.ReadFile(written)
	if err != nil {
		t.Fatal(err)
	}
	var got ExecutionStatus
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !got.StatusJSONWritten || !containsID(got.ErrorIDs, DiagOutputWriteFailed) {
		t.Fatalf("on-disk status must be machine-detectable: %+v", got)
	}
	line := FormatQuietStatusLine(st)
	if !strings.Contains(line, "status_json_written=true") || !strings.Contains(line, DiagOutputWriteFailed) {
		t.Fatal(line)
	}
}
