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
}
