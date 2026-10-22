package audit

import (
	"strings"
	"testing"
	"time"
)

func TestProcessTelemetryAbsentKeepsPossibleNotAssessed(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, nil, nil)
	if r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("got %s", r.PossibleCompromiseStatus)
	}
}

func TestProcessTelemetryMDEPHPToCmd(t *testing.T) {
	dir := t.TempDir()
	csv := "Timestamp,DeviceName,ActionType,FileName,FolderPath,ProcessId,ProcessCommandLine,InitiatingProcessFileName,InitiatingProcessFolderPath,InitiatingProcessId,ReportId\n" +
		"2026-10-18T14:06:00Z,win-web-01,ProcessCreated,cmd.exe,C:\\Windows\\System32,5000,cmd.exe /c whoami,php-cgi.exe,C:\\PHP,4000,rpt-mde-1\n"
	path := writeTemp(t, dir, "mde.csv", csv)
	r := NewReport("host", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	_, leads := ScanProcessTelemetry(r, path)
	if len(leads) == 0 {
		t.Fatalf("expected lead, coverage=%+v", r.ProcessTelemetry)
	}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true, HasProcessTelemetry: true}, nil, nil, leads)
	if r.PossibleCompromiseStatus != "POSSIBLE_COMPROMISE_REVIEW" {
		t.Fatalf("got %s findings=%+v", r.PossibleCompromiseStatus, r.InvestigationFindings)
	}
	if r.ExploitationAttemptStatus != "NOT_ASSESSED" {
		t.Fatalf("attempts should stay NOT_ASSESSED without logs, got %s", r.ExploitationAttemptStatus)
	}
	html := string(EncodeHTML(r))
	if strings.Contains(html, "whoami") {
		t.Fatal("raw command line must not appear in HTML")
	}
	if !strings.Contains(html, "rpt-mde-1") && !strings.Contains(html, "shell") {
		// entity id or classification should be present
		t.Log(html[0:min(500, len(html))])
	}
	for _, f := range r.InvestigationFindings {
		if strings.Contains(f.Detail, "whoami") || strings.Contains(f.Detail, "/c ") {
			t.Fatalf("command line leaked: %s", f.Detail)
		}
	}
}

func TestProcessTelemetryLinuxPHPFPMToSh(t *testing.T) {
	dir := t.TempDir()
	// 2026-10-18 14:06:00 UTC = 1792332360
	body := "" +
		`type=SYSCALL msg=audit(1792332360.100:100): arch=c000003e syscall=59 success=yes pid=100 ppid=1 exe="/usr/sbin/php-fpm" comm="php-fpm"` + "\n" +
		`type=SYSCALL msg=audit(1792332361.200:200): arch=c000003e syscall=59 success=yes pid=200 ppid=100 exe="/bin/sh" comm="sh"` + "\n" +
		`type=EXECVE msg=audit(1792332361.200:200): argc=3 a0="/bin/sh" a1="-c" a2="id"` + "\n"
	path := writeTemp(t, dir, "audit.log", body)
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	_, leads := ScanProcessTelemetry(r, path)
	if len(leads) == 0 {
		t.Fatalf("expected php-fpm→sh lead, telemetry=%+v", r.ProcessTelemetry)
	}
	FinalizeInvestigation(r, InvestigationOptions{
		Assessing: true, HasProcessTelemetry: true,
		From: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC),
	}, nil, nil, leads)
	if r.PossibleCompromiseStatus != "POSSIBLE_COMPROMISE_REVIEW" {
		t.Fatalf("got %s leads=%+v", r.PossibleCompromiseStatus, leads)
	}
}

func TestProcessTelemetryIISW3WPUnusualChild(t *testing.T) {
	dir := t.TempDir()
	csv := "UtcTime,EventID,Image,ParentImage,ProcessId,ParentProcessId,ProcessGuid,CommandLine\n" +
		"2026-10-18 14:07:00.000,1,C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,C:\\Windows\\System32\\inetsrv\\w3wp.exe,9001,8000,{guid-child},powershell.exe -enc AAAA\n"
	path := writeTemp(t, dir, "sysmon.csv", csv)
	r := NewReport("host", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	_, leads := ScanProcessTelemetry(r, path)
	if len(leads) == 0 {
		t.Fatal("expected w3wp→powershell lead")
	}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true, HasProcessTelemetry: true}, nil, nil, leads)
	if r.PossibleCompromiseStatus != "POSSIBLE_COMPROMISE_REVIEW" {
		t.Fatalf("got %s", r.PossibleCompromiseStatus)
	}
	for _, f := range r.InvestigationFindings {
		if strings.Contains(f.Detail, "-enc AAAA") {
			t.Fatal("encoded command must not leak")
		}
	}
}

func TestProcessTelemetryLegitimateAdminNegative(t *testing.T) {
	dir := t.TempDir()
	// Non-web parent launching shell — should not create compromise lead.
	csv := "UtcTime,EventID,Image,ParentImage,ProcessId,ParentProcessId,ProcessGuid,CommandLine\n" +
		"2026-10-18 14:07:00.000,1,C:\\Windows\\System32\\cmd.exe,C:\\Windows\\explorer.exe,9001,8000,{guid-admin},cmd.exe\n"
	path := writeTemp(t, dir, "sysmon-admin.csv", csv)
	r := NewReport("host", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	_, leads := ScanProcessTelemetry(r, path)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true, HasProcessTelemetry: true}, nil, nil, leads)
	if r.PossibleCompromiseStatus != "NO_MATCHES_IN_SCOPE" {
		t.Fatalf("explorer→cmd must not be web compromise lead, got %s leads=%d", r.PossibleCompromiseStatus, len(leads))
	}
}

func TestProcessTelemetryMissingParent(t *testing.T) {
	dir := t.TempDir()
	csv := "UtcTime,EventID,Image,ParentImage,ProcessId,ParentProcessId,ProcessGuid,CommandLine\n" +
		"2026-10-18 14:07:00.000,1,C:\\Windows\\System32\\cmd.exe,,9001,,{guid},cmd.exe\n"
	path := writeTemp(t, dir, "sysmon-orphan.csv", csv)
	r := NewReport("host", "windows", "amd64")
	_, leads := ScanProcessTelemetry(r, path)
	if len(leads) != 0 {
		t.Fatalf("missing parent must not invent web relationship, got %d", len(leads))
	}
}

func TestProcessTelemetryOutsideWindow(t *testing.T) {
	dir := t.TempDir()
	csv := "Timestamp,DeviceName,ActionType,FileName,FolderPath,ProcessId,ProcessCommandLine,InitiatingProcessFileName,InitiatingProcessFolderPath,InitiatingProcessId,ReportId\n" +
		"2026-10-10T14:06:00Z,win-web-01,ProcessCreated,cmd.exe,C:\\Windows\\System32,5000,cmd.exe,php-cgi.exe,C:\\PHP,4000,rpt-old\n"
	path := writeTemp(t, dir, "mde-old.csv", csv)
	r := NewReport("host", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	_, leads := ScanProcessTelemetry(r, path)
	FinalizeInvestigation(r, InvestigationOptions{
		Assessing: true, HasProcessTelemetry: true,
		From: SuggestedInvestigateFromUTC,
	}, nil, nil, leads)
	if r.PossibleCompromiseStatus != "NO_MATCHES_IN_SCOPE" {
		t.Fatalf("outside-window lead must be excluded, got %s", r.PossibleCompromiseStatus)
	}
}

func TestProcessTelemetryUnsupportedAndMalformed(t *testing.T) {
	dir := t.TempDir()
	path := writeTemp(t, dir, "junk.bin", "this is not a supported EDR schema\nfoo,bar\n")
	r := NewReport("host", "linux", "amd64")
	_, leads := ScanProcessTelemetry(r, path)
	if len(leads) != 0 || r.ProcessTelemetry[0].Status != "UNSUPPORTED_FORMAT" {
		t.Fatalf("want UNSUPPORTED_FORMAT, got %+v leads=%d", r.ProcessTelemetry, len(leads))
	}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true, HasProcessTelemetry: true}, nil, nil, leads)
	if r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("unsupported telemetry must not become negative match, got %s", r.PossibleCompromiseStatus)
	}
}

func TestProcessTelemetryElasticECSAndCorrelation(t *testing.T) {
	dir := t.TempDir()
	ecs := `{"@timestamp":"2026-10-18T14:05:45Z","host":{"name":"app1"},"event":{"category":["process"],"type":["start"]},"process":{"name":"sh","executable":"/bin/sh","pid":200,"entity_id":"ent-sh","command_line":"/bin/sh -c id","parent":{"name":"php-fpm","executable":"/usr/sbin/php-fpm","pid":100,"entity_id":"ent-fpm"}}}` + "\n"
	procPath := writeTemp(t, dir, "ecs.jsonl", ecs)
	errlog := writeTemp(t, dir, "error.log",
		`[18-Oct-2026 14:05:30 UTC] PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 3500032 bytes) in Unknown on line 0`+"\n")
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	_, leads := ScanProcessTelemetry(r, procPath)
	errEv := ScanErrorLog(r, errlog)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true, HasProcessTelemetry: true}, nil, errEv, leads)
	if r.PossibleCompromiseStatus != "POSSIBLE_COMPROMISE_REVIEW" {
		t.Fatalf("possible=%s", r.PossibleCompromiseStatus)
	}
	if r.ExploitationAttemptStatus != "SUSPECTED_ATTEMPTS_REVIEW" {
		t.Fatalf("attempts=%s", r.ExploitationAttemptStatus)
	}
	found := false
	for _, f := range r.InvestigationFindings {
		if f.Kind == "correlated_process_and_error" {
			found = true
			if !strings.Contains(f.Detail, "not causality") {
				t.Fatalf("correlation must deny causality: %s", f.Detail)
			}
		}
		if strings.Contains(f.Detail, "/bin/sh -c id") {
			t.Fatal("cmdline leaked")
		}
	}
	if !found {
		t.Fatalf("expected process↔error correlation, findings=%+v", r.InvestigationFindings)
	}
	csvBytes, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(csvBytes), "POSSIBLE_COMPROMISE_REVIEW") {
		t.Fatal("CSV must carry possible compromise status")
	}
	if !strings.Contains(string(csvBytes), "SUSPECTED_ATTEMPTS_REVIEW") {
		t.Fatal("CSV must keep independent attempt status")
	}
}

func TestProcessTelemetryDedupSameEntity(t *testing.T) {
	dir := t.TempDir()
	csv := "Timestamp,DeviceName,ActionType,FileName,FolderPath,ProcessId,ProcessCommandLine,InitiatingProcessFileName,InitiatingProcessFolderPath,InitiatingProcessId,ReportId\n" +
		"2026-10-18T14:06:00Z,win-web-01,ProcessCreated,cmd.exe,C:\\Windows\\System32,5000,cmd.exe,php-cgi.exe,C:\\PHP,4000,same-rpt\n" +
		"2026-10-18T14:06:01Z,win-web-01,ProcessCreated,cmd.exe,C:\\Windows\\System32,5000,cmd.exe /c echo,php-cgi.exe,C:\\PHP,4000,same-rpt\n"
	path := writeTemp(t, dir, "mde-dup.csv", csv)
	r := NewReport("host", "windows", "amd64")
	_, leads := ScanProcessTelemetry(r, path)
	if len(leads) != 1 {
		t.Fatalf("want 1 deduped lead, got %d", len(leads))
	}
}

func TestProcessTelemetryPIDReuseDoesNotInventParent(t *testing.T) {
	dir := t.TempDir()
	// Same PPID string reused for unrelated parents across time — each row still
	// carries its own InitiatingProcessFileName; we must not invent cross-row ancestry.
	csv := "Timestamp,DeviceName,ActionType,FileName,FolderPath,ProcessId,ProcessCommandLine,InitiatingProcessFileName,InitiatingProcessFolderPath,InitiatingProcessId,ReportId\n" +
		"2026-10-18T12:00:00Z,win-web-01,ProcessCreated,notepad.exe,C:\\Windows\\System32,9000,notepad.exe,explorer.exe,C:\\Windows,100,rpt-a\n" +
		"2026-10-18T14:06:00Z,win-web-01,ProcessCreated,cmd.exe,C:\\Windows\\System32,9001,cmd.exe,php-cgi.exe,C:\\PHP,100,rpt-b\n"
	path := writeTemp(t, dir, "mde-pidreuse.csv", csv)
	r := NewReport("host", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	_, leads := ScanProcessTelemetry(r, path)
	if len(leads) != 1 {
		t.Fatalf("want only php-cgi→cmd lead, got %d %+v", len(leads), leads)
	}
	if leads[0].Event.ParentName != "php-cgi.exe" {
		t.Fatalf("parent=%q", leads[0].Event.ParentName)
	}
}

func TestProcessTelemetryTruncatedCSV(t *testing.T) {
	dir := t.TempDir()
	// Header only — documented schema detected, zero events.
	csv := "Timestamp,DeviceName,ActionType,FileName,FolderPath,ProcessId,ProcessCommandLine,InitiatingProcessFileName,InitiatingProcessFolderPath,InitiatingProcessId,ReportId\n"
	path := writeTemp(t, dir, "mde-empty.csv", csv)
	r := NewReport("host", "windows", "amd64")
	_, leads := ScanProcessTelemetry(r, path)
	if len(leads) != 0 {
		t.Fatalf("header-only must yield no leads, got %d", len(leads))
	}
	if r.ProcessTelemetry[0].EventsParsed != 0 {
		t.Fatalf("events=%d", r.ProcessTelemetry[0].EventsParsed)
	}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true, HasProcessTelemetry: true}, nil, nil, leads)
	if r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("empty usable events → NOT_ASSESSED, got %s status=%s", r.PossibleCompromiseStatus, r.ProcessTelemetry[0].Status)
	}
}

func TestProcessTelemetryHTMLCSVConsistency(t *testing.T) {
	dir := t.TempDir()
	csv := "Timestamp,DeviceName,ActionType,FileName,FolderPath,ProcessId,ProcessCommandLine,InitiatingProcessFileName,InitiatingProcessFolderPath,InitiatingProcessId,ReportId\n" +
		"2026-10-18T14:06:00Z,win-web-01,ProcessCreated,cmd.exe,C:\\Windows\\System32,5000,cmd.exe /c whoami,php-cgi.exe,C:\\PHP,4000,rpt-html\n"
	path := writeTemp(t, dir, "mde.csv", csv)
	r := NewReport("demo-host", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	_, leads := ScanProcessTelemetry(r, path)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true, HasProcessTelemetry: true}, nil, nil, leads)
	FinalizeSummary(r)
	html := string(EncodeHTML(r))
	fleet, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	cs := string(fleet)
	for _, needle := range []string{"POSSIBLE_COMPROMISE_REVIEW", "Process / EDR telemetry", "rpt-html"} {
		if !strings.Contains(html, needle) && needle != "rpt-html" {
			if needle == "Process / EDR telemetry" && !strings.Contains(html, "process") {
				t.Fatalf("HTML missing process telemetry section")
			}
		}
		if needle == "POSSIBLE_COMPROMISE_REVIEW" && !strings.Contains(html, "POSSIBLE_COMPROMISE_REVIEW") {
			t.Fatal("HTML missing status")
		}
	}
	if !strings.Contains(cs, "POSSIBLE_COMPROMISE_REVIEW") {
		t.Fatal("CSV missing possible compromise status")
	}
	if strings.Contains(html, "whoami") || strings.Contains(cs, "whoami") {
		t.Fatal("command line leaked into reports")
	}
	// Entity id retained for analyst trace-back.
	if !strings.Contains(html, "rpt-html") {
		t.Fatal("HTML should retain ReportId for trace-back")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
