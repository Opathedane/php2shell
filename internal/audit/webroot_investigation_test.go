package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWebrootInvestigationAbsentKeepsPossibleNotAssessed(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, nil, nil, nil, nil)
	if r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("got %s", r.PossibleCompromiseStatus)
	}
}

func TestWebrootUploadPHPLead(t *testing.T) {
	root := t.TempDir()
	up := filepath.Join(root, "uploads")
	if err := os.MkdirAll(up, 0755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(up, "drop.php")
	if err := os.WriteFile(f, []byte("<?php echo 1;"), 0644); err != nil {
		t.Fatal(err)
	}
	// Benign app PHP outside upload — must not alone create a lead.
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC)
	_ = os.Chtimes(f, mtime, mtime)

	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	from, to := SuggestedInvestigateFromUTC, r.GeneratedUTC
	leads := ScanWebrootInvestigation(r, root, from, to)
	if len(leads) == 0 {
		t.Fatalf("expected upload lead, coverage=%+v", r.WebrootInvestigation)
	}
	foundUpload := false
	for _, l := range leads {
		if l.Confidence != "unconfirmed" {
			t.Fatalf("metadata lead must be unconfirmed, got %s", l.Confidence)
		}
		if l.Kind == "webroot_php_in_upload_dir" {
			foundUpload = true
		}
		if strings.Contains(l.Detail, "<?php") {
			t.Fatal("file contents must not appear in lead detail")
		}
		if !strings.Contains(l.Detail, "WEAK METADATA-ONLY") {
			t.Fatalf("lead must label weak metadata: %s", l.Detail)
		}
	}
	if !foundUpload {
		t.Fatalf("missing upload lead: %+v", leads)
	}
	FinalizeInvestigation(r, InvestigationOptions{
		Assessing: true, HasWebrootInvestigation: true, From: from,
	}, nil, nil, nil, leads)
	if r.PossibleCompromiseStatus != "POSSIBLE_COMPROMISE_REVIEW" {
		t.Fatalf("got %s", r.PossibleCompromiseStatus)
	}
	if !possibleCompromiseIsWebrootMetadataOnly(r) {
		t.Fatal("expected webroot-metadata-only possible compromise")
	}
	html := string(EncodeHTML(r))
	if strings.Contains(html, "<?php") {
		t.Fatal("PHP source leaked into HTML")
	}
	if !strings.Contains(html, "Webroot filesystem investigation") {
		t.Fatal("HTML missing webroot coverage section")
	}
	if !strings.Contains(html, "LOW-CONFIDENCE") {
		t.Fatal("HTML must explain low-confidence webroot-only possible compromise")
	}
	if !strings.Contains(html, "Elevated") || !strings.Contains(strings.ToLower(html), "low-confidence") {
		t.Fatal("overall priority must not overstate webroot-only as High EDR-strength")
	}
	csv, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	csvS := string(csv)
	if !strings.Contains(csvS, "POSSIBLE_COMPROMISE_REVIEW") {
		t.Fatal("CSV missing possible compromise status")
	}
	if !strings.Contains(csvS, "low-confidence webroot metadata") {
		t.Fatal("CSV limitations must explain webroot-only low confidence")
	}
}

func TestWebrootUnusualDoubleExtension(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "shell.php.jpg")
	if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(f, time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC), time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC))
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	leads := ScanWebrootInvestigation(r, root, SuggestedInvestigateFromUTC, r.GeneratedUTC)
	found := false
	for _, l := range leads {
		if l.Kind == "webroot_unusual_extension" {
			found = true
			if l.Confidence != "unconfirmed" {
				t.Fatalf("confidence=%s", l.Confidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected unusual extension lead, got %+v", leads)
	}
}

func TestWebrootNonExecutableDoubleExtensionNoLead(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"readme.php.txt", "config.php.bak", "notes.php.md"} {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte("not php source for export"), 0644); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(p, time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC), time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC))
	}
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	leads := ScanWebrootInvestigation(r, root, SuggestedInvestigateFromUTC, r.GeneratedUTC)
	for _, l := range leads {
		if l.Kind == "webroot_unusual_extension" {
			t.Fatalf("non-executable outer double-ext must not be unusual lead: %+v", l)
		}
	}
}

func TestWebrootCMSUploadOutsideWindowNoLead(t *testing.T) {
	root := t.TempDir()
	up := filepath.Join(root, "wp-content", "uploads", "2024", "01")
	_ = os.MkdirAll(up, 0755)
	f := filepath.Join(up, "legacy-plugin.php")
	_ = os.WriteFile(f, []byte("<?php /* old cms */"), 0644)
	old := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	_ = os.Chtimes(f, old, old)

	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	leads := ScanWebrootInvestigation(r, root, SuggestedInvestigateFromUTC, r.GeneratedUTC)
	FinalizeInvestigation(r, InvestigationOptions{
		Assessing: true, HasWebrootInvestigation: true,
	}, nil, nil, nil, leads)
	if len(leads) != 0 {
		t.Fatalf("long-lived CMS upload outside window must not lead: %+v", leads)
	}
	if r.PossibleCompromiseStatus != "NO_MATCHES_IN_SCOPE" {
		t.Fatalf("got %s", r.PossibleCompromiseStatus)
	}
}

func TestWebrootBenignAppNoLead(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"index.php", "app/Controller.php", "vendor/autoload.php"} {
		p := filepath.Join(root, name)
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		if err := os.WriteFile(p, []byte("<?php"), 0644); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(p, time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC), time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC))
	}
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	leads := ScanWebrootInvestigation(r, root, SuggestedInvestigateFromUTC, r.GeneratedUTC)
	FinalizeInvestigation(r, InvestigationOptions{
		Assessing: true, HasWebrootInvestigation: true,
	}, nil, nil, nil, leads)
	if r.PossibleCompromiseStatus != "NO_MATCHES_IN_SCOPE" {
		t.Fatalf("benign deploy must not be compromise lead, got %s leads=%d", r.PossibleCompromiseStatus, len(leads))
	}
}

func TestWebrootSymlinkRootRejected(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	_ = os.MkdirAll(real, 0755)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlink not supported:", err)
	}
	r := NewReport("host", "linux", "amd64")
	leads := ScanWebrootInvestigation(r, link, SuggestedInvestigateFromUTC, time.Now().UTC())
	if len(leads) != 0 || r.WebrootInvestigation[0].Status != "UNAVAILABLE" {
		t.Fatalf("symlink root must be unavailable, got %+v leads=%d", r.WebrootInvestigation, len(leads))
	}
	FinalizeInvestigation(r, InvestigationOptions{
		Assessing: true, HasWebrootInvestigation: true,
	}, nil, nil, nil, leads)
	if r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("unusable webroot must stay NOT_ASSESSED, got %s", r.PossibleCompromiseStatus)
	}
}

func TestWebrootMtimeProximityAloneDoesNotCorrelate(t *testing.T) {
	// On platforms without reliable birth (typical Linux), mtime±15m of an error
	// or process event must not create correlated_webroot_* findings or elevate confidence.
	root := t.TempDir()
	up := filepath.Join(root, "uploads")
	_ = os.MkdirAll(up, 0755)
	f := filepath.Join(up, "x.phtml")
	_ = os.WriteFile(f, []byte("x"), 0644)
	ts := time.Date(2026, 10, 18, 14, 6, 0, 0, time.UTC)
	_ = os.Chtimes(f, ts, ts)

	errlog := writeTemp(t, t.TempDir(), "error.log",
		`[18-Oct-2026 14:05:30 UTC] PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 3500032 bytes) in Unknown on line 0`+"\n")

	procCSV := "Timestamp,DeviceName,ActionType,FileName,FolderPath,ProcessId,ProcessCommandLine,InitiatingProcessFileName,InitiatingProcessFolderPath,InitiatingProcessId,ReportId\n" +
		"2026-10-18T14:06:30Z,win-web-01,ProcessCreated,cmd.exe,C:\\Windows\\System32,5000,cmd.exe,php-cgi.exe,C:\\PHP,4000,rpt-corr\n"
	procPath := writeTemp(t, t.TempDir(), "mde.csv", procCSV)

	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	leads := ScanWebrootInvestigation(r, root, SuggestedInvestigateFromUTC, r.GeneratedUTC)
	if len(leads) == 0 {
		t.Fatal("expected webroot leads from in-window upload/unusual")
	}
	for _, l := range leads {
		if l.BirthAvailable {
			t.Skip("platform reports birth; mtime-only correlation refusal not applicable here")
		}
	}
	errEv := ScanErrorLog(r, errlog)
	_, procLeads := ScanProcessTelemetry(r, procPath)
	FinalizeInvestigation(r, InvestigationOptions{
		Assessing: true, HasWebrootInvestigation: true, HasProcessTelemetry: true,
	}, nil, errEv, procLeads, leads)

	for _, fnd := range r.InvestigationFindings {
		if strings.HasPrefix(fnd.Kind, "correlated_webroot") {
			t.Fatalf("mtime proximity alone must not correlate webroot: %+v", fnd)
		}
		if strings.HasPrefix(fnd.Kind, "webroot_") && fnd.Confidence != "unconfirmed" {
			t.Fatalf("webroot finding confidence elevated: %+v", fnd)
		}
		if strings.Contains(fnd.Detail, "<?php") || strings.Contains(fnd.Detail, "whoami") {
			t.Fatal("sensitive content leaked")
		}
	}
	if r.PossibleCompromiseStatus != "POSSIBLE_COMPROMISE_REVIEW" {
		t.Fatalf("possible=%s (process + webroot leads still warrant review)", r.PossibleCompromiseStatus)
	}
	if possibleCompromiseIsWebrootMetadataOnly(r) {
		t.Fatal("process leads present — must not classify as webroot-metadata-only")
	}
	pri := overallPriority(r)
	if !strings.Contains(pri, "High") {
		t.Fatalf("with EDR process leads, priority should stay High, got %q", pri)
	}
}

func TestWebrootBirthCorrelationWhenAvailable(t *testing.T) {
	w := WebrootLead{
		Path: "/demo/uploads/x.php", RelPath: "uploads/x.php",
		Kind: "webroot_php_in_upload_dir", Confidence: "unconfirmed",
		MtimeUTC: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), // stale mtime must be ignored
		BirthUTC: time.Date(2026, 10, 18, 14, 6, 0, 0, time.UTC), BirthAvailable: true,
		DedupKey: "webroot_php_in_upload_dir|uploads/x.php",
	}
	errEv := []InvestigationEvent{{
		Kind: "php_oom_unknown_line0", Time: time.Date(2026, 10, 18, 14, 5, 30, 0, time.UTC),
		Line: 1, Location: "error.log:1",
	}}
	r := NewReport("host", "linux", "amd64")
	n := correlateWebroot(r, []WebrootLead{w}, errEv, nil, nil)
	if n == 0 {
		t.Fatal("expected birth-based correlation")
	}
	found := false
	for _, f := range r.InvestigationFindings {
		if f.Kind == "correlated_webroot_and_error" {
			found = true
			if f.Confidence != "unconfirmed" {
				t.Fatalf("correlation must stay unconfirmed, got %s", f.Confidence)
			}
			if !strings.Contains(f.Detail, "mtime was not used") {
				t.Fatalf("detail must state mtime unused: %s", f.Detail)
			}
		}
	}
	if !found {
		t.Fatal("missing correlated_webroot_and_error")
	}

	// Same lead without birth: no correlation even if mtime matches.
	r2 := NewReport("host", "linux", "amd64")
	w2 := w
	w2.BirthAvailable = false
	w2.MtimeUTC = time.Date(2026, 10, 18, 14, 6, 0, 0, time.UTC)
	if correlateWebroot(r2, []WebrootLead{w2}, errEv, nil, nil) != 0 {
		t.Fatal("mtime-only must not correlate")
	}
}

func TestWebrootMtimeCaveatNotCreation(t *testing.T) {
	root := t.TempDir()
	up := filepath.Join(root, "tmp")
	_ = os.MkdirAll(up, 0755)
	f := filepath.Join(up, "a.php")
	_ = os.WriteFile(f, []byte("x"), 0644)
	_ = os.Chtimes(f, time.Date(2026, 10, 18, 15, 0, 0, 0, time.UTC), time.Date(2026, 10, 18, 15, 0, 0, 0, time.UTC))
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	leads := ScanWebrootInvestigation(r, root, SuggestedInvestigateFromUTC, r.GeneratedUTC)
	for _, l := range leads {
		low := strings.ToLower(l.Detail)
		if strings.Contains(low, "modification time") && (strings.Contains(low, "never treated as file creation") ||
			strings.Contains(low, "not file creation") || strings.Contains(low, "mtime is not")) {
			return
		}
		if strings.Contains(l.Detail, "Modification time is never treated as file creation") {
			return
		}
	}
	if len(r.WebrootInvestigation) > 0 && strings.Contains(r.WebrootInvestigation[0].Detail, "mtime is never treated as creation") {
		return
	}
	t.Fatalf("mtime≠creation caveat missing: leads=%+v cov=%+v", leads, r.WebrootInvestigation)
}

func TestWebrootIncompleteCoverageStaysNotAssessedOrIncomplete(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	r := NewReport("host", "linux", "amd64")
	leads := ScanWebrootInvestigation(r, missing, SuggestedInvestigateFromUTC, time.Now().UTC())
	if len(leads) != 0 {
		t.Fatalf("no leads from missing root: %d", len(leads))
	}
	if r.WebrootInvestigation[0].Status != "UNAVAILABLE" {
		t.Fatalf("status=%s", r.WebrootInvestigation[0].Status)
	}
	FinalizeInvestigation(r, InvestigationOptions{
		Assessing: true, HasWebrootInvestigation: true,
	}, nil, nil, nil, leads)
	if r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("incomplete webroot must not invent compromise status, got %s", r.PossibleCompromiseStatus)
	}
}

func TestIsPHPLikeAndUploadHelpers(t *testing.T) {
	if !isPHPLikeName("x.phtml") || !isUnusualPHPExtension("x.php.jpg") {
		t.Fatal("helpers")
	}
	if isUnusualPHPExtension("index.php") {
		t.Fatal("normal php must not be unusual")
	}
	if isUnusualPHPExtension("readme.php.txt") || isUnusualPHPExtension("config.php.bak") {
		t.Fatal("non-executable outer must not be unusual")
	}
	if !pathLooksLikeUploadDir("wp-content/uploads/2026/a.php") {
		t.Fatal("upload path")
	}
}
