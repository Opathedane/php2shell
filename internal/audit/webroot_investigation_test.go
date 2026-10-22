package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func invWindow() (from, to time.Time) {
	to = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	return SuggestedInvestigateFromUTC, to
}

// mustSetFixtureTimes sets mtime and birth for cross-platform deterministic fixtures.
// When the OS reports birth, the read-back birth must match the requested value
// within a small skew — tests must not assume Chtimes rewrites creation time.
func mustSetFixtureTimes(t *testing.T, path string, mtime, birth time.Time) {
	t.Helper()
	if err := setFixtureFileTimes(path, mtime, mtime, birth); err != nil {
		t.Fatalf("setFixtureFileTimes(%s): %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	gotM := info.ModTime().UTC()
	if gotM.Sub(mtime.UTC()).Abs() > 2*time.Second {
		t.Fatalf("mtime not applied: want %s got %s", mtime.UTC(), gotM)
	}
	gotB, ok := fileBirthTimeUTC(info)
	if !ok {
		return // Linux / platforms without birth — mtime fixture is authoritative
	}
	if gotB.Sub(birth.UTC()).Abs() > 2*time.Second {
		t.Fatalf("birth not applied (Chtimes does not change creation time): want %s got %s", birth.UTC(), gotB)
	}
}

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
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	from, to := invWindow()
	inWin := time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC)
	mustSetFixtureTimes(t, f, inWin, inWin)

	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = to
	leads := ScanWebrootInvestigation(r, root, from, to)
	if len(leads) == 0 {
		t.Fatalf("expected upload lead, coverage=%+v", r.WebrootInvestigation)
	}
	foundUpload, foundTemporal := false, false
	for _, l := range leads {
		if l.Confidence != "unconfirmed" {
			t.Fatalf("metadata lead must be unconfirmed, got %s", l.Confidence)
		}
		if l.Kind == "webroot_php_in_upload_dir" {
			foundUpload = true
			if !strings.Contains(l.Detail, "LOCATION CONTEXT") {
				t.Fatalf("path lead must be labeled location context: %s", l.Detail)
			}
		}
		if webrootLeadIsTimestampEvidence(l.Kind) {
			foundTemporal = true
		}
		if strings.Contains(l.Detail, "<?php") {
			t.Fatal("file contents must not appear in lead detail")
		}
	}
	if !foundUpload || !foundTemporal {
		t.Fatalf("need path context + timestamp evidence, got %+v", leads)
	}
	FinalizeInvestigation(r, InvestigationOptions{
		Assessing: true, HasWebrootInvestigation: true, From: from,
	}, nil, nil, nil, leads)
	if r.PossibleCompromiseStatus != "POSSIBLE_COMPROMISE_REVIEW" {
		t.Fatalf("got %s", r.PossibleCompromiseStatus)
	}
	html := string(EncodeHTML(r))
	if strings.Contains(html, "<?php") {
		t.Fatal("PHP source leaked into HTML")
	}
	if !strings.Contains(html, "LOW-CONFIDENCE") {
		t.Fatal("HTML must explain low-confidence webroot-only possible compromise")
	}
	csv, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(csv), "POSSIBLE_COMPROMISE_REVIEW") ||
		!strings.Contains(string(csv), "low-confidence webroot metadata") {
		t.Fatal("CSV must match HTML low-confidence webroot-only messaging")
	}
}

func TestWebrootUnusualDoubleExtension(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "shell.php.jpg")
	if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	from, to := invWindow()
	inWin := time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC)
	mustSetFixtureTimes(t, f, inWin, inWin)
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = to
	leads := ScanWebrootInvestigation(r, root, from, to)
	found := false
	for _, l := range leads {
		if l.Kind == "webroot_unusual_extension" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unusual extension lead, got %+v", leads)
	}
}

func TestWebrootNonExecutableDoubleExtensionNoLead(t *testing.T) {
	root := t.TempDir()
	from, to := invWindow()
	inWin := time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC)
	for _, name := range []string{"readme.php.txt", "config.php.bak", "notes.php.md"} {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte("not php source for export"), 0644); err != nil {
			t.Fatal(err)
		}
		mustSetFixtureTimes(t, p, inWin, inWin)
	}
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = to
	leads := ScanWebrootInvestigation(r, root, from, to)
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
	// Deterministic: set BOTH mtime and birth outside the window. Never assume
	// Chtimes rewrites creation time (Windows/macOS keep real create time).
	mustSetFixtureTimes(t, f, old, old)

	from, to := invWindow()
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = to
	leads := ScanWebrootInvestigation(r, root, from, to)
	FinalizeInvestigation(r, InvestigationOptions{
		Assessing: true, HasWebrootInvestigation: true,
	}, nil, nil, nil, leads)
	if len(leads) != 0 {
		t.Fatalf("historical CMS (both timestamps outside window) must not lead: %+v", leads)
	}
	if r.PossibleCompromiseStatus != "NO_MATCHES_IN_SCOPE" {
		t.Fatalf("got %s", r.PossibleCompromiseStatus)
	}
	assertHTMLCSVConsistentPossible(t, r)
}

func TestWebrootOldMtimeNewBirthPreserved(t *testing.T) {
	// Requirement: detect in-window creation even when mtime is old.
	from, to := invWindow()
	oldM := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	newB := time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC)

	// Pure evaluation — deterministic on every OS.
	leads := webrootLeadsForFile(webrootFileMeta{
		Path: "/demo/uploads/drop.php", RelPath: "uploads/drop.php", Name: "drop.php",
		Mtime: oldM, Birth: newB, BirthOK: true,
	}, from, to)
	kinds := map[string]bool{}
	for _, l := range leads {
		kinds[l.Kind] = true
	}
	if !kinds["webroot_birth_in_window"] {
		t.Fatalf("expected birth_in_window with old mtime, got %+v", leads)
	}
	if !kinds["webroot_php_in_upload_dir"] {
		t.Fatalf("expected path context alongside birth evidence, got %+v", leads)
	}
	if kinds["webroot_mtime_in_window"] {
		t.Fatal("old mtime must not emit mtime_in_window")
	}

	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = to
	r.WebrootInvestigation = []WebrootInvestigationCoverage{{
		Root: "/demo", Status: "ASSESSED_SCOPE_LIMITED", EntriesSeen: 1, PHPLikeSeen: 1, Leads: len(leads),
	}}
	FinalizeInvestigation(r, InvestigationOptions{
		Assessing: true, HasWebrootInvestigation: true,
	}, nil, nil, nil, leads)
	if r.PossibleCompromiseStatus != "POSSIBLE_COMPROMISE_REVIEW" {
		t.Fatalf("in-window birth must drive possible compromise, got %s", r.PossibleCompromiseStatus)
	}
	if !possibleCompromiseIsWebrootMetadataOnly(r) {
		t.Fatal("expected webroot-metadata-only")
	}
	assertHTMLCSVConsistentPossible(t, r)

	// Filesystem fixture when the OS exposes adjustable birth.
	root := t.TempDir()
	up := filepath.Join(root, "uploads")
	_ = os.MkdirAll(up, 0755)
	f := filepath.Join(up, "drop.php")
	_ = os.WriteFile(f, []byte("x"), 0644)
	mustSetFixtureTimes(t, f, oldM, newB)
	info, _ := os.Stat(f)
	if _, ok := fileBirthTimeUTC(info); !ok {
		return // Linux: pure evaluation above already covers the behavior
	}
	r2 := NewReport("host", "linux", "amd64")
	r2.GeneratedUTC = to
	fsLeads := ScanWebrootInvestigation(r2, root, from, to)
	foundBirth := false
	for _, l := range fsLeads {
		if l.Kind == "webroot_birth_in_window" {
			foundBirth = true
		}
	}
	if !foundBirth {
		t.Fatalf("FS scan missed birth_in_window: %+v", fsLeads)
	}
}

func TestWebrootBothTimestampsOutsideWindow(t *testing.T) {
	from, to := invWindow()
	old := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	leads := webrootLeadsForFile(webrootFileMeta{
		Path: "/x/uploads/a.php", RelPath: "uploads/a.php", Name: "a.php",
		Mtime: old, Birth: old, BirthOK: true,
	}, from, to)
	if len(leads) != 0 {
		t.Fatalf("both outside window must yield no leads: %+v", leads)
	}
}

func TestWebrootBirthUnavailableMtimeOutsideNoLead(t *testing.T) {
	from, to := invWindow()
	old := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	leads := webrootLeadsForFile(webrootFileMeta{
		Path: "/x/uploads/a.php", RelPath: "uploads/a.php", Name: "a.php",
		Mtime: old, BirthOK: false,
	}, from, to)
	if len(leads) != 0 {
		t.Fatalf("birth unavailable + mtime outside must yield no leads: %+v", leads)
	}
}

func TestWebrootBirthUnavailableMtimeInWindow(t *testing.T) {
	from, to := invWindow()
	inWin := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	leads := webrootLeadsForFile(webrootFileMeta{
		Path: "/x/uploads/a.php", RelPath: "uploads/a.php", Name: "a.php",
		Mtime: inWin, BirthOK: false,
	}, from, to)
	kinds := map[string]bool{}
	for _, l := range leads {
		kinds[l.Kind] = true
	}
	if !kinds["webroot_mtime_in_window"] || !kinds["webroot_php_in_upload_dir"] {
		t.Fatalf("expected mtime evidence + path context: %+v", leads)
	}
	if kinds["webroot_birth_in_window"] {
		t.Fatal("birth unavailable must not invent birth lead")
	}
}

func TestWebrootPathOnlyWithoutTemporalNoCompromise(t *testing.T) {
	// Simulate a path-context-only lead (should not be emitted by scanner, but if
	// present must not overstate top-level compromise).
	from, to := invWindow()
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := webrootLeadsForFile(webrootFileMeta{
		Path: "/x/uploads/a.php", RelPath: "uploads/a.php", Name: "a.php",
		Mtime: old, Birth: old, BirthOK: true,
	}, from, to); len(got) != 0 {
		t.Fatalf("scanner must not emit path-only leads without temporal corroboration: %+v", got)
	}

	pathOnly := []WebrootLead{{
		Path: "/x/uploads/a.php", RelPath: "uploads/a.php",
		Kind: "webroot_php_in_upload_dir", Confidence: "unconfirmed",
		MtimeUTC: old, DedupKey: "webroot_php_in_upload_dir|uploads/a.php",
		Detail: "LOCATION CONTEXT only",
	}}
	r := NewReport("host", "linux", "amd64")
	r.WebrootInvestigation = []WebrootInvestigationCoverage{{
		Root: "/x", Status: "ASSESSED_SCOPE_LIMITED", EntriesSeen: 1, PHPLikeSeen: 1, Leads: 1,
	}}
	FinalizeInvestigation(r, InvestigationOptions{
		Assessing: true, HasWebrootInvestigation: true,
	}, nil, nil, nil, pathOnly)
	if r.PossibleCompromiseStatus != "NO_MATCHES_IN_SCOPE" {
		t.Fatalf("path-only must not produce POSSIBLE_COMPROMISE_REVIEW, got %s", r.PossibleCompromiseStatus)
	}
	// Finding may still be listed for analyst context.
	found := false
	for _, f := range r.InvestigationFindings {
		if f.Kind == "webroot_php_in_upload_dir" {
			found = true
		}
	}
	if !found {
		t.Fatal("path context finding should still be recorded")
	}
	assertHTMLCSVConsistentPossible(t, r)
}

func TestWebrootBenignAppNoLead(t *testing.T) {
	root := t.TempDir()
	from, to := invWindow()
	inWin := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	for _, name := range []string{"index.php", "app/Controller.php", "vendor/autoload.php"} {
		p := filepath.Join(root, name)
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		if err := os.WriteFile(p, []byte("<?php"), 0644); err != nil {
			t.Fatal(err)
		}
		mustSetFixtureTimes(t, p, inWin, inWin)
	}
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = to
	leads := ScanWebrootInvestigation(r, root, from, to)
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
	root := t.TempDir()
	up := filepath.Join(root, "uploads")
	_ = os.MkdirAll(up, 0755)
	f := filepath.Join(up, "x.phtml")
	_ = os.WriteFile(f, []byte("x"), 0644)
	ts := time.Date(2026, 10, 18, 14, 6, 0, 0, time.UTC)
	mustSetFixtureTimes(t, f, ts, ts)

	errlog := writeTemp(t, t.TempDir(), "error.log",
		`[18-Oct-2026 14:05:30 UTC] PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 3500032 bytes) in Unknown on line 0`+"\n")

	procCSV := "Timestamp,DeviceName,ActionType,FileName,FolderPath,ProcessId,ProcessCommandLine,InitiatingProcessFileName,InitiatingProcessFolderPath,InitiatingProcessId,ReportId\n" +
		"2026-10-18T14:06:30Z,win-web-01,ProcessCreated,cmd.exe,C:\\Windows\\System32,5000,cmd.exe,php-cgi.exe,C:\\PHP,4000,rpt-corr\n"
	procPath := writeTemp(t, t.TempDir(), "mde.csv", procCSV)

	from, to := invWindow()
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = to
	leads := ScanWebrootInvestigation(r, root, from, to)
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
	}
	if r.PossibleCompromiseStatus != "POSSIBLE_COMPROMISE_REVIEW" {
		t.Fatalf("possible=%s", r.PossibleCompromiseStatus)
	}
}

func TestWebrootBirthCorrelationWhenAvailable(t *testing.T) {
	w := WebrootLead{
		Path: "/demo/uploads/x.php", RelPath: "uploads/x.php",
		Kind: "webroot_php_in_upload_dir", Confidence: "unconfirmed",
		MtimeUTC: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		BirthUTC: time.Date(2026, 10, 18, 14, 6, 0, 0, time.UTC), BirthAvailable: true,
		DedupKey: "webroot_php_in_upload_dir|uploads/x.php",
	}
	errEv := []InvestigationEvent{{
		Kind: "php_oom_unknown_line0", Time: time.Date(2026, 10, 18, 14, 5, 30, 0, time.UTC),
		Line: 1, Location: "error.log:1",
	}}
	r := NewReport("host", "linux", "amd64")
	if correlateWebroot(r, []WebrootLead{w}, errEv, nil, nil) == 0 {
		t.Fatal("expected birth-based correlation")
	}
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
	from, to := invWindow()
	inWin := time.Date(2026, 10, 18, 15, 0, 0, 0, time.UTC)
	mustSetFixtureTimes(t, f, inWin, inWin)
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = to
	leads := ScanWebrootInvestigation(r, root, from, to)
	for _, l := range leads {
		low := strings.ToLower(l.Detail)
		if strings.Contains(low, "modification time") && strings.Contains(low, "creation") {
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
	if isUnusualPHPExtension("index.php") || isUnusualPHPExtension("readme.php.txt") {
		t.Fatal("helpers")
	}
	if !pathLooksLikeUploadDir("wp-content/uploads/2026/a.php") {
		t.Fatal("upload path")
	}
	if webrootLeadIsTimestampEvidence("webroot_php_in_upload_dir") {
		t.Fatal("path context is not timestamp evidence")
	}
	if !webrootLeadIsTimestampEvidence("webroot_birth_in_window") {
		t.Fatal("birth is timestamp evidence")
	}
}

func assertHTMLCSVConsistentPossible(t *testing.T, r *Report) {
	t.Helper()
	html := string(EncodeHTML(r))
	csv, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	csvS := string(csv)
	if !strings.Contains(csvS, r.PossibleCompromiseStatus) {
		t.Fatalf("CSV missing status %s", r.PossibleCompromiseStatus)
	}
	switch r.PossibleCompromiseStatus {
	case "POSSIBLE_COMPROMISE_REVIEW":
		if possibleCompromiseIsWebrootMetadataOnly(r) {
			if !strings.Contains(html, "LOW-CONFIDENCE") {
				t.Fatal("HTML missing low-confidence for webroot-only possible")
			}
			if !strings.Contains(csvS, "low-confidence webroot metadata") {
				t.Fatal("CSV missing low-confidence limitation")
			}
		}
	case "NO_MATCHES_IN_SCOPE":
		if strings.Contains(html, "LOW-CONFIDENCE investigative lead from webroot metadata only") {
			t.Fatal("HTML must not claim webroot-only possible when NO_MATCHES")
		}
	}
}
