package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWindowsVMReport8424PathInferencePipeline reproduces the real v2.3.0 TestVM HTML
// report scenario (2026-10-21): four binaries under Programs\PHP\current and
// Programs\PHP\8.4.24\nts\x64 with no embedded/PE version markers, administrator-
// confirmed PHP 8.4.24 via php -v (not used by the scanner).
//
// Validates discovery → version inference → alias corroboration → patch assessment →
// HTML/CSV reporting, without executing PHP or claiming an active web runtime.
func TestWindowsVMReport8424PathInferencePipeline(t *testing.T) {
	root := t.TempDir()
	versioned := filepath.Join(root, "AppData", "Local", "Programs", "PHP", "8.4.24", "nts", "x64")
	current := filepath.Join(root, "AppData", "Local", "Programs", "PHP", "current")
	if err := os.MkdirAll(versioned, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(current, 0755); err != nil {
		t.Fatal(err)
	}

	// Marker-free payloads (same content for current vs versioned → corroborate alias).
	phpBody := []byte("MZ\x00\x00 official-windows-php-layout-fixture-without-version-resource")
	cgiBody := []byte("MZ\x00\x00 official-windows-php-cgi-layout-fixture-without-version-resource")
	paths := []struct {
		dir  string
		name string
		body []byte
	}{
		{current, "php.exe", phpBody},
		{current, "php-cgi.exe", cgiBody},
		{versioned, "php.exe", phpBody},
		{versioned, "php-cgi.exe", cgiBody},
	}
	for _, p := range paths {
		if err := os.WriteFile(filepath.Join(p.dir, p.name), p.body, 0644); err != nil {
			t.Fatal(err)
		}
	}

	r := NewReport("TestVM", "windows", "amd64")
	src := "Windows LocalAppData Programs\\PHP static binary inspection"
	for _, p := range paths {
		AddBinaryVersionEvidence(r, filepath.Join(p.dir, p.name), p.name, src)
	}
	if len(r.Evidence) != 4 {
		t.Fatalf("expected 4 evidence rows, got %d", len(r.Evidence))
	}

	// Before reconcile: versioned paths inferred; current may still be unknown.
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	if r.VulnerabilityStatus != "BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED" {
		t.Fatalf("status=%s assessments=%+v", r.VulnerabilityStatus, r.PatchAssessments)
	}
	if len(r.PatchAssessments) == 0 {
		t.Fatal("expected patch assessments")
	}

	var sawInferred, saw8424, sawConfidence bool
	installKeys := map[string]struct{}{}
	for _, a := range r.PatchAssessments {
		if a.ObservedVersion == "8.4.24" {
			saw8424 = true
		}
		if a.EvidenceType == "binary_path_inferred_version" {
			sawInferred = true
		}
		if a.Confidence == "MEDIUM" && strings.Contains(a.Qualification, "PATH-INFERRED") {
			sawConfidence = true
		}
		if a.Status != "BELOW_UPSTREAM_FIX" || a.MinimumFixed != "8.4.27" {
			t.Fatalf("unexpected assessment %+v", a)
		}
		installKeys[a.InstallKey] = struct{}{}
	}
	if !saw8424 || !sawInferred || !sawConfidence {
		t.Fatalf("missing inferred/confidence signalling: assessments=%+v", r.PatchAssessments)
	}
	// current + versioned directories should collapse to one install group when corroborated.
	if len(installKeys) != 1 {
		t.Fatalf("expected one corroborated install key, got %v from %+v", installKeys, r.PatchAssessments)
	}

	label, vers := humanPHPDetected(r)
	if label != "Yes" || len(vers) != 1 || vers[0] != "8.4.24" {
		t.Fatalf("php detected label=%q vers=%v", label, vers)
	}
	rt, detail := humanRuntime(r)
	if rt == "Verified" {
		t.Fatal("must not claim verified web runtime from CLI/path inventory")
	}
	if !strings.Contains(strings.ToLower(detail), "not verified") && rt != "Candidates identified" {
		t.Fatalf("runtime=%q detail=%q", rt, detail)
	}

	html := string(EncodeHTML(r))
	for _, want := range []string{
		"8.4.24",
		"8.4.27",
		"Update review required",
		"path-inferred",
		"confidence=MEDIUM",
		"PATH-INFERRED",
		Version, // scanner version embedded in report header
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	if strings.Contains(strings.ToLower(html), "active runtime verified") {
		t.Fatal("HTML must not claim active runtime verified")
	}

	fleetBytes, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	fleetRows, err := ParseFleetCSV(fleetBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(fleetRows) != 1 || fleetRows[0].PHPVersion != "8.4.24" || fleetRows[0].UpstreamMinimumFixed != "8.4.27" {
		t.Fatalf("fleet CSV %+v", fleetRows)
	}
	if fleetRows[0].VersionEvidence != "path_inferred" || fleetRows[0].VersionConfidence != "MEDIUM" {
		t.Fatalf("%+v", fleetRows[0])
	}
	if fleetRows[0].PatchStatus != "BELOW_UPSTREAM_FIX" {
		t.Fatal(fleetRows[0].PatchStatus)
	}

	// Legacy evidence CSV still encodes assessments for older tooling.
	csvBytes, err := EncodeCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	csv := string(csvBytes)
	if !strings.Contains(csv, "patch_assessment") || !strings.Contains(csv, "8.4.24") {
		t.Fatalf("CSV missing assessment/version: %s", csv)
	}
	if !strings.Contains(csv, "confidence=MEDIUM") || !strings.Contains(csv, "binary_path_inferred_version") {
		t.Fatalf("CSV missing confidence/inferred type: %s", csv)
	}
	if !strings.Contains(csv, "BELOW_UPSTREAM_FIX") || !strings.Contains(csv, "min_fixed=8.4.27") {
		t.Fatalf("CSV missing patch status: %s", csv)
	}

	groups := GroupInstallations(r)
	if len(groups) != 1 {
		t.Fatalf("expected one grouped installation, got %d (%+v)", len(groups), groups)
	}
	if groups[0].Version != "8.4.24" || groups[0].MinimumFixed != "8.4.27" {
		t.Fatalf("%+v", groups[0])
	}
}

func TestWindowsVMCurrentNotMergedWithoutCorroboration(t *testing.T) {
	root := t.TempDir()
	versioned := filepath.Join(root, "Programs", "PHP", "8.4.24", "nts", "x64")
	current := filepath.Join(root, "Programs", "PHP", "current")
	_ = os.MkdirAll(versioned, 0755)
	_ = os.MkdirAll(current, 0755)
	_ = os.WriteFile(filepath.Join(versioned, "php.exe"), []byte("MZ versioned-build-A"), 0644)
	_ = os.WriteFile(filepath.Join(current, "php.exe"), []byte("MZ different-current-build-B"), 0644)

	r := NewReport("host", "windows", "amd64")
	AddBinaryVersionEvidence(r, filepath.Join(versioned, "php.exe"), "php.exe", "test")
	AddBinaryVersionEvidence(r, filepath.Join(current, "php.exe"), "php.exe", "test")
	EvaluatePatchPosture(r)

	keys := map[string]struct{}{}
	for _, a := range r.PatchAssessments {
		keys[a.InstallKey] = struct{}{}
	}
	if len(keys) < 1 {
		t.Fatal("expected at least the versioned assessment")
	}
	// current has no path version and different content → remains version-unknown,
	// so only the versioned path yields a patch assessment.
	if len(r.PatchAssessments) != 1 || r.PatchAssessments[0].ObservedVersion != "8.4.24" {
		t.Fatalf("%+v", r.PatchAssessments)
	}
	warned := false
	for _, w := range r.Warnings {
		if strings.Contains(w, "not corroborated") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected non-corroboration warning, got %v", r.Warnings)
	}
}

func TestVersionFromInstallPathSegments(t *testing.T) {
	v, src := VersionFromInstallPath(`C:\Users\x\AppData\Local\Programs\PHP\8.4.24\nts\x64\php.exe`)
	if v != "8.4.24" || src == "" {
		t.Fatalf("%q %q", v, src)
	}
	v, _ = VersionFromInstallPath(`C:\Users\x\AppData\Local\Programs\PHP\current\php.exe`)
	if v != "" {
		t.Fatalf("current alone must not invent a version: %q", v)
	}
}
