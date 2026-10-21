package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDeepDiscoverTruncationIncompleteHTMLCSVRollup(t *testing.T) {
	isolatePHPIniHostDiscovery(t)
	prevEntries := deepEntriesCap
	deepEntriesCap = 8
	t.Cleanup(func() { deepEntriesCap = prevEntries })

	root := t.TempDir()
	for i := 0; i < 40; i++ {
		_ = os.WriteFile(filepath.Join(root, "pad"+itoa(i)+".dat"), []byte("pad"), 0644)
	}
	writeFakePHP(t, filepath.Join(root, "late", phpName("php")), "8.4.24")

	r := NewReport("deep-trunc", runtime.GOOS, "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 22, 0, 0, 0, time.UTC)
	ScanHost(r, HostScanOptions{DeepRoots: []string{root}})
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	deepStatus := ""
	binStatus := ""
	for _, c := range r.Coverage {
		switch c.Name {
		case "deep_discovery":
			deepStatus = c.Status
		case "binary_paths":
			binStatus = c.Status
		}
	}
	if !strings.EqualFold(deepStatus, "TRUNCATED") && !strings.EqualFold(deepStatus, "INCOMPLETE") {
		t.Fatalf("deep_discovery coverage want TRUNCATED/INCOMPLETE, got %q coverage=%+v", deepStatus, r.Coverage)
	}
	if !strings.EqualFold(binStatus, "TRUNCATED") {
		t.Fatalf("binary_paths should be TRUNCATED when deep truncates, got %q", binStatus)
	}
	if !ScanIncomplete(r) {
		t.Fatal("ScanIncomplete must be true after deep truncation")
	}
	if code := ScanExitCode(r, nil); code != ExitIncomplete {
		t.Fatalf("exit code want %d (incomplete), got %d — exit 0 must not mean complete coverage", ExitIncomplete, code)
	}

	html := string(EncodeHTML(r))
	if !strings.Contains(strings.ToUpper(html), "TRUNCATED") && !strings.Contains(html, "incomplete") {
		t.Fatalf("HTML must surface truncation/incomplete coverage")
	}
	rows := BuildFleetRows(r)
	if len(rows) == 0 {
		t.Fatal("expected fleet rows")
	}
	for _, row := range rows {
		if row.DiscoveryCompleteness != "INCOMPLETE" {
			t.Fatalf("fleet discovery_completeness want INCOMPLETE, got %q row=%+v", row.DiscoveryCompleteness, row)
		}
		if !strings.Contains(row.LimitationsSummary, "Deep Discovery") &&
			!strings.Contains(row.LimitationsSummary, "not complete host coverage") {
			t.Fatalf("limitations must note bounded/deep discovery: %q", row.LimitationsSummary)
		}
	}

	csvPath := filepath.Join(root, "trunc.csv")
	data, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(csvPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	outRollup := filepath.Join(root, "rollup.csv")
	if err := RollupFleetCSV(FleetRollupOptions{InputFiles: []string{csvPath}, Output: outRollup}); err != nil {
		t.Fatal(err)
	}
	rolled, err := os.ReadFile(outRollup)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rolled), "INCOMPLETE") {
		snip := string(rolled)
		if len(snip) > 400 {
			snip = snip[:400]
		}
		t.Fatalf("rollup must preserve INCOMPLETE: %s", snip)
	}
}

func TestDeepDiscoverDirNameNotHighConfidence(t *testing.T) {
	isolatePHPIniHostDiscovery(t)
	root := t.TempDir()
	// Directory name looks like a fixed version, but binary has no version marker.
	dir := filepath.Join(root, "PHP", "8.4.27", "nts", "x64")
	_ = os.MkdirAll(dir, 0755)
	bin := filepath.Join(dir, phpName("php"))
	payload := []byte("MZ\x00no version marker here\x00")
	if runtime.GOOS != "windows" {
		payload = []byte("ELF\x00no version marker here\x00")
	}
	if err := os.WriteFile(bin, payload, 0755); err != nil {
		t.Fatal(err)
	}

	r := NewReport("path-only", runtime.GOOS, "amd64")
	ScanHost(r, HostScanOptions{DeepRoots: []string{root}})
	EvaluatePatchPosture(r)

	for _, e := range r.Evidence {
		if normalizeInstallPath(e.Location) != normalizeInstallPath(bin) {
			continue
		}
		if e.Type == "binary_static_version" {
			t.Fatalf("unexpected verified static version without marker: %+v", e)
		}
		if e.Type == "binary_path_inferred_version" && e.Version == "8.4.27" {
			// Path inference is allowed at MEDIUM, never HIGH.
			for _, a := range r.PatchAssessments {
				if normalizeInstallPath(a.Location) == normalizeInstallPath(bin) || strings.Contains(a.InstallKey, "8.4.27") {
					if strings.EqualFold(a.Confidence, "HIGH") {
						t.Fatalf("path-inferred version must not be HIGH: %+v", a)
					}
				}
			}
		}
	}
	rows := BuildFleetRows(r)
	for _, row := range rows {
		if row.PHPVersion == "8.4.27" && strings.EqualFold(row.VersionConfidence, "HIGH") {
			t.Fatalf("CSV must not claim HIGH for directory-name inference alone: %+v", row)
		}
		if strings.EqualFold(row.VersionConfidence, "HIGH") && row.VersionEvidence != "verified_binary_metadata" {
			t.Fatalf("HIGH requires verified_binary_metadata, got %+v", row)
		}
	}
}

func TestDeepDiscoverIndependentInstallsNotMerged(t *testing.T) {
	isolatePHPIniHostDiscovery(t)
	root := t.TempDir()
	left := filepath.Join(root, "left", "8.4.24", phpName("php"))
	right := filepath.Join(root, "right", "8.4.24", phpName("php"))
	// Same version string, different content fingerprints → must stay separate.
	writeFakePHP(t, left, "8.4.24")
	if err := os.MkdirAll(filepath.Dir(right), 0755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("MZ\x00OTHER PHP Version 8.4.24\x00distinct-fingerprint")
	if runtime.GOOS != "windows" {
		payload = []byte("ELF\x00OTHER PHP Version 8.4.24\x00distinct-fingerprint")
	}
	if err := os.WriteFile(right, payload, 0755); err != nil {
		t.Fatal(err)
	}

	r := NewReport("no-merge", runtime.GOOS, "amd64")
	ScanHost(r, HostScanOptions{DeepRoots: []string{root}})
	EvaluatePatchPosture(r)

	keys := map[string]bool{}
	for _, g := range GroupInstallations(r) {
		if strings.HasPrefix(g.Key, "install:binary-dir:") {
			keys[g.Key] = true
		}
	}
	if len(keys) < 2 {
		t.Fatalf("independent same-version trees must not merge: keys=%v", keys)
	}
}
