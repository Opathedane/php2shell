package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionFromEmbeddedString(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "php-fpm8.4")
	payload := strings.Repeat("\x00", 4096) + "PHP Version 8.4.26" + strings.Repeat("\x00", 4096)
	if err := os.WriteFile(path, []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}
	res := VersionFromBinary(path)
	if res.Err != nil || res.Version != "8.4.26" {
		t.Fatalf("got %+v", res)
	}
	if !strings.Contains(strings.Join(res.Sources, ","), "embedded_build_string") {
		t.Fatal(res.Sources)
	}
	if res.Coverage.Partial {
		t.Fatalf("small file should be full read: %+v", res.Coverage)
	}
	if res.Provenance != "verified_binary_metadata" || res.Confidence != "HIGH" {
		t.Fatalf("provenance=%s confidence=%s", res.Provenance, res.Confidence)
	}
}

func TestLargeBinaryPartialInspectionFindsHeadMarker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "php.exe")
	const size = binaryFullReadLimit + (1 << 20)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("PHP Version 8.4.27"); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	f.Close()
	res := VersionFromBinary(path)
	if res.Err != nil || res.Version != "8.4.27" {
		t.Fatalf("got %+v", res)
	}
	if !res.Coverage.Partial {
		t.Fatalf("expected partial inspection: %+v", res.Coverage)
	}
	if !strings.Contains(res.Coverage.Detail, "partial_window_read") {
		t.Fatal(res.Coverage.Detail)
	}
	if !strings.Contains(strings.Join(res.Sources, ","), "partial_file_window_inspection") {
		t.Fatal(res.Sources)
	}
}

func TestLargeBinaryPartialInspectionMissReportsIncomplete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "php.exe")
	const size = binaryFullReadLimit + (5 << 20)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, binaryHeadWindow+1024)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(size-(2<<20), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("PHP Version 8.4.99"); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	f.Close()
	res := VersionFromBinary(path)
	if res.Err != nil || res.Version != "8.4.99" {
		t.Fatalf("tail marker should be found: %+v", res)
	}
	if !res.Coverage.Partial {
		t.Fatal(res.Coverage)
	}
}

func TestLargeBinaryNoMarkerPartialCoverage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "php.exe")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(binaryFullReadLimit + 1024); err != nil {
		t.Fatal(err)
	}
	f.Close()
	res := VersionFromBinary(path)
	if res.Err == nil || res.Version != "" {
		t.Fatalf("expected missing marker error: %+v", res)
	}
	if !res.Coverage.Partial || res.Coverage.BytesRead == 0 {
		t.Fatalf("expected partial read stats: %+v", res.Coverage)
	}
}

func TestPENotUsedWithoutPHPContent(t *testing.T) {
	b := []byte{'M', 'Z', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	_, _, err := versionMarkersFromBytes(b)
	if err == nil {
		t.Fatal("expected no version without PHP markers")
	}
}

func TestAddBinaryVersionEvidenceStaticNotRuntime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "php.exe")
	body := "PHP Version 8.4.27 built by static test"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	r := NewReport("host", "windows", "amd64")
	AddBinaryVersionEvidence(r, path, "php.exe", "test")
	if len(r.Evidence) != 1 || r.Evidence[0].Type != "binary_static_version" {
		t.Fatalf("%+v", r.Evidence)
	}
	if r.Evidence[0].Interpretation != "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION" {
		t.Fatal(r.Evidence[0].Interpretation)
	}
}

func TestAddBinaryVersionEvidencePartialWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "php.exe")
	f, _ := os.Create(path)
	f.WriteString("PHP Version 8.2.35")
	f.Truncate(binaryFullReadLimit + 4096)
	f.Close()
	r := NewReport("host", "linux", "amd64")
	AddBinaryVersionEvidence(r, path, "php.exe", "test")
	if len(r.Warnings) == 0 {
		t.Fatal("expected partial inspection warning")
	}
	if !strings.Contains(r.Evidence[0].Detail, "inspect_coverage=partial") {
		t.Fatal(r.Evidence[0].Detail)
	}
}

func TestPathInferredVersionWhenMarkersAbsent(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "Programs", "PHP", "8.4.24", "nts", "x64")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(binDir, "php.exe")
	// Deliberately no PHP Version string / PE resource — mirrors TestVM report.
	if err := os.WriteFile(path, []byte("MZ\x00\x00 not a real PE resource"), 0644); err != nil {
		t.Fatal(err)
	}
	res := VersionFromBinary(path)
	if res.Version != "8.4.24" || res.Provenance != "path_inferred" || res.Confidence != "MEDIUM" {
		t.Fatalf("%+v", res)
	}
	r := NewReport("TestVM", "windows", "amd64")
	AddBinaryVersionEvidence(r, path, "php.exe", "Windows LocalAppData Programs\\PHP static binary inspection")
	if r.Evidence[0].Type != "binary_path_inferred_version" || r.Evidence[0].Version != "8.4.24" {
		t.Fatalf("%+v", r.Evidence[0])
	}
}
