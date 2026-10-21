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
	ver, src, cov, err := VersionFromBinary(path)
	if err != nil || ver != "8.4.26" {
		t.Fatalf("got %q %v %v %v", ver, src, cov, err)
	}
	if !strings.Contains(strings.Join(src, ","), "embedded_build_string") {
		t.Fatal(src)
	}
	if cov.Partial {
		t.Fatalf("small file should be full read: %+v", cov)
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
	ver, src, cov, err := VersionFromBinary(path)
	if err != nil || ver != "8.4.27" {
		t.Fatalf("got %q src=%v cov=%+v err=%v", ver, src, cov, err)
	}
	if !cov.Partial {
		t.Fatalf("expected partial inspection: %+v", cov)
	}
	if !strings.Contains(cov.Detail, "partial_window_read") {
		t.Fatal(cov.Detail)
	}
	if !strings.Contains(strings.Join(src, ","), "partial_file_window_inspection") {
		t.Fatal(src)
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
	ver, _, cov, err := VersionFromBinary(path)
	if err != nil || ver != "8.4.99" {
		t.Fatalf("tail marker should be found: ver=%q cov=%+v err=%v", ver, cov, err)
	}
	if !cov.Partial {
		t.Fatal(cov)
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
	_, _, cov, err := VersionFromBinary(path)
	if err == nil {
		t.Fatal("expected missing marker error")
	}
	if !cov.Partial || cov.BytesRead == 0 {
		t.Fatalf("expected partial read stats: %+v", cov)
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
