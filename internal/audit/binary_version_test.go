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
	ver, src, err := VersionFromBinary(path)
	if err != nil || ver != "8.4.26" {
		t.Fatalf("got %q %v %v", ver, src, err)
	}
	if !strings.Contains(strings.Join(src, ","), "embedded_build_string") {
		t.Fatal(src)
	}
}

func TestPENotUsedWithoutPHPContent(t *testing.T) {
	// Minimal MZ header only — not PHP-related; must not invent a version from PE alone.
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
