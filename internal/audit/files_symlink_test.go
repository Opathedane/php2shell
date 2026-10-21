package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadRegularRejectsSymlinkWithoutFollow(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.ini")
	if err := os.WriteFile(target, []byte("memory_limit = 16M\n"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.ini")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink required: %v", err)
	}
	b, err := ReadRegular(link, 1<<20)
	if err == nil || b != nil {
		t.Fatalf("expected symlink rejection, got data=%q err=%v", b, err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "symbolic") && !strings.Contains(strings.ToLower(err.Error()), "reparse") && !strings.Contains(strings.ToLower(err.Error()), "not a regular") {
		t.Fatalf("unexpected error: %v", err)
	}
	// Target itself remains readable.
	if _, err := ReadRegular(target, 1<<20); err != nil {
		t.Fatal(err)
	}
}

func TestReadRegularRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadRegular(dir, 1<<20); err == nil {
		t.Fatal("expected directory rejection")
	}
}

func TestReadRegularPermissionErrorProducesNoPHPIniEvidence(t *testing.T) {
	// Portable proof that observePHPIniFile emits nothing when the reader fails,
	// independent of OS ACL semantics around chmod.
	root := t.TempDir()
	path := filepath.Join(root, "php.ini")
	if err := os.WriteFile(path, []byte("memory_limit = 8M\n"), 0644); err != nil {
		t.Fatal(err)
	}
	orig := readPHPIniContents
	t.Cleanup(func() { readPHPIniContents = orig })
	readPHPIniContents = func(string, int64) ([]byte, error) {
		return nil, os.ErrPermission
	}
	r := NewReport("perm", runtime.GOOS, runtime.GOARCH)
	st := newPHPIniScanState()
	st.observePHPIniFile(r, path, "stub-denied", "primary_candidate")
	if len(r.Evidence) != 0 {
		t.Fatalf("expected no evidence on read error: %+v", r.Evidence)
	}
}
