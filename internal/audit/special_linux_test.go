//go:build linux

package audit

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestFIFOIsNotOpened(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "Dockerfile")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	r := NewReport("test", "linux", "amd64")
	ScanRepository(r, root)
	if len(r.Evidence) != 0 || r.Repositories[0].SkippedFiles == 0 {
		t.Fatalf("special file was treated as a regular input: %+v", r.Repositories)
	}
	if _, err := ReadRegular(fifo, 1024); err == nil {
		t.Fatal("FIFO read was accepted")
	}
	info, _ := os.Lstat(fifo)
	if info.Mode().IsRegular() {
		t.Fatal("test setup failure: FIFO is regular")
	}
}
