package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func moduleRootDir(t testing.TB) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		if filepath.Dir(dir) == dir {
			t.Fatal("module root (go.mod) not found from ", wd)
		}
	}
}

func moduleTestdataPath(t testing.TB, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{moduleRootDir(t), "testdata"}, parts...)...)
}
