package audit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var ErrInvalidReport = errors.New("invalid or unsupported PHP2Shell report schema")

// ReadRegular only accepts regular, non-symlink files and enforces a hard size cap.
// It never executes a file, follows a URL, or reads a special device on purpose.
// Symlinks and Windows reparse/junction targets are rejected via Lstat (no follow).
func ReadRegular(path string, max int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	// Explicit symlink/reparse rejection before IsRegular (portable across GOOS).
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symbolic link or reparse point rejected: %s", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file or is a symbolic link: %s", path)
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("file exceeds %d-byte safety limit: %s", max, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || opened.Mode()&os.ModeSymlink != 0 || !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("file changed or became nonregular: %s", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("file exceeded read limit: %s", path)
	}
	return b, nil
}

func MakeReportDirectory(outPrefix string) error {
	dir := filepath.Dir(outPrefix)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("invalid output directory: %s", dir)
	}
	return nil
}
