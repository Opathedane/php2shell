//go:build windows

package audit

import (
	"syscall"
	"time"
)

// setFixtureFileTimes sets creation (birth), access, and modification times.
// os.Chtimes alone cannot change Windows creation time.
func setFixtureFileTimes(path string, atime, mtime, birth time.Time) error {
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(pathp, syscall.FILE_WRITE_ATTRIBUTES,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)

	toFT := func(t time.Time) *syscall.Filetime {
		if t.IsZero() {
			return nil
		}
		ft := syscall.NsecToFiletime(t.UTC().UnixNano())
		return &ft
	}
	return syscall.SetFileTime(h, toFT(birth), toFT(atime), toFT(mtime))
}
