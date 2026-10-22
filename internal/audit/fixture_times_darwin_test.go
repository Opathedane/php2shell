//go:build darwin

package audit

import (
	"os"
	"syscall"
	"time"
	"unsafe"
)

// setattrlist attribute bitmap (sys/attr.h).
const (
	attrBitMapCount = 5
	attrCmnCrtime   = 0x00000200
)

type attrList struct {
	bitmapCount uint16
	reserved    uint16
	commonAttr  uint32
	volAttr     uint32
	dirAttr     uint32
	fileAttr    uint32
	forkAttr    uint32
}

// setFixtureFileTimes sets mtime/atime via Chtimes and birth via setattrlist.
func setFixtureFileTimes(path string, atime, mtime, birth time.Time) error {
	if err := os.Chtimes(path, atime, mtime); err != nil {
		return err
	}
	if birth.IsZero() {
		return nil
	}
	var attr attrList
	attr.bitmapCount = attrBitMapCount
	attr.commonAttr = attrCmnCrtime
	ts := syscall.Timespec{Sec: birth.Unix(), Nsec: int64(birth.Nanosecond())}
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETATTRLIST,
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(unsafe.Pointer(&attr)),
		uintptr(unsafe.Pointer(&ts)),
		unsafe.Sizeof(ts),
		0,
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
