//go:build windows

package audit

import (
	"os"
	"syscall"
	"time"
)

func fileBirthTimeUTC(info os.FileInfo) (time.Time, bool) {
	st, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || st == nil {
		return time.Time{}, false
	}
	return time.Unix(0, st.CreationTime.Nanoseconds()).UTC(), true
}
