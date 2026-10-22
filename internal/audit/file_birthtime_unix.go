//go:build unix && !windows

package audit

import (
	"os"
	"syscall"
	"time"
)

// fileBirthTimeUTC returns filesystem birth/creation time when the platform
// exposes it. Absence means creation evidence is unavailable — do not infer
// creation from ModTime.
func fileBirthTimeUTC(info os.FileInfo) (time.Time, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return time.Time{}, false
	}
	sec, nsec := birthTimespec(st)
	if sec <= 0 {
		return time.Time{}, false
	}
	return time.Unix(sec, nsec).UTC(), true
}
