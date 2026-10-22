//go:build !unix && !windows

package audit

import (
	"os"
	"time"
)

func fileBirthTimeUTC(info os.FileInfo) (time.Time, bool) {
	_ = info
	return time.Time{}, false
}
