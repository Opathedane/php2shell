//go:build linux

package audit

import "syscall"

// Classic Linux stat(2) does not expose reliable birth/creation time.
// Do not substitute Ctim/Mtim — those are not creation evidence.
func birthTimespec(st *syscall.Stat_t) (sec int64, nsec int64) {
	_ = st
	return 0, 0
}
