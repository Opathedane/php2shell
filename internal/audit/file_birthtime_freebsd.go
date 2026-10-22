//go:build freebsd

package audit

import "syscall"

func birthTimespec(st *syscall.Stat_t) (sec int64, nsec int64) {
	return st.Birthtimespec.Sec, int64(st.Birthtimespec.Nsec)
}
