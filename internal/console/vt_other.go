//go:build !windows

package console

import "os"

func enableVirtualTerminal(_ *os.File) bool {
	return true
}
