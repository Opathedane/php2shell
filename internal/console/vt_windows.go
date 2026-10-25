//go:build windows

package console

import (
	"os"
	"syscall"
	"unsafe"
)

// enableVirtualTerminal turns on ENABLE_VIRTUAL_TERMINAL_PROCESSING for a console
// handle. Best-effort: fails safely on hosts without VT (e.g. Server 2012 R2),
// so callers should fall back to plain text.
func enableVirtualTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	const enableVirtualTerminalProcessing = 0x0004
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	var mode uint32
	r1, _, _ := getConsoleMode.Call(f.Fd(), uintptr(unsafe.Pointer(&mode)))
	if r1 == 0 {
		return false
	}
	mode |= enableVirtualTerminalProcessing
	r1, _, _ = setConsoleMode.Call(f.Fd(), uintptr(mode))
	return r1 != 0
}
