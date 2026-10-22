//go:build windows

package audit

import (
	"fmt"
	"syscall"
	"unsafe"
)

// RTL_OSVERSIONINFOW layout (subset) for ntdll.RtlGetVersion.
type rtlOSVersionInfoW struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformID        uint32
	CSDVersion        [128]uint16
}

var (
	modNtdll          = syscall.NewLazyDLL("ntdll.dll")
	procRtlGetVersion = modNtdll.NewProc("RtlGetVersion")
)

// ReadWindowsHostInfo returns the host OS version via ntdll.RtlGetVersion (manifest-honest).
func ReadWindowsHostInfo() (*WindowsHostInfo, error) {
	var info rtlOSVersionInfoW
	info.OSVersionInfoSize = uint32(unsafe.Sizeof(info))
	r0, _, e1 := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&info)))
	if r0 != 0 {
		if e1 != syscall.Errno(0) {
			return nil, fmt.Errorf("RtlGetVersion: %w", e1)
		}
		return nil, fmt.Errorf("RtlGetVersion status 0x%x", r0)
	}
	return &WindowsHostInfo{
		Major:  info.MajorVersion,
		Minor:  info.MinorVersion,
		Build:  info.BuildNumber,
		Source: "RtlGetVersion",
	}, nil
}
