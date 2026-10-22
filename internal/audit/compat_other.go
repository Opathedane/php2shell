//go:build !windows

package audit

import "fmt"

// ReadWindowsHostInfo is only meaningful on Windows.
func ReadWindowsHostInfo() (*WindowsHostInfo, error) {
	return nil, fmt.Errorf("not windows")
}
