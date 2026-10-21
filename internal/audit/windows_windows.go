//go:build windows

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

func scanWindowsSpecific(r *Report) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		r.AddCheck("windows_processes", "UNAVAILABLE", err.Error())
	} else {
		defer syscall.CloseHandle(snap)
		entry := syscall.ProcessEntry32{Size: uint32(unsafe.Sizeof(syscall.ProcessEntry32{}))}
		count := 0
		if syscall.Process32First(snap, &entry) == nil {
			for {
				n := syscall.UTF16ToString(entry.ExeFile[:])
				low := strings.ToLower(n)
				if phpBin.MatchString(n) || low == "w3wp.exe" {
					if count < 256 {
						r.AddEvidence(Evidence{Type: "running_process", Name: n, Source: "Windows Toolhelp32 process snapshot", Location: fmt.Sprintf("PID=%d", entry.ProcessID), Interpretation: "PROCESS_NAME_ONLY_NOT_PROOF_OF_ACTIVE_PHP_OR_PATCH_STATE"})
					}
					count++
				}
				if syscall.Process32Next(snap, &entry) != nil {
					break
				}
			}
		}
		status := "PARTIAL"
		if count > 256 {
			status = "TRUNCATED"
		}
		r.AddCheck("windows_processes", status, fmt.Sprintf("Observed %d PHP/IIS process names, up to 256 recorded; w3wp may serve non-PHP applications", count))
	}
	scanIISConfig(r)
}
func scanIISConfig(r *Report) {
	windir := os.Getenv("SystemRoot")
	if windir == "" {
		windir = `C:\Windows`
	}
	path := filepath.Join(windir, "System32", "inetsrv", "config", "applicationHost.config")
	b, err := ReadRegular(path, 8<<20)
	if err != nil {
		r.AddCheck("windows_iis_configuration", "UNAVAILABLE", "IIS config not accessible or IIS absent (requires permission): "+err.Error())
		return
	}
	entries, e := parseIISHandlers(path, b)
	if e != nil {
		r.AddCheck("windows_iis_configuration", "INCOMPLETE", "Invalid IIS config XML: "+e.Error())
		return
	}
	for _, v := range entries {
		r.AddEvidence(v)
		exe := ResolveHandlerExecutablePath(HandlerExecutableFromDetail(v.Detail))
		if HandlerExecutableLooksLikePHP(exe) {
			AddBinaryVersionEvidence(r, exe, filepath.Base(exe), "IIS handler scriptProcessor static binary inspection")
		}
	}
	status := "PARTIAL"
	if len(entries) >= 128 {
		status = "TRUNCATED"
	}
	r.AddCheck("windows_iis_configuration", status, fmt.Sprintf("Read IIS applicationHost.config; found %d possibly PHP-related handler/FastCGI entries (up to 128); active PHP runtime, inherited overrides and patch state unverified", len(entries)))
}
