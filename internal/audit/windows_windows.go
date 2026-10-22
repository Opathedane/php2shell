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
		var snapshot []windowsProc
		// Process32First seeds the cursor; Process32Next runs once per iteration
		// even when later filtering skips the entry (never continue past Next).
		for more := syscall.Process32First(snap, &entry) == nil; more; more = syscall.Process32Next(snap, &entry) == nil {
			snapshot = append(snapshot, windowsProc{
				PID:  entry.ProcessID,
				Name: syscall.UTF16ToString(entry.ExeFile[:]),
			})
		}
		recorded, count := selectWindowsPHPProcesses(snapshot, scannerSelfPID(), 256)
		for _, p := range recorded {
			r.AddEvidence(Evidence{Type: "running_process", Name: p.Name, Source: "Windows Toolhelp32 process snapshot", Location: fmt.Sprintf("PID=%d", p.PID), Interpretation: "PROCESS_NAME_ONLY_NOT_PROOF_OF_ACTIVE_PHP_OR_PATCH_STATE"})
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
	// Distinguish absent IIS (not an incomplete scan) from permission / I/O failures.
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			r.AddCheck("windows_iis_configuration", "NOT_APPLICABLE",
				"IIS applicationHost.config not present; IIS role appears absent — not an incomplete inventory")
			return
		}
		r.AddCheck("windows_iis_configuration", "ACCESS_DENIED",
			"Cannot stat IIS applicationHost.config (permission or I/O): "+err.Error())
		return
	}
	b, err := ReadRegular(path, 8<<20)
	if err != nil {
		low := strings.ToLower(err.Error())
		status := "UNAVAILABLE"
		if strings.Contains(low, "permission denied") || strings.Contains(low, "access is denied") {
			status = "ACCESS_DENIED"
		}
		r.AddCheck("windows_iis_configuration", status,
			"IIS config present but not readable: "+err.Error())
		return
	}
	ApplyIISApplicationHostInventory(r, path, b)
}
