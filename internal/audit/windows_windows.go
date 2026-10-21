//go:build windows

package audit

import (
	"fmt"
	"os"
	"path/filepath"
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
	b, err := ReadRegular(path, 8<<20)
	if err != nil {
		r.AddCheck("windows_iis_configuration", "UNAVAILABLE", "IIS config not accessible or IIS absent (requires permission): "+err.Error())
		return
	}
	ApplyIISApplicationHostInventory(r, path, b)
}
