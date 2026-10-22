package audit

import (
	"fmt"
	"runtime"
)

// WindowsHostInfo is a best-effort OS version snapshot used for compatibility gates.
type WindowsHostInfo struct {
	Major, Minor, Build uint32
	ProductName         string // optional; may be empty
	Source              string // e.g. RtlGetVersion
}

// ModernWindowsMinMajor is the minimum major version for Go 1.21+ runtimes
// (Windows 10 / Windows Server 2016 = 10.0).
const ModernWindowsMinMajor = 10

// LegacyWindowsMin describes the oldest Windows the legacy Go 1.20 binary targets.
// Server 2012 = 6.2; Server 2012 R2 = 6.3. Go 1.20 also supported Win7 (6.1);
// we document Server 2012 R2 as the engagement target.
const (
	LegacyWindowsMinMajor = 6
	LegacyWindowsMinMinor = 2 // Server 2012 / Windows 8 floor for this product's legacy artifact
)

// EvaluateWindowsCompatibility decides whether this binary may run on the host.
// Returns (ok, actionable stderr message). Non-Windows hosts always pass.
func EvaluateWindowsCompatibility(goos string, flavor string, info *WindowsHostInfo, infoErr error) (bool, string) {
	if goos != "windows" {
		return true, ""
	}
	legacy := flavor == "legacy"

	if infoErr != nil || info == nil {
		// Fail open only for legacy (better chance on old hosts); fail closed for modern
		// so operators do not silently run an incompatible Go 1.21+ binary.
		if legacy {
			return true, ""
		}
		return false, fmt.Sprintf(
			"ERROR: cannot determine Windows version (%v).\n"+
				"The standard Windows build requires Windows 10 / Windows Server 2016 or newer (Go 1.21+ runtime).\n"+
				"On Windows Server 2012 R2 x64, use php2shell-windows-legacy-amd64.exe from the same release.\n"+
				"See docs/WINDOWS-LEGACY-2012R2.md.",
			infoErr,
		)
	}

	if !legacy {
		if info.Major < ModernWindowsMinMajor {
			return false, fmt.Sprintf(
				"ERROR: this standard PHP2Shell build cannot run on Windows %d.%d (build %d).\n"+
					"Go 1.21+ requires Windows 10 or Windows Server 2016 or newer.\n"+
					"On Windows Server 2012 R2 x64, download and run php2shell-windows-legacy-amd64.exe\n"+
					"(same release; built with Go 1.20). For PSAppDeployToolkit, point Deploy-Application.ps1\n"+
					"at the legacy executable on 2012 R2 hosts.\n"+
					"See docs/WINDOWS-LEGACY-2012R2.md.",
				info.Major, info.Minor, info.Build,
			)
		}
		return true, ""
	}

	// Legacy artifact: reject hosts older than Server 2012 so we do not imply Win7 support.
	if info.Major < LegacyWindowsMinMajor ||
		(info.Major == LegacyWindowsMinMajor && info.Minor < LegacyWindowsMinMinor) {
		return false, fmt.Sprintf(
			"ERROR: the legacy PHP2Shell build targets Windows Server 2012 / 2012 R2 or newer;\n"+
				"this host reports Windows %d.%d (build %d), which is below that floor.\n"+
				"See docs/WINDOWS-LEGACY-2012R2.md.",
			info.Major, info.Minor, info.Build,
		)
	}
	return true, ""
}

// WindowsCompatAdvisory returns a non-fatal doctor/scan note when the legacy
// binary runs on a modern host (operators should prefer the standard build).
func WindowsCompatAdvisory(goos string, flavor string, info *WindowsHostInfo) string {
	if goos != "windows" || flavor != "legacy" || info == nil {
		return ""
	}
	if info.Major >= ModernWindowsMinMajor {
		return "NOTE: legacy Windows build running on Windows 10 / Server 2016+. Prefer php2shell-windows-amd64.exe on modern hosts (current Go toolchain, supported security baseline)."
	}
	return ""
}

// CheckHostCompatibility is the process entry gate (Windows OS version vs build flavor).
func CheckHostCompatibility() (ok bool, message string) {
	if runtime.GOOS != "windows" {
		return true, ""
	}
	info, err := ReadWindowsHostInfo()
	return EvaluateWindowsCompatibility(runtime.GOOS, BuildFlavor, info, err)
}
