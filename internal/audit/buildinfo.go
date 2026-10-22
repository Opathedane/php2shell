package audit

// BuildFlavor identifies which release artifact this binary is.
// Set at link time via -ldflags "-X github.com/Opathedane/php2shell/internal/audit.BuildFlavor=legacy".
// Empty or "standard" = modern primary Windows/Linux/macOS builds (current Go toolchain).
// "legacy" = php2shell-windows-legacy-amd64.exe built with Go 1.20 for Windows Server 2012 R2.
var BuildFlavor = "standard"

// IsLegacyWindowsBuild reports whether this binary is the Server 2012 R2–compatible artifact.
func IsLegacyWindowsBuild() bool {
	return BuildFlavor == "legacy"
}

// BuildFlavorLabel returns a short display token for version/doctor output.
func BuildFlavorLabel() string {
	if IsLegacyWindowsBuild() {
		return "legacy"
	}
	return "standard"
}
