//go:build !windows

package audit

func scanWindowsSpecific(r *Report) {
	r.AddCheck("windows_iis_configuration", "NOT_APPLICABLE", "Only runs on Windows/IIS")
}
