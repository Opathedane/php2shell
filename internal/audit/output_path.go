package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"
)

// DefaultReportDir returns the preferred unattended report directory.
// Windows: C:\ProgramData\PHP2Shell\Reports
// Unix with HOME: $HOME/.php2shell/reports
// Unix without HOME (service accounts): /var/tmp/php2shell/reports
func DefaultReportDir() string {
	if runtime.GOOS == "windows" {
		if pd := strings.TrimSpace(os.Getenv("PROGRAMDATA")); pd != "" {
			return filepath.Join(pd, "PHP2Shell", "Reports")
		}
		return `C:\ProgramData\PHP2Shell\Reports`
	}
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		return filepath.Join(home, ".php2shell", "reports")
	}
	return "/var/tmp/php2shell/reports"
}

// SanitizeHostnameForFilename replaces characters unsafe in Windows/Unix filenames.
func SanitizeHostnameForFilename(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "unknown-host"
	}
	var b strings.Builder
	for _, r := range host {
		switch {
		case r < 32 || r == 127:
			b.WriteByte('-')
		case strings.ContainsRune(`<>:"/\|?*`, r):
			b.WriteByte('-')
		case unicode.IsSpace(r):
			b.WriteByte('-')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), ".-")
	if out == "" {
		return "unknown-host"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// UniqueReportPath builds php2shell-<host>-<UTC-timestamp>.html under dir.
// It does not create the file; callers must use exclusive create and refuse overwrite.
func UniqueReportPath(dir, hostname string, t time.Time) string {
	if t.IsZero() {
		t = time.Now().UTC()
	} else {
		t = t.UTC()
	}
	name := fmt.Sprintf("php2shell-%s-%s.html", SanitizeHostnameForFilename(hostname), t.Format("20060102T150405Z"))
	return filepath.Join(dir, name)
}

// ResolveScanReportPath chooses the HTML report path.
// --out (exact path or prefix) wins over --output-dir when set.
// A path ending in .html (case-insensitive) is used as-is; otherwise .html is appended.
func ResolveScanReportPath(outFlag, outputDir, hostname string, t time.Time) (string, error) {
	outFlag = strings.TrimSpace(outFlag)
	outputDir = strings.TrimSpace(outputDir)
	if outFlag != "" {
		p := outFlag
		if !strings.HasSuffix(strings.ToLower(p), ".html") {
			p = p + ".html"
		}
		if filepath.IsAbs(p) || filepath.VolumeName(p) != "" || strings.HasPrefix(p, `\\`) {
			return filepath.Clean(p), nil
		}
		return filepath.Clean(p), nil
	}
	dir := outputDir
	if dir == "" {
		dir = DefaultReportDir()
	}
	if dir == "" {
		return "", fmt.Errorf("empty output directory")
	}
	return UniqueReportPath(dir, hostname, t), nil
}
