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

// NormalizeHTMLReportPath maps operator --out values to an HTML path.
// .html/.htm kept; .csv remapped to .html; bare prefixes get .html appended.
func NormalizeHTMLReportPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return p
	}
	lower := strings.ToLower(p)
	switch {
	case strings.HasSuffix(lower, ".html"), strings.HasSuffix(lower, ".htm"):
		return p
	case strings.HasSuffix(lower, ".csv"):
		return p[:len(p)-len(".csv")] + ".html"
	default:
		return p + ".html"
	}
}

// MatchingCSVPath returns the CSV sibling for an HTML report path.
// report.html → report.csv; .csv inputs are normalized to .html first then remapped.
func MatchingCSVPath(htmlPath string) string {
	htmlPath = NormalizeHTMLReportPath(htmlPath)
	lower := strings.ToLower(htmlPath)
	if strings.HasSuffix(lower, ".html") {
		return htmlPath[:len(htmlPath)-len(".html")] + ".csv"
	}
	if strings.HasSuffix(lower, ".htm") {
		return htmlPath[:len(htmlPath)-len(".htm")] + ".csv"
	}
	return htmlPath + ".csv"
}

// ResolveScanReportPath chooses the HTML report path.
// --out (exact path or prefix) wins over --output-dir when set.
// .html/.htm kept; .csv remapped to .html; otherwise .html is appended.
// The matching CSV path is always MatchingCSVPath(html).
func ResolveScanReportPath(outFlag, outputDir, hostname string, t time.Time) (string, error) {
	outFlag = strings.TrimSpace(outFlag)
	outputDir = strings.TrimSpace(outputDir)
	if outFlag != "" {
		return filepath.Clean(NormalizeHTMLReportPath(outFlag)), nil
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

// ResolveScanReportPair returns HTML and matching CSV paths for one scan.
func ResolveScanReportPair(outFlag, outputDir, hostname string, t time.Time) (htmlPath, csvPath string, err error) {
	htmlPath, err = ResolveScanReportPath(outFlag, outputDir, hostname, t)
	if err != nil {
		return "", "", err
	}
	return htmlPath, MatchingCSVPath(htmlPath), nil
}
