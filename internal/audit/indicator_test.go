package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Opathedane/php2shell/internal/rules"
)

func TestApacheLogSignedLiteralMatchNoSensitiveData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	os.WriteFile(path, []byte(`198.51.100.10 - - [21/Oct/2026:11:05:09 +0000] "GET /php.php?token=private123&marker=TEST-MARKER HTTP/1.1" 403 22`+"\n"), 0600)
	r := NewReport("host", "linux", "amd64")
	indicator := rules.Indicator{ID: "test.marker", Type: "http_target_literal", Value: "test-marker", Severity: "medium", Confidence: "suspected", Source: "https://example.org/test"}
	ScanAccessLogWithIndicators(r, path, []rules.Indicator{indicator})
	if len(r.Findings) != 1 || r.Logs[0].MatchedRules != 1 {
		t.Fatalf("expected single indicator match: %+v %+v", r.Findings, r.Logs)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "private123") || strings.Contains(string(b), "198.51.100.10") {
		t.Fatal("raw log or private query leaked")
	}
}
func TestIISW3CFieldsAndTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "u_ex.log")
	data := "#Software: Microsoft Internet Information Services 10.0\n#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port c-ip sc-status\n2026-10-21 12:00:01 10.1.1.1 POST /index.php token=private&marker=test-marker 443 10.2.2.2 500\n"
	os.WriteFile(path, []byte(data), 0600)
	r := NewReport("server", "windows", "amd64")
	ScanAccessLogWithIndicators(r, path, []rules.Indicator{{ID: "test.marker", Type: "http_target_literal", Value: "test-marker", Severity: "medium", Confidence: "suspected", Source: "https://example.org/test"}})
	if r.Logs[0].FirstTimestamp != "2026-10-21T12:00:01Z" || r.Logs[0].ParsedRequests != 1 || len(r.Findings) != 1 {
		t.Fatalf("bad IIS W3C coverage: %+v %+v", r.Logs, r.Findings)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "private") || strings.Contains(string(b), "10.2.2.2") {
		t.Fatal("sensitive log fields retained")
	}
}
func TestFileSHA256MatchWithoutExecutingFiles(t *testing.T) {
	dir := t.TempDir()
	contents := []byte("benign synthetic fixture")
	os.WriteFile(filepath.Join(dir, "file.php"), contents, 0600)
	h := sha256.Sum256(contents)
	r := NewReport("host", "linux", "amd64")
	ScanFileHashes(r, dir, []rules.Indicator{{ID: "test.hash", Type: "file_sha256", Value: hex.EncodeToString(h[:]), Severity: "high", Confidence: "suspected", Source: "https://example.org/test"}})
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "test.hash" {
		t.Fatalf("hash not found: %+v", r.Findings)
	}
}
func TestIISConfigExtractionDoesNotClaimActiveRuntime(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><configuration><system.webServer><handlers><add name="PHP_via_FastCGI" path="*.php" verb="*" modules="FastCgiModule" scriptProcessor="C:\PHP\php-cgi.exe"/></handlers><fastCgi><application fullPath="C:\PHP\php-cgi.exe"/></fastCgi></system.webServer></configuration>`)
	entries, err := parseIISHandlers(`C:\Windows\System32\inetsrv\config\applicationHost.config`, data)
	if err != nil || len(entries) != 2 {
		t.Fatalf("invalid config extraction %v %+v", err, entries)
	}
	for _, e := range entries {
		if e.Interpretation != "CONFIGURED_HANDLER_NOT_VERIFIED_SERVING_RUNTIME" {
			t.Fatal("unsafe IIS verdict")
		}
	}
}
