package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEncodeFleetCSVFormulaAndBOM(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php", Version: "8.4.24", Source: "test", Location: "/usr/bin/php", Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION"})
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	data, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 3 || data[0] != 0xEF || data[1] != 0xBB || data[2] != 0xBF {
		t.Fatal("expected UTF-8 BOM")
	}
	rows, err := ParseFleetCSV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].PHPVersion != "8.4.24" || rows[0].UpstreamMinimumFixed != "8.4.27" {
		t.Fatalf("%+v", rows)
	}
	if rows[0].VersionEvidence != "verified_binary_metadata" {
		t.Fatal(rows[0].VersionEvidence)
	}
	if rows[0].ActiveHTTPRuntimeStatus != "NOT_VERIFIED" {
		t.Fatal(rows[0].ActiveHTTPRuntimeStatus)
	}
}

func TestFleetCSVFormulaInjection(t *testing.T) {
	r := NewReport("=cmd", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "+evil", Version: "8.4.24", Source: "test", Location: "/tmp/=x", Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION"})
	EvaluatePatchPosture(r)
	data, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if strings.Contains(s, "\n=cmd,") || strings.Contains(s, ",+evil,") {
		t.Fatalf("unsanitized formula risk: %s", s)
	}
	if !strings.Contains(s, "'=cmd") && !strings.Contains(s, "\"'=cmd") {
		// SpreadsheetSafe prefixes; CSV may quote
		if !strings.Contains(s, SpreadsheetSafe("=cmd")) {
			t.Fatal(s)
		}
	}
}

func TestFleetHostRowWhenNoPHP(t *testing.T) {
	r := NewReport("empty", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	rows := BuildFleetRows(r)
	if len(rows) != 1 || rows[0].VersionEvidence != "php_not_observed_in_scope" {
		t.Fatalf("%+v", rows)
	}
	if rows[0].InstallID != "host:no_comparable_install" {
		t.Fatal(rows[0].InstallID)
	}
}

func TestFleetUnknownVersionPath(t *testing.T) {
	r := NewReport("win", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	r.AddEvidence(Evidence{Type: "binary_path", Name: "php.exe", Source: "test", Location: `C:\PHP\php.exe`, Detail: "no version marker found", Interpretation: "PRESENT_VERSION_UNKNOWN_NOT_RUNTIME_VERIFIED"})
	EvaluatePatchPosture(r)
	rows := BuildFleetRows(r)
	if len(rows) != 1 || rows[0].VersionEvidence != "version_unknown" {
		t.Fatalf("%+v", rows)
	}
}

func TestFleetMultipleInstallsSameVersion(t *testing.T) {
	r := NewReport("web", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php-fpm", Version: "8.3.24", Source: "t", Location: "/opt/a/sbin/php-fpm", Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION"})
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php-fpm", Version: "8.3.24", Source: "t", Location: "/opt/b/sbin/php-fpm", Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION"})
	EvaluatePatchPosture(r)
	rows := BuildFleetRows(r)
	if len(rows) != 2 {
		t.Fatalf("got %d rows %+v", len(rows), rows)
	}
	if rows[0].InstallID == rows[1].InstallID {
		t.Fatal("install ids must differ")
	}
}

func TestFleetPathInferredConsistencyHTMLCSV(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "Programs", "PHP", "8.4.24", "nts", "x64", "php.exe")
	_ = os.MkdirAll(filepath.Dir(bin), 0755)
	_ = os.WriteFile(bin, []byte("MZ\x00\x00 no-marker"), 0644)
	r := NewReport("TestVM", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 17, 16, 12, 0, time.UTC)
	AddBinaryVersionEvidence(r, bin, "php.exe", "Windows LocalAppData Programs\\PHP static binary inspection")
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	html := string(EncodeHTML(r))
	csvData, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseFleetCSV(csvData)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].PHPVersion != "8.4.24" || rows[0].UpstreamMinimumFixed != "8.4.27" {
		t.Fatalf("%+v", rows)
	}
	if rows[0].VersionEvidence != "path_inferred" || rows[0].VersionConfidence != "MEDIUM" {
		t.Fatalf("%+v", rows[0])
	}
	if !strings.Contains(html, "8.4.24") || !strings.Contains(html, "8.4.27") {
		t.Fatal("HTML inconsistent with CSV")
	}
	if r.VulnerabilityStatus != "BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED" {
		t.Fatal(r.VulnerabilityStatus)
	}
}

func TestSaveReportPairAndOverwrite(t *testing.T) {
	dir := t.TempDir()
	r := NewReport("pair", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	html := filepath.Join(dir, "php2shell-pair-20261021T120000Z.html")
	csv := MatchingCSVPath(html)
	if err := SaveReportPair(r, html, csv); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(html); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(csv); err != nil {
		t.Fatal(err)
	}
	if err := SaveReportPair(r, html, csv); err == nil {
		t.Fatal("expected overwrite refusal")
	}
}

func TestMatchingCSVPath(t *testing.T) {
	if MatchingCSVPath(`C:\x\report.html`) != `C:\x\report.csv` {
		t.Fatal(MatchingCSVPath(`C:\x\report.html`))
	}
	html, csv, err := ResolveScanReportPair("out/custom", "", "host", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(html, "custom.html") || !strings.HasSuffix(csv, "custom.csv") {
		t.Fatalf("%s %s", html, csv)
	}
}

func TestRollupFleetCSVThreeServers(t *testing.T) {
	dir := t.TempDir()
	mk := func(host, ver, status string) string {
		r := NewReport(host, "linux", "amd64")
		r.GeneratedUTC = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
		r.CustomerLabel = "Acme"
		if ver != "" {
			r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php", Version: ver, Source: "t", Location: "/usr/bin/php", Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION"})
		}
		EvaluatePatchPosture(r)
		FinalizeSummary(r)
		p := filepath.Join(dir, host+".csv")
		b, err := EncodeFleetCSV(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mk("srv-win", "8.4.24", "below")
	mk("srv-linux", "8.4.27", "ok")
	mk("srv-empty", "", "none")

	out := filepath.Join(dir, "customer-summary.csv")
	if err := RollupFleetCSV(FleetRollupOptions{InputDir: dir, Output: out}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	rows, err := ParseFleetCSV(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows", len(rows))
	}
	hosts := map[string]bool{}
	for _, row := range rows {
		hosts[row.Hostname] = true
		if row.CustomerLabel != "Acme" {
			t.Fatal(row.CustomerLabel)
		}
	}
	if !hosts["srv-win"] || !hosts["srv-linux"] || !hosts["srv-empty"] {
		t.Fatalf("%v", hosts)
	}
}

func TestRollupRejectsMixedCustomers(t *testing.T) {
	dir := t.TempDir()
	write := func(host, label string) {
		r := NewReport(host, "linux", "amd64")
		r.GeneratedUTC = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
		r.CustomerLabel = label
		EvaluatePatchPosture(r)
		b, _ := EncodeFleetCSV(r)
		_ = os.WriteFile(filepath.Join(dir, host+".csv"), b, 0600)
	}
	write("a", "CustomerA")
	write("b", "CustomerB")
	err := RollupFleetCSV(FleetRollupOptions{InputDir: dir, Output: filepath.Join(dir, "out.csv")})
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("expected customer conflict, got %v", err)
	}
}

func TestRollupMalformedSchema(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.csv")
	_ = os.WriteFile(p, []byte("foo,bar\n1,2\n"), 0600)
	err := RollupFleetCSV(FleetRollupOptions{InputFiles: []string{p}, Output: filepath.Join(dir, "out.csv")})
	if err == nil {
		t.Fatal("expected schema error")
	}
}

func TestUnicodeHostnameFleetCSV(t *testing.T) {
	r := NewReport("srv-æøå", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	EvaluatePatchPosture(r)
	data, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseFleetCSV(data)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Hostname != "srv-æøå" {
		t.Fatal(rows[0].Hostname)
	}
}
