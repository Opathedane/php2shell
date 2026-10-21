package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScanRepositoryDistinguishesDeclaration(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM php:8.4-fpm\n"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{"require":{"php":"^8.3"}}`), 0600)
	_ = os.WriteFile(filepath.Join(dir, ".php-version"), []byte("8.2.34\n"), 0600)
	r := NewReport("host", "linux", "amd64")
	ScanRepository(r, dir)
	if len(r.Evidence) != 3 {
		t.Fatalf("wanted 3 declaration findings, got %+v", r.Evidence)
	}
	for _, e := range r.Evidence {
		if e.Interpretation != "DECLARED_ONLY_NOT_DEPLOYED_OR_PATCH_VERIFIED" {
			t.Fatalf("unsafe conclusion: %v", e)
		}
	}
}
func TestRepoIgnoresSymlinksAndSpecialFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires special permissions on Windows")
	}
	dir := t.TempDir()
	_ = os.Symlink("/dev/zero", filepath.Join(dir, "Dockerfile"))
	r := NewReport("host", "linux", "amd64")
	ScanRepository(r, dir)
	if len(r.Evidence) != 0 {
		t.Fatalf("followed symlink: %v", r.Evidence)
	}
	if r.Repositories[0].SkippedFiles == 0 {
		t.Fatal("did not record skipped symlink")
	}
}
func TestReadRegularRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permissions")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	_ = os.WriteFile(target, []byte("abc"), 0600)
	link := filepath.Join(dir, "link")
	_ = os.Symlink(target, link)
	if _, err := ReadRegular(link, 32); err == nil {
		t.Fatal("symlink was accepted")
	}
}
func TestCSVFormulaSanitization(t *testing.T) {
	for _, value := range []string{"=1+2", " +2", "-SUM(1)", "@SUM(1)", "\t=cmd", "\r=cmd", "\n=cmd"} {
		got := SpreadsheetSafe(value)
		if !strings.HasPrefix(got, "'") {
			t.Fatalf("unsanitized CSV value %q: %q", value, got)
		}
	}
	if got := SpreadsheetSafe("ordinary"); got != "ordinary" {
		t.Fatal(got)
	}
}
func TestHTMLEscaping(t *testing.T) {
	r := NewReport("<script>alert(1)</script>", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "test", Name: `<img src=x onerror=alert(1)>`})
	s := string(EncodeHTML(r))
	if strings.Contains(s, "<script>alert") || strings.Contains(s, "<img src=x") {
		t.Fatal("unescaped HTML value")
	}
	if !strings.Contains(s, "&lt;img") {
		t.Fatal("expected escaped HTML")
	}
}
func TestSaveNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "assessment.html")
	r := NewReport("host", "linux", "amd64")
	if err := Save(r, path); err != nil {
		t.Fatal(err)
	}
	if err := Save(r, path); err == nil {
		t.Fatal("should never overwrite output")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	for _, e := range []string{".json", ".csv"} {
		if _, err := os.Stat(filepath.Join(dir, "assessment"+e)); !os.IsNotExist(err) {
			t.Fatalf("unexpected sidecar file assessment%s: %v", e, err)
		}
	}
}
func TestSaveHTMLOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "only.html")
	r := NewReport("host", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "test", Name: "php", Version: "8.4.1", Source: "unit", Interpretation: "TEST"})
	if err := Save(r, path); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "only.html" {
		t.Fatalf("expected single HTML file, got %+v", entries)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "PHP2Shell") || !strings.Contains(s, "Scan coverage and limitations") {
		t.Fatal("HTML missing expected sections")
	}
}
func TestSaveRefusesDestinationSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires permissions on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	_ = os.WriteFile(target, []byte("unchanged"), 0600)
	path := filepath.Join(dir, "assessment.html")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := Save(NewReport("host", "linux", "amd64"), path); err == nil {
		t.Fatal("symlink was overwritten")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "unchanged" {
		t.Fatal("target was modified")
	}
}
func TestAccessLogOnlySummarizes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	data := `192.0.2.10 - - [21/Oct/2026:12:23:51 +0000] "POST /upload.php?secret=private HTTP/1.1" 200 23` + "\n"
	_ = os.WriteFile(path, []byte(data), 0600)
	r := NewReport("host", "linux", "amd64")
	ScanAccessLog(r, path)
	if len(r.Logs) != 1 || r.Logs[0].ParsedRequests != 1 {
		t.Fatalf("missing log statistics: %+v", r.Logs)
	}
	if r.CompromiseStatus != "NOT_ASSESSED" {
		t.Fatal("falsely cleared compromise")
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "secret=private") || strings.Contains(string(b), "192.0.2.10") {
		t.Fatal("raw access log data leaked into output")
	}
	if r.Logs[0].FirstTimestamp != "2026-10-21T12:23:51Z" {
		t.Fatalf("invalid log timestamp: %s", r.Logs[0].FirstTimestamp)
	}
}
func TestOversizedLogReportedUnavailable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.log")
	f, _ := os.Create(path)
	_ = f.Truncate(33 << 20)
	_ = f.Close()
	r := NewReport("host", "linux", "amd64")
	ScanAccessLog(r, path)
	if r.Logs[0].Status != "UNAVAILABLE" || r.CompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("incorrect classification: %+v", r.Logs[0])
	}
}
func TestRollupRequiresExplicitTenantMapping(t *testing.T) {
	dir := t.TempDir()
	r := NewReport("user-provided", "linux", "amd64")
	r.CustomerLabel = "Tenant A claims"
	raw, _ := json.Marshal(r)
	p := filepath.Join(dir, "report.json")
	_ = os.WriteFile(p, raw, 0600)
	output := filepath.Join(dir, "rollup.csv")
	if err := Rollup([]string{p}, "", output); err != nil {
		t.Fatal(err)
	}
	csv, _ := os.ReadFile(output)
	if !strings.Contains(string(csv), "UNMAPPED") || strings.Contains(string(csv), "Tenant A claims") {
		t.Fatalf("tenant claim trusted: %s", csv)
	}
	digest := sha256.Sum256(raw)
	m := map[string]string{hex.EncodeToString(digest[:]): "Verified tenant"}
	b, _ := json.Marshal(m)
	mfile := filepath.Join(dir, "map.json")
	_ = os.WriteFile(mfile, b, 0600)
	if err := Rollup([]string{p}, mfile, filepath.Join(dir, "rollup2.csv")); err != nil {
		t.Fatal(err)
	}
}
func TestWrongSchemaRejected(t *testing.T) {
	if _, err := ParseReport([]byte(`{"schema":"evil"}`)); err == nil {
		t.Fatal("bad schema accepted")
	}
}
