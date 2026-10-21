package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindowsPHPIniSidecarDiscoveryAndHTMLCSV(t *testing.T) {
	root := t.TempDir()
	phpDir := filepath.Join(root, "Programs", "PHP", "8.4.24", "nts", "x64")
	if err := os.MkdirAll(phpDir, 0755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(phpDir, "php-cgi.exe")
	if err := os.WriteFile(bin, []byte("MZ PHP Version 8.4.24"), 0644); err != nil {
		t.Fatal(err)
	}
	ini := filepath.Join(phpDir, "php.ini")
	template := filepath.Join(phpDir, "php.ini-development")
	iniBody := "memory_limit = 128M\npost_max_size = 8M\nsession.upload_progress.enabled = On\npassword = s3cret-must-not-appear\n"
	if err := os.WriteFile(ini, []byte(iniBody), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(template, []byte("memory_limit = 256M\n"), 0644); err != nil {
		t.Fatal(err)
	}

	r := NewReport("win-ini", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 21, 0, 0, 0, time.UTC)
	AddBinaryVersionEvidence(r, bin, "php-cgi.exe", "test fixture")
	scanConfigs(r, HostScanOptions{}, nil)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	sawPrimary, sawTemplate, sawMemory, sawSecret := false, false, false, false
	for _, e := range r.Evidence {
		switch e.Type {
		case "php_ini_candidate":
			if e.Location == ini {
				sawPrimary = true
				if !strings.Contains(e.Detail, "related_binary=") {
					t.Fatalf("expected binary correlation: %s", e.Detail)
				}
				if e.Version != "" {
					t.Fatal("php.ini must not invent a PHP version")
				}
			}
			if e.Location == template {
				sawTemplate = true
				if e.Interpretation != "SAMPLE_OR_TEMPLATE_INI_NOT_PROOF_ACTIVE_OR_EFFECTIVE" {
					t.Fatal(e.Interpretation)
				}
			}
		case "configuration_observation":
			if e.Name == "memory_limit" && e.Location == ini {
				sawMemory = true
				if e.Interpretation != "OBSERVED_NOT_EFFECTIVE_SETTING_NOT_VERIFIED_MITIGATION" {
					t.Fatal(e.Interpretation)
				}
			}
			if strings.Contains(strings.ToLower(e.Name), "password") || strings.Contains(e.Detail, "s3cret") {
				sawSecret = true
			}
		}
	}
	if !sawPrimary || !sawTemplate || !sawMemory {
		t.Fatalf("primary=%v template=%v memory=%v evidence=%+v", sawPrimary, sawTemplate, sawMemory, r.Evidence)
	}
	if sawSecret {
		t.Fatal("secret leaked from php.ini")
	}
	if r.VulnerabilityStatus != "BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED" {
		t.Fatal(r.VulnerabilityStatus)
	}
	// Version must come from binary evidence, not ini.
	vers := false
	for _, a := range r.PatchAssessments {
		if a.ObservedVersion == "8.4.24" && a.EvidenceType != "configuration_observation" && a.EvidenceType != "php_ini_candidate" {
			vers = true
		}
	}
	if !vers {
		t.Fatal(r.PatchAssessments)
	}

	html := string(EncodeHTML(r))
	if !strings.Contains(html, "php.ini") || !strings.Contains(html, "memory_limit") {
		t.Fatal("HTML missing config findings")
	}
	if strings.Contains(html, "s3cret") {
		t.Fatal("HTML leaked secret")
	}
	fleet, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseFleetCSV(fleet)
	if err != nil || len(rows) < 1 {
		t.Fatal(err)
	}
	if rows[0].PHPVersion != "8.4.24" {
		t.Fatal(rows[0].PHPVersion)
	}
	if !strings.Contains(rows[0].LimitationsSummary, "PHP config candidates observed") {
		t.Fatal(rows[0].LimitationsSummary)
	}
	if rows[0].SchemaVersion != FleetCSVSchemaV2 {
		t.Fatal(rows[0].SchemaVersion)
	}
	if rows[0].ConfigCorrelatedToInstall != "YES" || rows[0].ConfigCandidateCount == "0" {
		t.Fatalf("structured config fields: %+v", rows[0])
	}
	if rows[0].ActiveHTTPRuntimeStatus == "VERIFIED" {
		t.Fatal("ini must not verify runtime")
	}
	cfgOK := false
	for _, c := range r.Coverage {
		if c.Name == "configuration" && c.Status != "NOT_SUPPORTED" {
			cfgOK = true
		}
	}
	if !cfgOK {
		t.Fatal(r.Coverage)
	}
}

func TestLinuxPHPIniWellKnownAndPHPRC(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc", "php", "8.3", "fpm")
	if err := os.MkdirAll(etc, 0755); err != nil {
		t.Fatal(err)
	}
	ini := filepath.Join(etc, "php.ini")
	if err := os.WriteFile(ini, []byte("expose_php = Off\nupload_max_filesize = 2M\n"), 0644); err != nil {
		t.Fatal(err)
	}
	prc := filepath.Join(root, "custom")
	_ = os.MkdirAll(prc, 0755)
	prcIni := filepath.Join(prc, "php.ini")
	if err := os.WriteFile(prcIni, []byte("memory_limit = 64M\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PHPRC", prc)

	// Point well-known patterns at the temp tree by invoking observe helpers directly.
	r := NewReport("linux-ini", "linux", "amd64")
	st := newPHPIniScanState()
	st.observePHPIniFile(r, ini, "test well-known", "primary_candidate", false)
	for _, c := range phpIniEnvCandidates() {
		st.observePHPIniFile(r, c.path, c.source, c.class, false)
	}

	sawPRC, sawExpose := false, false
	for _, e := range r.Evidence {
		if e.Type == "php_ini_candidate" && e.Location == prcIni {
			sawPRC = true
		}
		if e.Type == "configuration_observation" && e.Name == "expose_php" && e.Location == ini {
			sawExpose = true
		}
		if strings.Contains(e.Detail, "api_key") {
			t.Fatal(e.Detail)
		}
	}
	if !sawPRC || !sawExpose {
		t.Fatalf("prc=%v expose=%v evidence=%+v", sawPRC, sawExpose, r.Evidence)
	}
}

func TestExtractDashCIniPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`-c C:\PHP\php.ini`, `C:\PHP\php.ini`},
		{`-c "C:\Program Files\PHP\php.ini" -d display_errors=0`, `C:\Program Files\PHP\php.ini`},
		{`-d foo=1`, ``},
	}
	for _, tc := range cases {
		if got := ExtractDashCIniPath(tc.in); got != tc.want {
			t.Fatalf("ExtractDashCIniPath(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestClassifyPHPIniBasename(t *testing.T) {
	if classifyPHPIniBasename("php.ini") != "primary_candidate" {
		t.Fatal(classifyPHPIniBasename("php.ini"))
	}
	if classifyPHPIniBasename("php.ini-development") != "sample_or_template" {
		t.Fatal(classifyPHPIniBasename("php.ini-development"))
	}
	if classifyPHPIniBasename("opcache.ini") != "scan_dir_fragment" {
		t.Fatal(classifyPHPIniBasename("opcache.ini"))
	}
}

func TestIISDashCFeedsPHPIniCandidate(t *testing.T) {
	root := t.TempDir()
	phpDir := filepath.Join(root, "PHP", "8.4.24")
	site := filepath.Join(root, "www")
	_ = os.MkdirAll(phpDir, 0755)
	_ = os.MkdirAll(site, 0755)
	cgi := filepath.Join(phpDir, "php-cgi.exe")
	ini := filepath.Join(phpDir, "php.ini")
	_ = os.WriteFile(cgi, []byte("PHP Version 8.4.24"), 0644)
	_ = os.WriteFile(ini, []byte("memory_limit = 128M\n"), 0644)

	xml := `<?xml version="1.0"?><configuration><system.applicationHost><sites>` +
		`<site name="shop"><application path="/"><virtualDirectory path="/" physicalPath="` + site + `"/>` +
		`</application></site></sites></system.applicationHost>` +
		`<system.webServer><handlers><add name="PHP_via_FastCGI" path="*.php" verb="*" modules="FastCgiModule" ` +
		`scriptProcessor="` + cgi + `|-c ` + ini + `|-d password=nope"/></handlers></system.webServer></configuration>`

	r := NewReport("iis-ini", "windows", "amd64")
	ApplyIISApplicationHostInventory(r, filepath.Join(root, "applicationHost.config"), []byte(xml))
	scanConfigs(r, HostScanOptions{}, nil)

	sawIni := false
	for _, e := range r.Evidence {
		if e.Type == "php_ini_candidate" && normalizeInstallPath(e.Location) == normalizeInstallPath(ini) {
			sawIni = true
		}
		if strings.Contains(e.Detail, "nope") || strings.Contains(e.Detail, "password=") {
			t.Fatal(e.Detail)
		}
	}
	if !sawIni {
		t.Fatalf("expected php.ini from IIS -c: %+v", r.Evidence)
	}
}
