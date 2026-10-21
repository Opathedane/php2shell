package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseIISSitesEDriveSomewebsite(t *testing.T) {
	path := moduleTestdataPath(t, "iis/applicationhost-edrive-site.xml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sites, err := parseIISSites(b)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range sites {
		if s.Name == "somewebsite" && strings.EqualFold(strings.ReplaceAll(s.PhysicalPath, `/`, `\`), `E:\websites\prod\somewebsite`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected E: somewebsite site, got %+v", sites)
	}
	handlers, err := parseIISHandlers(path, b)
	if err != nil || len(handlers) < 1 {
		t.Fatalf("handlers=%v err=%v", handlers, err)
	}
	exe := HandlerExecutableFromDetail(handlers[0].Detail)
	if !strings.Contains(strings.ToLower(exe), `e:\runtime\php\8.4.24`) {
		t.Fatalf("expected E: PHP handler, got %q", exe)
	}
	if !HandlerExecutableLooksLikePHP(exe) {
		t.Fatal(exe)
	}
}

func TestApplyIISInventoryRecordsSiteWithoutClaimingRuntime(t *testing.T) {
	path := moduleTestdataPath(t, "iis/applicationhost-edrive-site.xml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := NewReport("win", "windows", "amd64")
	ApplyIISApplicationHostInventory(r, path, b)
	sawSite, sawHandler := false, false
	for _, e := range r.Evidence {
		switch e.Type {
		case "iis_site_config":
			if e.Name == "somewebsite" && strings.Contains(e.Location, `E:\websites\prod\somewebsite`) {
				sawSite = true
			}
			if e.Interpretation != "CONFIGURED_SITE_PATH_NOT_PROOF_PHP_IS_SERVED_OR_ACTIVE_RUNTIME" {
				t.Fatal(e.Interpretation)
			}
		case "iis_php_handler_config":
			sawHandler = true
			if e.Interpretation != "CONFIGURED_HANDLER_NOT_VERIFIED_SERVING_RUNTIME" {
				t.Fatal(e.Interpretation)
			}
		}
	}
	if !sawSite || !sawHandler {
		t.Fatalf("site=%v handler=%v evidence=%+v", sawSite, sawHandler, r.Evidence)
	}
	for _, c := range r.Coverage {
		if c.Name == "windows_iis_configuration" && !strings.Contains(c.Detail, "--webroot") {
			t.Fatal(c.Detail)
		}
	}
}

func TestSiteWebConfigNonStandardRootAndPHP(t *testing.T) {
	root := t.TempDir()
	siteDir := filepath.Join(root, "websites", "prod", "somewebsite")
	phpDir := filepath.Join(root, "runtime", "PHP", "8.4.24", "nts", "x64")
	if err := os.MkdirAll(siteDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(phpDir, 0755); err != nil {
		t.Fatal(err)
	}
	phpCGI := filepath.Join(phpDir, "php-cgi.exe")
	if err := os.WriteFile(phpCGI, []byte("header PHP Version 8.4.24 footer"), 0644); err != nil {
		t.Fatal(err)
	}
	// web.config references the local php-cgi with a path ResolveConfiguredWindowsPath can use.
	webConfig := `<?xml version="1.0"?><configuration><system.webServer><handlers>` +
		`<add name="PHP_via_FastCGI" path="*.php" verb="*" modules="FastCgiModule" scriptProcessor="` + phpCGI + `"/>` +
		`</handlers></system.webServer></configuration>`
	if err := os.WriteFile(filepath.Join(siteDir, "web.config"), []byte(webConfig), 0644); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(siteDir, "index.php"), []byte("<?php echo 1;"), 0644)

	r := NewReport("win", "windows", "amd64")
	site := IISSite{Name: "somewebsite", PhysicalPath: siteDir}
	n, _, st := inspectSiteWebConfig(r, site)
	if st != "read" || n < 1 {
		t.Fatalf("status=%s n=%d", st, n)
	}
	sawInferredOrStatic := false
	for _, e := range r.Evidence {
		if e.Type == "binary_static_version" && e.Version == "8.4.24" {
			sawInferredOrStatic = true
		}
		if e.Type == "iis_php_handler_config" && strings.Contains(e.Detail, "site=somewebsite") {
			// ok
		}
	}
	if !sawInferredOrStatic {
		t.Fatalf("expected versioned PHP from handler path, evidence=%+v", r.Evidence)
	}
	// Site tree .php files are NOT auto-inventoried without --webroot.
	for _, e := range r.Evidence {
		if e.Type == "php_webroot_filename" {
			t.Fatal("must not walk site for .php without --webroot")
		}
	}
	scanWebRoot(r, siteDir)
	sawPHPFile := false
	for _, e := range r.Evidence {
		if e.Type == "php_webroot_filename" && e.Name == "index.php" {
			sawPHPFile = true
			if e.Interpretation != "FILE_PRESENT_NOT_PROOF_IT_IS_SERVED_OR_VULNERABLE" {
				t.Fatal(e.Interpretation)
			}
		}
	}
	if !sawPHPFile {
		t.Fatal("explicit --webroot should list .php filenames")
	}
	EvaluatePatchPosture(r)
	if r.VulnerabilityStatus != "BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED" {
		t.Fatal(r.VulnerabilityStatus)
	}
	rt, _ := humanRuntime(r)
	if rt == "Verified" {
		t.Fatal("must not claim verified active runtime")
	}
	if runtime.GOOS == "windows" {
		// Ensure E: style configured paths still look like PHP executables.
		if !HandlerExecutableLooksLikePHP(`E:\runtime\PHP\8.4.24\nts\x64\php-cgi.exe`) {
			t.Fatal("E: PHP path should look like PHP")
		}
	}
}

func TestConfiguredEDriveHandlerLooksLikePHP(t *testing.T) {
	exe := `E:\runtime\PHP\8.4.24\nts\x64\php-cgi.exe`
	if !HandlerExecutableLooksLikePHP(exe) {
		t.Fatal(exe)
	}
	if ConfiguredWindowsHandlerPath(exe) != exe {
		t.Fatal(ConfiguredWindowsHandlerPath(exe))
	}
}

func TestParseIISNestedAppsVDirsAndLocationHandlers(t *testing.T) {
	path := moduleTestdataPath(t, "iis/applicationhost-nested-edrive.xml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	maps, err := parseIISSiteMappings(b)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"somewebsite|/|/":        `E:\websites\prod\somewebsite`,
		"somewebsite|/|/assets":  `E:\websites\prod\somewebsite-assets`,
		"somewebsite|/api|/":     `E:\websites\prod\somewebsite-api`,
	}
	got := map[string]string{}
	for _, m := range maps {
		key := m.SiteName + "|" + m.AppPath + "|" + m.VDirPath
		got[key] = strings.ReplaceAll(m.PhysicalPath, `/`, `\`)
	}
	for k, phys := range want {
		if !strings.EqualFold(got[k], phys) {
			t.Fatalf("mapping %s: got %q want %q (all=%+v)", k, got[k], phys, maps)
		}
	}
	handlers, err := parseIISHandlers(path, b)
	if err != nil || len(handlers) < 1 {
		t.Fatalf("handlers=%v err=%v", handlers, err)
	}
	d := handlers[0].Detail
	if !strings.Contains(d, "site=somewebsite") || !strings.Contains(d, "location_path=somewebsite") {
		t.Fatalf("expected location site context: %s", d)
	}
	if strings.Contains(d, "display_errors") || strings.Contains(d, "password=") {
		t.Fatalf("args leaked: %s", d)
	}
	if !strings.Contains(d, "php_ini=") {
		t.Fatalf("expected php_ini path from -c: %s", d)
	}
}
