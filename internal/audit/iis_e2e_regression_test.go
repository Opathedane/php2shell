package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2EIISSomewebsiteEDrivePHP8424Pipeline is the release-gate regression for:
//   website  E:\websites\prod\somewebsite  (simulated via temp dirs + config paths)
//   PHP      E:\PHP\8.4.24\php-cgi.exe       (local fixture with path/version evidence)
//   FastCGI  configured with scriptProcessor arguments
// Expect: 8.4.24 below 8.4.27, HTML+CSV consistent, active runtime unverified,
// no secrets from handler args, no .php walk without --webroot.
func TestE2EIISSomewebsiteEDrivePHP8424Pipeline(t *testing.T) {
	root := t.TempDir()
	siteDir := filepath.Join(root, "websites", "prod", "somewebsite")
	apiDir := filepath.Join(root, "websites", "prod", "somewebsite-api")
	phpDir := filepath.Join(root, "PHP", "8.4.24")
	for _, d := range []string{siteDir, apiDir, phpDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	phpCGI := filepath.Join(phpDir, "php-cgi.exe")
	// Marker-free binary; version comes from path segment 8.4.24 (path_inferred).
	if err := os.WriteFile(phpCGI, []byte("MZ\x00\x00 iis-e2e-fixture-no-embedded-version"), 0644); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(siteDir, "index.php"), []byte("<?php echo 1;"), 0644)
	_ = os.WriteFile(filepath.Join(siteDir, "web.config"), []byte(
		`<?xml version="1.0"?><configuration><system.webServer><handlers>`+
			`<add name="PHP_local" path="*.php" verb="*" modules="FastCgiModule" scriptProcessor="`+phpCGI+`|-d secret=should-not-appear"/>`+
			`</handlers></system.webServer></configuration>`,
	), 0644)

	// applicationHost-style inventory using resolvable physical paths + E:-style handler spelling in parallel fixture.
	hostXML := `<?xml version="1.0"?><configuration><system.applicationHost><sites>` +
		`<site name="somewebsite"><application path="/"><virtualDirectory path="/" physicalPath="` + siteDir + `"/>` +
		`<virtualDirectory path="/assets" physicalPath="` + siteDir + `-assets"/></application>` +
		`<application path="/api"><virtualDirectory path="/" physicalPath="` + apiDir + `"/></application>` +
		`</site></sites></system.applicationHost>` +
		`<system.webServer><fastCgi><application fullPath="` + phpCGI + `"/></fastCgi>` +
		`<handlers><add name="PHP_via_FastCGI" path="*.php" verb="*" modules="FastCgiModule" ` +
		`scriptProcessor="` + phpCGI + `|-c ` + filepath.Join(phpDir, "php.ini") + `|-d password=s3cret"/></handlers>` +
		`</system.webServer></configuration>`

	r := NewReport("iis-e2e", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 20, 0, 0, 0, time.UTC)
	ApplyIISApplicationHostInventory(r, filepath.Join(root, "applicationHost.config"), []byte(hostXML))

	// Also assert literal E: config parsing (config-only; binary may be inaccessible off Windows).
	edrive := moduleTestdataPath(t, "iis/applicationhost-nested-edrive.xml")
	eb, err := os.ReadFile(edrive)
	if err != nil {
		t.Fatal(err)
	}
	maps, err := parseIISSiteMappings(eb)
	if err != nil {
		t.Fatal(err)
	}
	var sawRoot, sawAPI, sawAssets bool
	for _, m := range maps {
		switch {
		case m.SiteName == "somewebsite" && m.AppPath == "/" && m.VDirPath == "/" &&
			strings.EqualFold(strings.ReplaceAll(m.PhysicalPath, `/`, `\`), `E:\websites\prod\somewebsite`):
			sawRoot = true
		case m.SiteName == "somewebsite" && m.AppPath == "/api":
			sawAPI = true
		case m.VDirPath == "/assets":
			sawAssets = true
		}
	}
	if !sawRoot || !sawAPI || !sawAssets {
		t.Fatalf("nested mappings incomplete: root=%v api=%v assets=%v maps=%+v", sawRoot, sawAPI, sawAssets, maps)
	}
	h, err := parseIISHandlers(edrive, eb)
	if err != nil || len(h) == 0 {
		t.Fatal(err)
	}
	detail := h[0].Detail
	if strings.Contains(detail, "password") || strings.Contains(strings.ToLower(detail), "s3cret") || strings.Contains(detail, "display_errors") {
		t.Fatalf("secrets leaked in handler detail: %s", detail)
	}
	if !strings.Contains(detail, "handler_args=redacted") {
		t.Fatalf("expected redacted args flag: %s", detail)
	}
	// Path-only php_ini= is allowed; full -c argument strings are not.
	if !strings.Contains(detail, "php_ini=") {
		t.Fatalf("expected php_ini path extraction from -c: %s", detail)
	}
	if got := HandlerExecutableFromDetail(detail); !strings.EqualFold(got, `E:\PHP\8.4.24\php-cgi.exe`) {
		t.Fatalf("handler exe %q", got)
	}

	// Live inventory assertions (resolvable paths).
	sawSite, sawHandler, sawVersion := false, false, false
	for _, e := range r.Evidence {
		switch e.Type {
		case "iis_site_config":
			if strings.Contains(e.Location, "somewebsite") {
				sawSite = true
			}
		case "iis_php_handler_config":
			sawHandler = true
			if strings.Contains(e.Detail, "s3cret") || strings.Contains(e.Detail, "should-not-appear") {
				t.Fatalf("secret in evidence: %s", e.Detail)
			}
		case "binary_path_inferred_version", "binary_static_version":
			if e.Version == "8.4.24" {
				sawVersion = true
			}
		case "php_webroot_filename":
			t.Fatal("must not enumerate .php without --webroot")
		}
	}
	if !sawSite || !sawHandler || !sawVersion {
		t.Fatalf("site=%v handler=%v version=%v evidence=%+v", sawSite, sawHandler, sawVersion, r.Evidence)
	}

	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	if r.VulnerabilityStatus != "BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED" {
		t.Fatal(r.VulnerabilityStatus)
	}
	rt, _ := humanRuntime(r)
	if rt == "Verified" {
		t.Fatal("active serving runtime must remain unverified")
	}

	groups := GroupInstallations(r)
	if len(groups) < 1 || groups[0].Version != "8.4.24" || groups[0].MinimumFixed != "8.4.27" {
		t.Fatalf("groups %+v", groups)
	}
	sawRelatedHandler, sawRelatedSite := false, false
	for _, e := range groups[0].RelatedEvidence {
		switch e.Type {
		case "iis_php_handler_config":
			sawRelatedHandler = true
		case "iis_site_config":
			if strings.Contains(strings.ToLower(e.Name), "somewebsite") {
				sawRelatedSite = true
			}
		}
	}
	if !sawRelatedHandler || !sawRelatedSite {
		t.Fatalf("expected site↔handler correlation in RelatedEvidence; handler=%v site=%v related=%+v",
			sawRelatedHandler, sawRelatedSite, groups[0].RelatedEvidence)
	}

	html := string(EncodeHTML(r))
	for _, want := range []string{"8.4.24", "8.4.27", "Update review required", "somewebsite", "handler_args=redacted"} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	if strings.Contains(html, "s3cret") || strings.Contains(html, "should-not-appear") {
		t.Fatal("HTML leaked handler secrets")
	}

	fleet, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseFleetCSV(fleet)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 1 || rows[0].PHPVersion != "8.4.24" || rows[0].UpstreamMinimumFixed != "8.4.27" {
		t.Fatalf("%+v", rows)
	}
	if rows[0].ActiveHTTPRuntimeStatus == "" || rows[0].ActiveHTTPRuntimeStatus == "VERIFIED" {
		t.Fatalf("runtime status %+v", rows[0])
	}
	if rows[0].PatchStatus != "BELOW_UPSTREAM_FIX" {
		t.Fatal(rows[0].PatchStatus)
	}

	outDir := t.TempDir()
	htmlPath := filepath.Join(outDir, "e2e.html")
	csvPath := MatchingCSVPath(htmlPath)
	if err := SaveReportPair(r, htmlPath, csvPath); err != nil {
		t.Fatal(err)
	}
	summary := filepath.Join(outDir, "rollup.csv")
	if err := RollupFleetCSV(FleetRollupOptions{InputFiles: []string{csvPath}, Output: summary}); err != nil {
		t.Fatal(err)
	}
	sumBytes, _ := os.ReadFile(summary)
	sumRows, err := ParseFleetCSV(sumBytes)
	if err != nil || len(sumRows) < 1 || sumRows[0].PHPVersion != "8.4.24" {
		t.Fatalf("rollup %+v err=%v", sumRows, err)
	}
}

func TestIISInaccessibleHandlerReportsIncompleteNotSafe(t *testing.T) {
	xml := `<?xml version="1.0"?><configuration><system.webServer><handlers>` +
		`<add name="PHP_via_FastCGI" path="*.php" verb="*" modules="FastCgiModule" ` +
		`scriptProcessor="E:\PHP\missing\php-cgi.exe|-d password=nope"/></handlers></system.webServer></configuration>`
	r := NewReport("win", "windows", "amd64")
	ApplyIISApplicationHostInventory(r, `C:\Windows\System32\inetsrv\config\applicationHost.config`, []byte(xml))
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	incomplete := false
	for _, c := range r.Coverage {
		if c.Name == "windows_iis_configuration" && (c.Status == "INCOMPLETE" || c.Status == "PARTIAL") {
			incomplete = true
		}
	}
	if !incomplete {
		t.Fatal(r.Coverage)
	}
	for _, e := range r.Evidence {
		if strings.Contains(e.Detail, "password") || strings.Contains(e.Detail, "nope") {
			t.Fatal(e.Detail)
		}
	}
	// No comparable version → must not claim host is patched/safe.
	if r.VulnerabilityStatus == "UPSTREAM_FIX_LEVEL_OBSERVED_ACTIVE_RUNTIME_UNVERIFIED" {
		t.Fatal(r.VulnerabilityStatus)
	}
	html := string(EncodeHTML(r))
	if strings.Contains(strings.ToLower(html), "host is safe") {
		t.Fatal(html)
	}
}

func TestFormatIISHandlerDetailRedactsArgs(t *testing.T) {
	d := FormatIISHandlerDetail("*.php", "FastCgiModule", `E:\PHP\8.4.24\php-cgi.exe|-d password=secret`)
	if strings.Contains(d, "secret") || strings.Contains(d, "password=") {
		t.Fatal(d)
	}
	if !strings.Contains(d, "handler_args=redacted") {
		t.Fatal(d)
	}
	if HandlerExecutableFromDetail(d) != `E:\PHP\8.4.24\php-cgi.exe` {
		t.Fatal(HandlerExecutableFromDetail(d))
	}
}
