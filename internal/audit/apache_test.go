package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestApacheDebianLayoutVHostsHandlersRemoteAndModPHP(t *testing.T) {
	root := moduleTestdataPath(t, "apache/linux-debian-layout")
	r := NewReport("apache-linux", "linux", "amd64")
	ParseApacheConfigForTest(r, root)

	sawA, sawB, sawRemote, sawMod := false, false, false, false
	for _, e := range r.Evidence {
		switch e.Type {
		case "apache_vhost_config":
			if e.Name == "app-a.example.local" && strings.Contains(e.Location, "/srv/www/app-a") {
				sawA = true
			}
			if e.Name == "app-b.example.local" && strings.Contains(e.Location, "/data/websites/app-b") {
				sawB = true
			}
			if e.Interpretation != "CONFIGURED_VHOST_PATH_NOT_PROOF_PHP_IS_SERVED_OR_ACTIVE_RUNTIME" {
				t.Fatal(e.Interpretation)
			}
		case "apache_php_handler_config":
			if strings.Contains(e.Detail, "php8.4-fpm.sock") || strings.Contains(e.Detail, "php8.3-fpm.sock") {
				// ok
			}
			if e.Interpretation != "CONFIGURED_HANDLER_NOT_VERIFIED_SERVING_RUNTIME" {
				t.Fatal(e.Interpretation)
			}
		case "apache_remote_php_backend":
			if strings.Contains(e.Detail, "10.9.9.9") {
				sawRemote = true
			}
			if e.Interpretation != "CONFIGURED_REMOTE_BACKEND_NOT_LOCAL_INSTALL_NOT_RUNTIME_VERIFIED" {
				t.Fatal(e.Interpretation)
			}
		case "apache_php_module_config":
			sawMod = true
		}
	}
	if !sawA || !sawB || !sawRemote || !sawMod {
		t.Fatalf("a=%v b=%v remote=%v mod=%v evidence=%+v", sawA, sawB, sawRemote, sawMod, r.Evidence)
	}
	incomplete := false
	for _, c := range r.Coverage {
		if c.Name == "apache_configuration" {
			if c.Status != "INCOMPLETE" {
				t.Fatalf("expected INCOMPLETE due to remote backend, got %s (%s)", c.Status, c.Detail)
			}
			incomplete = true
			if !strings.Contains(c.Detail, "Tomcat not scanned") {
				t.Fatal(c.Detail)
			}
		}
	}
	if !incomplete {
		t.Fatal("missing apache_configuration coverage")
	}
}

func TestApacheWindowsHttpdNonStandardPathsAndCGI(t *testing.T) {
	root := moduleTestdataPath(t, "apache/windows-httpd-layout")
	// Copy into temp so we can place a resolvable php-cgi beside a Unix-style open.
	tmp := t.TempDir()
	confDir := filepath.Join(tmp, "conf")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(root, "httpd.conf"))
	if err != nil {
		t.Fatal(err)
	}
	phpDir := filepath.Join(tmp, "PHP", "8.4.24")
	if err := os.MkdirAll(phpDir, 0755); err != nil {
		t.Fatal(err)
	}
	phpCGI := filepath.Join(phpDir, "php-cgi.exe")
	if err := os.WriteFile(phpCGI, []byte("MZ path PHP Version 8.4.24 marker"), 0644); err != nil {
		t.Fatal(err)
	}
	// Rewrite Action target to the temp php-cgi so version inspection works cross-platform.
	rewritten := strings.ReplaceAll(string(src), `E:/PHP/8.4.24/php-cgi.exe`, phpCGI)
	rewritten = strings.ReplaceAll(rewritten, `DocumentRoot "E:/websites/prod/apache-app"`, `DocumentRoot "`+filepath.Join(tmp, "websites", "prod", "apache-app")+`"`)
	if err := os.WriteFile(filepath.Join(confDir, "httpd.conf"), []byte(rewritten), 0644); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(tmp, "websites", "prod", "apache-app"), 0755)

	r := NewReport("apache-win", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 21, 20, 30, 0, 0, time.UTC)
	ParseApacheConfigForTest(r, confDir)

	sawVHost, sawHandler, sawVersion := false, false, false
	for _, e := range r.Evidence {
		switch e.Type {
		case "apache_vhost_config":
			if strings.Contains(e.Location, "apache-app") {
				sawVHost = true
			}
		case "apache_php_handler_config":
			sawHandler = true
			if strings.Contains(strings.ToLower(e.Detail), "password") {
				t.Fatal(e.Detail)
			}
		case "apache_php_module_config":
			// LoadModule still points at C:/PHP... — recorded as configured module
		case "binary_static_version", "binary_path_inferred_version":
			if e.Version == "8.4.24" {
				sawVersion = true
			}
		}
	}
	if !sawVHost || !sawHandler || !sawVersion {
		t.Fatalf("vhost=%v handler=%v version=%v evidence=%+v", sawVHost, sawHandler, sawVersion, r.Evidence)
	}

	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	if r.VulnerabilityStatus != "BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED" {
		t.Fatal(r.VulnerabilityStatus)
	}
	rt, _ := humanRuntime(r)
	if rt == "Verified" {
		t.Fatal("must not claim verified active runtime from Apache config")
	}

	html := string(EncodeHTML(r))
	for _, want := range []string{"8.4.24", "8.4.27", "Update review required", "apache"} {
		if !strings.Contains(strings.ToLower(html), strings.ToLower(want)) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	fleet, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseFleetCSV(fleet)
	if err != nil || len(rows) < 1 || rows[0].PHPVersion != "8.4.24" {
		t.Fatalf("fleet %+v err=%v", rows, err)
	}
	if rows[0].ActiveHTTPRuntimeStatus == "VERIFIED" {
		t.Fatal(rows[0].ActiveHTTPRuntimeStatus)
	}
}

func TestApacheTomcatConfigIsNotPHPEvidence(t *testing.T) {
	// Place Tomcat server.xml under a decoy directory that is NOT an Apache root seed pattern.
	// Direct parse of non-Apache XML through ApplyApacheRootsInventory should yield no PHP handlers.
	tmp := t.TempDir()
	conf := filepath.Join(tmp, "conf")
	_ = os.MkdirAll(conf, 0755)
	src := moduleTestdataPath(t, "apache/tomcat-not-php/server.xml")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conf, "server.xml"), b, 0644); err != nil {
		t.Fatal(err)
	}
	// Also drop a misleading httpd.conf that only comments about Tomcat — still no PHP directives.
	if err := os.WriteFile(filepath.Join(conf, "httpd.conf"), []byte("# proxy to Tomcat AJP — not PHP\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r := NewReport("tomcat-host", "linux", "amd64")
	ParseApacheConfigForTest(r, conf)
	for _, e := range r.Evidence {
		if strings.HasPrefix(e.Type, "apache_") && e.Type != "" {
			if e.Type == "apache_vhost_config" || e.Type == "apache_php_handler_config" || e.Type == "apache_php_module_config" || e.Type == "apache_remote_php_backend" {
				t.Fatalf("Tomcat/decoy must not yield PHP Apache evidence: %+v", e)
			}
		}
	}
}

func TestApacheNoRootsNotApplicable(t *testing.T) {
	if runtime.GOOS == "windows" {
		// May have Apache installed; still ensure function is safe.
	}
	r := NewReport("no-apache", "linux", "amd64")
	// Call inventory with empty roots equivalent path: use a temp empty dir that has no seed files.
	empty := t.TempDir()
	ParseApacheConfigForTest(r, empty)
	for _, c := range r.Coverage {
		if c.Name == "apache_configuration" && c.Status == "UNAVAILABLE" {
			t.Fatal("empty root should be PARTIAL/TRUNCATED-style inventory, not host-wide UNAVAILABLE")
		}
	}
}

func TestApacheInaccessibleHandlerBinaryIncomplete(t *testing.T) {
	tmp := t.TempDir()
	conf := filepath.Join(tmp, "conf")
	_ = os.MkdirAll(conf, 0755)
	missing := filepath.Join(tmp, "missing", "php-cgi")
	content := `DocumentRoot "/var/www"
Action application/x-httpd-php "` + missing + `"
AddHandler application/x-httpd-php .php
`
	if err := os.WriteFile(filepath.Join(conf, "httpd.conf"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	r := NewReport("apache-missing", "linux", "amd64")
	ParseApacheConfigForTest(r, conf)
	for _, c := range r.Coverage {
		if c.Name == "apache_configuration" && c.Status != "INCOMPLETE" {
			t.Fatalf("got %s %s", c.Status, c.Detail)
		}
	}
	html := string(EncodeHTML(r))
	if strings.Contains(strings.ToLower(html), "host is safe") {
		t.Fatal(html)
	}
}

func TestApacheMultiSiteCorrelationInHTMLAndCSV(t *testing.T) {
	tmp := t.TempDir()
	conf := filepath.Join(tmp, "conf")
	php84 := filepath.Join(tmp, "php", "8.4.24")
	_ = os.MkdirAll(conf, 0755)
	_ = os.MkdirAll(php84, 0755)
	cgi := filepath.Join(php84, "php-cgi")
	if err := os.WriteFile(cgi, []byte("PHP Version 8.4.24"), 0644); err != nil {
		t.Fatal(err)
	}
	site := filepath.Join(tmp, "www", "shop")
	_ = os.MkdirAll(site, 0755)
	content := `<VirtualHost *:443>
ServerName shop.example.local
DocumentRoot "` + site + `"
Action application/x-httpd-php "` + cgi + `"
AddHandler application/x-httpd-php .php
</VirtualHost>
`
	if err := os.WriteFile(filepath.Join(conf, "httpd.conf"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	r := NewReport("shop", "linux", "amd64")
	ParseApacheConfigForTest(r, conf)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	groups := GroupInstallations(r)
	if len(groups) < 1 {
		t.Fatal("expected install group")
	}
	sawHandler, sawVHost := false, false
	for _, e := range groups[0].RelatedEvidence {
		if e.Type == "apache_php_handler_config" {
			sawHandler = true
		}
		if e.Type == "apache_vhost_config" && strings.Contains(e.Name, "shop.example.local") {
			sawVHost = true
		}
	}
	if !sawHandler || !sawVHost {
		t.Fatalf("expected handler+vhost correlation; handler=%v vhost=%v related=%+v", sawHandler, sawVHost, groups[0].RelatedEvidence)
	}
	html := string(EncodeHTML(r))
	if !strings.Contains(html, "shop.example.local") {
		t.Fatal("HTML missing vhost name")
	}
	rows, err := ParseFleetCSV(mustEncodeFleet(t, r))
	if err != nil || rows[0].PHPVersion != "8.4.24" || rows[0].UpstreamMinimumFixed != "8.4.27" {
		t.Fatalf("%+v err=%v", rows, err)
	}
}

func mustEncodeFleet(t *testing.T, r *Report) []byte {
	t.Helper()
	b, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
