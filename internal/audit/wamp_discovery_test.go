package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestVersionFromInstallPathWampAndBare(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{`C:\wamp64\bin\php\php7.4.33\php.exe`, "7.4.33"},
		{`C:\wamp\bin\php\php8.2.12\php-cgi.exe`, "8.2.12"},
		{`C:\Users\x\AppData\Local\Programs\PHP\8.4.24\nts\x64\php.exe`, "8.4.24"},
		{`/opt/php/8.3.36/bin/php`, "8.3.36"},
		{`C:\wamp64\bin\php\php7.4\php.exe`, ""},          // no patch segment
		{`C:\wamp64\bin\php\php74\php.exe`, ""},           // ambiguous
		{`C:\wamp64\bin\php\current\php.exe`, ""},         // alias only
		{`C:\wamp64\bin\php\php-7.4.33\php.exe`, ""},      // hyphenated prefix
		{`C:\wamp64\bin\php\something7.4.33\php.exe`, ""}, // not a version segment
		{`C:\wamp64\bin\php\7.4.33rc1\php.exe`, ""},       // prerelease token
	}
	for _, tc := range cases {
		v, src := VersionFromInstallPath(tc.path)
		if v != tc.want {
			t.Fatalf("path %q: got version %q want %q", tc.path, v, tc.want)
		}
		if tc.want != "" && src != "install_path_version_segment" {
			t.Fatalf("path %q: unexpected source %q", tc.path, src)
		}
		if tc.want == "" && src != "" {
			t.Fatalf("path %q: expected empty source, got %q", tc.path, src)
		}
	}
}

func TestWampMarkerFreeBinaryKeepsPathInferredMedium(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "wamp64", "bin", "php", "php7.4.33")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(binDir, "php.exe")
	if err := os.WriteFile(path, []byte("MZ\x00\x00 marker-free WampServer fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	res := VersionFromBinary(path)
	if res.Version != "7.4.33" || res.Provenance != "path_inferred" || res.Confidence != "MEDIUM" {
		t.Fatalf("%+v", res)
	}
	r := NewReport("ASERVER2-fixture", "windows", "amd64")
	AddBinaryVersionEvidence(r, path, "php.exe", "Windows well-known WampServer static binary inspection")
	if len(r.Evidence) != 1 || r.Evidence[0].Type != "binary_path_inferred_version" {
		t.Fatalf("%+v", r.Evidence)
	}
	if r.Evidence[0].Interpretation != "PATH_INFERRED_VERSION_NOT_BINARY_VERIFIED_NOT_RUNTIME_ATTESTATION" {
		t.Fatal(r.Evidence[0].Interpretation)
	}
	if !strings.Contains(r.Evidence[0].Detail, "provenance=path_inferred") || !strings.Contains(r.Evidence[0].Detail, "confidence=MEDIUM") {
		t.Fatal(r.Evidence[0].Detail)
	}
}

func TestWampApacheAndPHPIniWellKnownPatterns(t *testing.T) {
	joinedApache := strings.Join(apacheConfigRootGlobs, "\n")
	for _, need := range []string{
		`C:\wamp64\bin\apache\*\conf`,
		`C:\wamp\bin\apache\*\conf`,
	} {
		if !strings.Contains(joinedApache, need) {
			t.Fatalf("missing apache glob %q in %v", need, apacheConfigRootGlobs)
		}
	}
	if runtime.GOOS == "windows" {
		iniJoined := strings.Join(phpIniWellKnownPatterns(), "\n")
		if !strings.Contains(iniJoined, `C:\wamp64\bin\php\*\php.ini`) {
			t.Fatalf("missing wamp64 php.ini pattern in %v", phpIniWellKnownPatterns())
		}
	} else {
		// Patterns are Windows-only; assert the source list still documents wamp64.
		src, err := os.ReadFile("php_ini.go")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), `C:\wamp64\bin\php\*\php.ini`) {
			t.Fatal("php_ini.go must list wamp64 php.ini well-known pattern")
		}
	}
}

func TestWampApacheGlobExpansionDiscoversConf(t *testing.T) {
	root := t.TempDir()
	confDir := filepath.Join(root, "wamp64", "bin", "apache", "apache2.4.54.2", "conf")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatal(err)
	}
	httpd := filepath.Join(confDir, "httpd.conf")
	body := `ServerRoot "` + filepath.ToSlash(filepath.Join(root, "wamp64", "bin", "apache", "apache2.4.54.2")) + `"
Listen 80
LoadModule php7_module "` + filepath.ToSlash(filepath.Join(root, "wamp64", "bin", "php", "php7.4.33", "php7apache2_4.dll")) + `"
<VirtualHost *:80>
    ServerName aserver2.local
    DocumentRoot "` + filepath.ToSlash(filepath.Join(root, "www")) + `"
</VirtualHost>
`
	if err := os.WriteFile(httpd, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(root, "wamp64", "bin", "apache", "*", "conf"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 conf root via bounded glob, got %v", matches)
	}
	r := NewReport("wamp-apache", "windows", "amd64")
	ParseApacheConfigForTest(r, confDir)
	sawMod, sawVHost := false, false
	for _, e := range r.Evidence {
		switch e.Type {
		case "apache_php_module_config":
			sawMod = true
			if e.Interpretation == "" || strings.Contains(strings.ToLower(e.Interpretation), "active") && strings.Contains(strings.ToLower(e.Interpretation), "verified") {
				// Must not claim verified active runtime.
			}
			if strings.Contains(e.Interpretation, "ACTIVE_RUNTIME") && !strings.Contains(e.Interpretation, "NOT") {
				t.Fatalf("must not attribute active runtime from static config: %s", e.Interpretation)
			}
		case "apache_vhost_config":
			sawVHost = true
			if e.Interpretation != "CONFIGURED_VHOST_PATH_NOT_PROOF_PHP_IS_SERVED_OR_ACTIVE_RUNTIME" {
				t.Fatal(e.Interpretation)
			}
		}
	}
	if !sawMod || !sawVHost {
		t.Fatalf("mod=%v vhost=%v evidence=%+v", sawMod, sawVHost, r.Evidence)
	}
	rt, _ := humanRuntime(r)
	if rt == "Verified" {
		t.Fatal("Apache config alone must not verify active web runtime")
	}
}

func TestASERVER2WampStyleFixtureE2E(t *testing.T) {
	// Synthetic ASERVER2-style WampServer layout: phpX.Y.Z dirs, marker-free binaries,
	// Apache conf + php.ini. No PHP execution; no false active-runtime attribution.
	root := t.TempDir()
	phpDir := filepath.Join(root, "wamp64", "bin", "php", "php7.4.33")
	confDir := filepath.Join(root, "wamp64", "bin", "apache", "apache2.4.54.2", "conf")
	www := filepath.Join(root, "www")
	for _, d := range []string{phpDir, confDir, www} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	phpBin := filepath.Join(phpDir, "php.exe")
	phpCGI := filepath.Join(phpDir, "php-cgi.exe")
	phpIni := filepath.Join(phpDir, "php.ini")
	markerFree := []byte("MZ\x00\x00 ASERVER2 WampServer marker-free fixture")
	if err := os.WriteFile(phpBin, markerFree, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(phpCGI, markerFree, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(phpIni, []byte("memory_limit = 128M\nexpose_php = Off\n"), 0644); err != nil {
		t.Fatal(err)
	}
	httpd := filepath.Join(confDir, "httpd.conf")
	if err := os.WriteFile(httpd, []byte(
		`LoadModule php7_module "`+filepath.ToSlash(filepath.Join(phpDir, "php7apache2_4.dll"))+`"
PHPIniDir "`+filepath.ToSlash(phpDir)+`"
<VirtualHost *:80>
    ServerName aserver2.example.local
    DocumentRoot "`+filepath.ToSlash(www)+`"
    Action application/x-httpd-php "`+filepath.ToSlash(phpCGI)+`"
    AddHandler application/x-httpd-php .php
</VirtualHost>
`), 0644); err != nil {
		t.Fatal(err)
	}

	r := NewReport("ASERVER2", "windows", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	src := "Windows well-known WampServer static binary inspection"
	AddBinaryVersionEvidence(r, phpBin, "php.exe", src)
	AddBinaryVersionEvidence(r, phpCGI, "php-cgi.exe", src)
	ParseApacheConfigForTest(r, confDir)

	oldPatterns := phpIniWellKnownPatternsFn
	phpIniWellKnownPatternsFn = func() []string {
		return []string{filepath.Join(root, "wamp64", "bin", "php", "*", "php.ini")}
	}
	defer func() { phpIniWellKnownPatternsFn = oldPatterns }()
	scanConfigs(r, HostScanOptions{}, nil)

	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	inferred, verified, unknown := 0, 0, 0
	for _, e := range r.Evidence {
		switch e.Type {
		case "binary_path_inferred_version":
			inferred++
			if e.Version != "7.4.33" {
				t.Fatalf("inferred version=%q", e.Version)
			}
		case "binary_static_version":
			verified++
		case "binary_path":
			unknown++
		}
	}
	// Well-known discovery yields php.exe + php-cgi.exe; Apache handler follow-up may
	// re-inspect php-cgi.exe — all remain path_inferred, never verified metadata.
	if inferred < 2 || verified != 0 || unknown != 0 {
		t.Fatalf("inferred=%d verified=%d unknown=%d evidence=%+v", inferred, verified, unknown, r.Evidence)
	}

	cov := CountBinaryInstallCoverage(r)
	if cov.PathInferred < 2 || cov.Verified != 0 || cov.VersionUnknown != 0 || cov.BinaryCandidates < 2 {
		t.Fatalf("%+v", cov)
	}

	if r.VulnerabilityStatus != "LEGACY_PHP_VENDOR_PATCH_VERIFICATION_REQUIRED" {
		t.Fatalf("status=%s assessments=%+v", r.VulnerabilityStatus, r.PatchAssessments)
	}
	for _, a := range r.PatchAssessments {
		if a.EvidenceType != "binary_path_inferred_version" || a.Confidence != "MEDIUM" {
			t.Fatalf("%+v", a)
		}
		if a.Status != "LEGACY_VENDOR_VERIFICATION_REQUIRED" {
			t.Fatalf("%+v", a)
		}
		if !strings.Contains(a.Qualification, "PATH-INFERRED") {
			t.Fatal(a.Qualification)
		}
	}

	rt, _ := humanRuntime(r)
	if rt == "Verified" {
		t.Fatal("must not claim verified active HTTP runtime from Wamp inventory/config")
	}

	gaps := executiveVerificationGaps(r)
	joinedGaps := strings.Join(gaps, "; ")
	if !strings.Contains(joinedGaps, "path-inferred") || !strings.Contains(joinedGaps, "HTTP-serving PHP runtime") {
		t.Fatalf("gaps=%v", gaps)
	}

	steps := BuildFocusedNextSteps(r)
	stepText := strings.Join(steps, "\n")
	if !strings.Contains(strings.ToLower(stepText), "legacy") {
		t.Fatalf("expected legacy review messaging in next steps: %v", steps)
	}
	if !strings.Contains(stepText, "path-inferred") {
		t.Fatalf("expected path-inferred manual verification step: %v", steps)
	}

	html := string(EncodeHTML(r))
	for _, need := range []string{
		"7.4.33",
		"path-inferred",
		"verified binary metadata",
		"manual verification",
		"not a clearance",
	} {
		if !strings.Contains(strings.ToLower(html), strings.ToLower(need)) {
			t.Fatalf("HTML missing %q", need)
		}
	}
	rtLabel, _ := humanRuntime(r)
	if rtLabel == "Verified" || strings.Contains(html, `<p class="value">Verified</p>`) {
		t.Fatal("HTML/CLI must not show Verified active web runtime")
	}

	csvBytes, err := EncodeCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	csv := string(csvBytes)
	if !strings.Contains(csv, "binary_path_inferred_version") || !strings.Contains(csv, "7.4.33") {
		t.Fatalf("CSV missing inferred evidence: %s", csv[:min(500, len(csv))])
	}
	if !strings.Contains(csv, "confidence=MEDIUM") || !strings.Contains(csv, "provenance=path_inferred") {
		t.Fatal("CSV must retain path_inferred MEDIUM provenance detail")
	}

	fleetBytes, err := EncodeFleetCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	fleet := string(fleetBytes)
	if !strings.Contains(fleet, "path_inferred") || !strings.Contains(fleet, "MEDIUM") {
		t.Fatalf("fleet CSV missing path_inferred/MEDIUM")
	}

	// Bare X.Y.Z layout still works alongside phpX.Y.Z.
	bareDir := filepath.Join(root, "wamp64", "bin", "php", "8.2.28")
	_ = os.MkdirAll(bareDir, 0755)
	bareBin := filepath.Join(bareDir, "php.exe")
	_ = os.WriteFile(bareBin, []byte("MZ\x00 bare-version-dir marker-free"), 0644)
	v, _ := VersionFromInstallPath(bareBin)
	if v != "8.2.28" {
		t.Fatalf("bare layout regression: %q", v)
	}
}
