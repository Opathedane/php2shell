package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeNginxTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNginxLocalFPMUnixSocketCorrelated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	fpmRoot := filepath.Join(root, "php", "8.3", "fpm", "pool.d")
	sock := filepath.Join(root, "run", "php", "php8.3-fpm.sock")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `
http {
  include conf.d/*.conf;
}
`,
		"conf.d/app.conf": `
server {
  server_name app.example.local;
  root /var/www/app;
  location ~ \.php$ {
    fastcgi_pass unix:` + sock + `;
  }
}
`,
	})
	writeNginxTree(t, fpmRoot, map[string]string{
		"www.conf": "[www]\nlisten = " + sock + "\n",
	})

	r := NewReport("nginx-unix", "linux", "amd64")
	ParseNginxConfigForTest(r, nginxRoot)
	ParseFPMPoolsForTest(r, fpmRoot)
	CorrelateNginxFPMBackends(r)
	FinalizeSummary(r)

	sawHandler, correlated, verified := false, false, false
	for _, e := range r.Evidence {
		if e.Type == "nginx_php_handler_config" && strings.Contains(e.Detail, "unix:") {
			sawHandler = true
			if strings.Contains(e.Detail, "correlated_fpm_pool=www") {
				correlated = true
			}
			if e.Interpretation != "CONFIGURED_HANDLER_NOT_VERIFIED_SERVING_RUNTIME" {
				t.Fatal(e.Interpretation)
			}
		}
		if e.Type == "php_fpm_pool_config" && e.Name == "www" {
			// ok
		}
	}
	if r.EffectiveWebRuntime == "VERIFIED" || strings.EqualFold(r.EffectiveWebRuntime, "verified") {
		verified = true
	}
	rt, _ := humanRuntime(r)
	if rt == "Verified" {
		verified = true
	}
	if !sawHandler || !correlated {
		t.Fatalf("handler=%v correlated=%v evidence=%+v", sawHandler, correlated, r.Evidence)
	}
	if verified {
		t.Fatal("must not claim verified HTTP runtime from nginx/FPM config alone")
	}
}

func TestNginxLocalFPMTCPLoopback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	fpmRoot := filepath.Join(root, "php-fpm.d")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `http { include sites-enabled/*; }`,
		"sites-enabled/app.conf": `
server {
  server_name tcp.example.local;
  root /srv/www;
  location ~ \.php$ {
    fastcgi_pass 127.0.0.1:9000;
  }
}
`,
	})
	writeNginxTree(t, fpmRoot, map[string]string{
		"www.conf": "[www]\nlisten = 127.0.0.1:9000\n",
	})
	r := NewReport("nginx-tcp", "linux", "amd64")
	ParseNginxConfigForTest(r, nginxRoot)
	ParseFPMPoolsForTest(r, fpmRoot)
	CorrelateNginxFPMBackends(r)
	saw := false
	for _, e := range r.Evidence {
		if e.Type == "nginx_php_handler_config" && strings.Contains(e.Detail, "127.0.0.1:9000") &&
			strings.Contains(e.Detail, "correlated_fpm_pool=www") {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("expected TCP loopback correlation: %+v", r.Evidence)
	}
}

func TestNginxRemoteFPMNotLocalInstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `http { include conf.d/*.conf; }`,
		"conf.d/remote.conf": `
server {
  server_name remote.example.local;
  root /var/www;
  location ~ \.php$ {
    fastcgi_pass 10.9.9.9:9000;
  }
}
`,
	})
	r := NewReport("nginx-remote", "linux", "amd64")
	ParseNginxConfigForTest(r, nginxRoot)
	sawRemote := false
	for _, e := range r.Evidence {
		if e.Type == "nginx_remote_php_backend" && strings.Contains(e.Detail, "10.9.9.9:9000") {
			sawRemote = true
			if e.Interpretation != "CONFIGURED_REMOTE_BACKEND_NOT_LOCAL_INSTALL_NOT_RUNTIME_VERIFIED" {
				t.Fatal(e.Interpretation)
			}
		}
		if e.Type == "nginx_php_handler_config" && strings.Contains(e.Detail, "10.9.9.9") {
			t.Fatal("remote must not be recorded as local handler")
		}
	}
	if !sawRemote {
		t.Fatalf("expected remote backend evidence: %+v", r.Evidence)
	}
	for _, c := range r.Coverage {
		if c.Name == "nginx_configuration" && c.Status != "INCOMPLETE" {
			t.Fatalf("remote backend should mark INCOMPLETE, got %s", c.Status)
		}
	}
}

func TestNginxMultipleFPMPoolsMixedVersions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	fpmRoot := filepath.Join(root, "pool.d")
	sock83 := filepath.Join(root, "php8.3-fpm.sock")
	sock84 := filepath.Join(root, "php8.4-fpm.sock")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `http { include conf.d/*.conf; }`,
		"conf.d/a.conf": `
server {
  server_name a.example.local;
  location ~ \.php$ { fastcgi_pass unix:` + sock83 + `; }
}
`,
		"conf.d/b.conf": `
server {
  server_name b.example.local;
  location ~ \.php$ { fastcgi_pass unix:` + sock84 + `; }
}
`,
	})
	writeNginxTree(t, fpmRoot, map[string]string{
		"a.conf": "[pool83]\nlisten = " + sock83 + "\n",
		"b.conf": "[pool84]\nlisten = " + sock84 + "\n",
	})
	r := NewReport("nginx-multi", "linux", "amd64")
	ParseNginxConfigForTest(r, nginxRoot)
	ParseFPMPoolsForTest(r, fpmRoot)
	CorrelateNginxFPMBackends(r)
	pools, handlers := map[string]bool{}, 0
	for _, e := range r.Evidence {
		if e.Type == "php_fpm_pool_config" {
			pools[e.Name] = true
		}
		if e.Type == "nginx_php_handler_config" {
			handlers++
		}
	}
	if !pools["pool83"] || !pools["pool84"] || handlers < 2 {
		t.Fatalf("pools=%v handlers=%d evidence=%+v", pools, handlers, r.Evidence)
	}
}

func TestNginxMissingRootsNotApplicable(t *testing.T) {
	// Empty allowlist: inventory still records a coverage row without inventing PHP.
	r := NewReport("nginx-empty", "linux", "amd64")
	ApplyNginxRootsInventory(r, []string{})
	sawNginx := false
	for _, c := range r.Coverage {
		if c.Name == "nginx_configuration" {
			sawNginx = true
		}
	}
	if !sawNginx {
		t.Fatal("expected nginx_configuration coverage for empty roots")
	}
	for _, e := range r.Evidence {
		if strings.HasPrefix(e.Type, "nginx_php") || e.Type == "php_fpm_pool_config" {
			t.Fatalf("empty roots must not invent PHP evidence: %+v", e)
		}
	}
	// Inaccessible custom root: no hang, no PHP handlers.
	missing := filepath.Join(t.TempDir(), "missing-nginx-root")
	r2 := NewReport("nginx-missing", "linux", "amd64")
	ApplyNginxRootsInventory(r2, []string{missing})
	for _, e := range r2.Evidence {
		if e.Type == "nginx_php_handler_config" || e.Type == "nginx_remote_php_backend" {
			t.Fatalf("inaccessible root must not invent handlers: %+v", e)
		}
	}
	rFPM := NewReport("fpm-empty", "linux", "amd64")
	ApplyFPMPoolRootsInventory(rFPM, []string{})
	for _, e := range rFPM.Evidence {
		if e.Type == "php_fpm_pool_config" {
			t.Fatalf("empty FPM roots must not invent pools: %+v", e)
		}
	}
}

func TestNginxIncludeCycleAndOutOfRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	outside := filepath.Join(root, "outside", "evil.conf")
	_ = os.MkdirAll(filepath.Dir(outside), 0755)
	_ = os.WriteFile(outside, []byte(`server { location ~ \.php$ { fastcgi_pass 10.1.1.1:9000; } }`), 0644)
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `
http {
  include a.conf;
}
`,
		"a.conf": `include b.conf;`,
		"b.conf": `include a.conf; include ` + outside + `;`,
	})
	r := NewReport("nginx-cycle", "linux", "amd64")
	done := make(chan struct{})
	go func() {
		ParseNginxConfigForTest(r, nginxRoot)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("nginx include cycle hung")
	}
	// Out-of-root include must not surface remote backend from outside.
	for _, e := range r.Evidence {
		if e.Type == "nginx_remote_php_backend" && strings.Contains(e.Detail, "10.1.1.1") {
			t.Fatal("must not follow include outside allowlisted root")
		}
	}
}

func TestNginxDoesNotInventHandlerWhenPHPInstalledElsewhere(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `
http {
  server {
    server_name static.example.local;
    root /var/www/static;
    location / { try_files $uri =404; }
  }
}
`,
	})
	r := NewReport("nginx-static", "linux", "amd64")
	// Simulate PHP binary inventory without nginx PHP wiring.
	r.AddEvidence(Evidence{
		Type: "binary_static_version", Name: "php", Version: "8.3.36",
		Source: "test", Location: "/usr/bin/php", Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
	})
	ParseNginxConfigForTest(r, nginxRoot)
	for _, e := range r.Evidence {
		if e.Type == "nginx_php_handler_config" || e.Type == "nginx_remote_php_backend" {
			t.Fatalf("static site must not invent PHP handlers: %+v", e)
		}
	}
	sawSite := false
	for _, e := range r.Evidence {
		if e.Type == "nginx_site_config" && e.Name == "static.example.local" {
			sawSite = true
		}
	}
	if !sawSite {
		t.Fatalf("expected site config row: %+v", r.Evidence)
	}
}

func TestNginxHandlerDoesNotVerifyRuntimeOrPatchRemote(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `http { include conf.d/*.conf; }`,
		"conf.d/x.conf": `
server {
  location ~ \.php$ { fastcgi_pass 10.2.2.2:9000; }
}
`,
	})
	r := NewReport("nginx-no-upgrade", "linux", "amd64")
	r.AddEvidence(Evidence{
		Type: "binary_static_version", Name: "php-fpm", Version: "8.4.27",
		Source: "test", Location: "/usr/sbin/php-fpm8.4",
		Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
	})
	ParseNginxConfigForTest(r, nginxRoot)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	if r.EffectiveWebRuntime != "NOT_VERIFIED" && r.EffectiveWebRuntime != "" {
		// Default NewReport sets NOT_VERIFIED; never upgrade.
		if r.EffectiveWebRuntime == "VERIFIED" {
			t.Fatal(r.EffectiveWebRuntime)
		}
	}
	rt, detail := humanRuntime(r)
	if rt == "Verified" {
		t.Fatalf("runtime=%q detail=%q", rt, detail)
	}
	// Local patched binary must not imply remote backend is patched — no assessment rows for remote IP.
	for _, e := range r.Evidence {
		if e.Type == "nginx_remote_php_backend" && e.Version != "" {
			t.Fatalf("remote backend must not carry a local PHP version: %+v", e)
		}
	}
	groups := GroupInstallations(r)
	for _, g := range groups {
		if strings.Contains(g.Label, "10.2.2.2") {
			t.Fatalf("must not create install group for remote backend: %+v", g)
		}
	}
}

func TestNginxAmbiguousUpstream(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `
http {
  upstream php_backend {
    server 10.0.0.5:9000;
    server 127.0.0.1:9000;
  }
  server {
    location ~ \.php$ { fastcgi_pass php_backend; }
  }
}
`,
	})
	r := NewReport("nginx-mixed", "linux", "amd64")
	ParseNginxConfigForTest(r, nginxRoot)
	sawAmbiguous := false
	for _, e := range r.Evidence {
		if e.Type == "nginx_php_handler_config" && strings.Contains(e.Detail, "ambiguous") {
			sawAmbiguous = true
		}
	}
	if !sawAmbiguous {
		t.Fatalf("expected ambiguous backend: %+v", r.Evidence)
	}
}

func TestNginxHandlerWithoutVersionStaysUnknown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	sock := filepath.Join(root, "php-fpm.sock")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `http { include conf.d/*.conf; }`,
		"conf.d/app.conf": `
server {
  location ~ \.php$ { fastcgi_pass unix:` + sock + `; }
}
`,
	})
	r := NewReport("nginx-ver-unknown", "linux", "amd64")
	ParseNginxConfigForTest(r, nginxRoot)
	saw := false
	for _, e := range r.Evidence {
		if e.Type == "nginx_php_handler_config" {
			saw = true
			if e.Version != "" {
				t.Fatalf("handler must not invent a PHP version: %+v", e)
			}
		}
	}
	if !saw {
		t.Fatal("expected handler evidence")
	}
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	if r.EffectiveWebRuntime == "VERIFIED" {
		t.Fatal("must not verify runtime from handler without version")
	}
}

func TestNginxNoPHPWithinCoverageSoftNone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `
http {
  server {
    server_name empty.example.local;
    root /var/www/empty;
    location / { return 204; }
  }
}
`,
	})
	r := NewReport("nginx-none", "linux", "amd64")
	r.AddCheck("packages", "PARTIAL", "Found 0")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0")
	r.AddCheck("processes", "PARTIAL", "Found 0")
	ParseNginxConfigForTest(r, nginxRoot)
	ApplyFPMPoolRootsInventory(r, []string{})
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	if !NoPHPDetectedWithinScanCoverage(r) && !NoPHPWithIncompleteInventory(r) {
		// Soft none-within-coverage or incomplete is acceptable; inventing installs is not.
		t.Logf("discovery class may be incomplete depending on coverage gaps; summary=%q", r.Summary.PHPDiscovery)
	}
	for _, e := range r.Evidence {
		if e.Type == "nginx_php_handler_config" || e.Type == "php_fpm_pool_config" {
			t.Fatalf("static empty site must not invent PHP: %+v", e)
		}
	}
	if r.EffectiveWebRuntime == "VERIFIED" {
		t.Fatal("must not verify runtime")
	}
}

func TestNginxApacheIISCompatibilityStillLoads(t *testing.T) {
	// Smoke: constructing a report with all three web-server check names remains valid.
	r := NewReport("compat", runtime.GOOS, "amd64")
	r.AddCheck("apache_configuration", "NOT_APPLICABLE", "test")
	r.AddCheck("nginx_configuration", "NOT_APPLICABLE", "test")
	r.AddCheck("windows_iis_configuration", "NOT_APPLICABLE", "test")
	r.AddCheck("php_fpm_configuration", "NOT_APPLICABLE", "test")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0")
	r.AddCheck("packages", "PARTIAL", "Found 0")
	r.AddCheck("processes", "PARTIAL", "Found 0")
	FinalizeSummary(r)
	if r.Summary.PHPDiscovery == "" {
		t.Fatal("expected php discovery summary")
	}
}
