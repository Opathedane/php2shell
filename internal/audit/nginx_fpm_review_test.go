package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Runtime-correlation and honesty regressions for PR #34 review.
// These scenarios must not silently upgrade evidence confidence.

func TestNginxArbitraryUpstreamNameReferencedByPHP(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `
http {
  upstream backend {
    server 127.0.0.1:9000;
  }
  upstream static_assets {
    server 10.0.0.9:80;
  }
  server {
    location /assets/ { proxy_pass http://static_assets; }
    location ~ \.php$ {
      include fastcgi_params;
      fastcgi_pass backend;
    }
  }
}
`,
	})
	r := NewReport("nginx-arb-upstream", "linux", "amd64")
	ParseNginxConfigForTest(r, nginxRoot)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	sawHandler, sawBackendUpstream, sawStaticUpstream := false, false, false
	for _, e := range r.Evidence {
		if e.Type == "nginx_php_handler_config" && strings.Contains(e.Detail, "127.0.0.1:9000") &&
			strings.Contains(e.Detail, "scope=local_candidate") {
			sawHandler = true
		}
		if e.Type == "nginx_php_upstream_config" && e.Name == "backend" {
			sawBackendUpstream = true
			if !strings.Contains(e.Detail, "referenced_by_php_fastcgi_pass") {
				t.Fatalf("arbitrarily named PHP-referenced upstream should note reference: %+v", e)
			}
		}
		if e.Type == "nginx_php_upstream_config" && e.Name == "static_assets" {
			sawStaticUpstream = true
		}
		if e.Version != "" && strings.HasPrefix(e.Type, "nginx_") {
			t.Fatalf("must not invent version: %+v", e)
		}
	}
	if !sawHandler {
		t.Fatalf("expected local FastCGI handler via upstream backend: %+v", r.Evidence)
	}
	if !sawBackendUpstream {
		t.Fatalf("expected upstream evidence for PHP-referenced backend: %+v", r.Evidence)
	}
	if sawStaticUpstream {
		t.Fatal("unrelated HTTP proxy upstream must not be classified as PHP")
	}
	if r.EffectiveWebRuntime == "VERIFIED" {
		t.Fatal("must not verify runtime")
	}
}

func TestNginxRelevantIncludeUnresolvedBlocksSoftNone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	outside := filepath.Join(root, "outside", "php-app.conf")
	_ = os.MkdirAll(filepath.Dir(outside), 0755)
	_ = os.WriteFile(outside, []byte(`
server {
  location ~ \.php$ { fastcgi_pass unix:/run/php/php-fpm.sock; }
}
`), 0644)
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `
http {
  include mime.types;
  include ` + outside + `;
}
`,
		"mime.types": `types { text/html html; }`,
	})
	r := NewReport("nginx-include-gap", "linux", "amd64")
	r.AddCheck("packages", "PARTIAL", "Found 0")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0")
	r.AddCheck("processes", "PARTIAL", "Found 0")
	ParseNginxConfigForTest(r, nginxRoot)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	sawUnresolved := false
	for _, e := range r.Evidence {
		if e.Type == "nginx_include_unresolved" && strings.Contains(e.Detail, "outside_allowlisted_roots") {
			sawUnresolved = true
		}
		if e.Type == "nginx_php_handler_config" && strings.Contains(e.Detail, "/run/php/php-fpm.sock") {
			t.Fatal("must not follow PHP include outside allowlisted roots")
		}
	}
	if !sawUnresolved {
		t.Fatalf("expected nginx_include_unresolved for PHP-relevant out-of-root include: %+v", r.Evidence)
	}
	for _, c := range r.Coverage {
		if c.Name == "nginx_configuration" && c.Status != "INCOMPLETE" && c.Status != "TRUNCATED" {
			t.Fatalf("PHP-relevant unresolved include should mark INCOMPLETE, got %s", c.Status)
		}
	}
	if NoPHPDetectedWithinScanCoverage(r) {
		t.Fatal("must not claim soft no-PHP-within-coverage when PHP-relevant includes remain unresolved")
	}
}

func TestNginxIrrelevantIncludeOutsideRootStaysSilent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	outside := filepath.Join(root, "outside", "mime.types")
	_ = os.MkdirAll(filepath.Dir(outside), 0755)
	_ = os.WriteFile(outside, []byte(`types { text/html html; }`), 0644)
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `
http {
  include ` + outside + `;
  server { server_name static.local; root /var/www; location / { return 204; } }
}
`,
	})
	r := NewReport("nginx-mime-out", "linux", "amd64")
	r.AddCheck("packages", "PARTIAL", "Found 0")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0")
	r.AddCheck("processes", "PARTIAL", "Found 0")
	ParseNginxConfigForTest(r, nginxRoot)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	for _, e := range r.Evidence {
		if e.Type == "nginx_include_unresolved" {
			t.Fatalf("irrelevant mime.types outside root must not create incomplete noise: %+v", e)
		}
	}
}

func TestNginxVariableFastCGIPassNotLocal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `http { include conf.d/*.conf; }`,
		"conf.d/var.conf": `
server {
  location ~ \.php$ {
    fastcgi_pass unix:/run/php/$pool.sock;
  }
  location ~ ^/app\.php$ {
    fastcgi_pass $php_upstream;
  }
}
`,
	})
	r := NewReport("nginx-var", "linux", "amd64")
	ParseNginxConfigForTest(r, nginxRoot)
	for _, e := range r.Evidence {
		if e.Type == "nginx_php_handler_config" {
			if strings.Contains(e.Detail, "scope=local_candidate") {
				t.Fatalf("variable fastcgi_pass must not be treated as local: %+v", e)
			}
			if !strings.Contains(e.Detail, "variable_unresolved") && !strings.Contains(e.Detail, "ambiguous") {
				t.Fatalf("expected variable/ambiguous scope: %+v", e)
			}
			if e.Version != "" {
				t.Fatalf("must not invent version: %+v", e)
			}
		}
		if e.Type == "nginx_remote_php_backend" {
			t.Fatalf("variable backend must not be classified remote: %+v", e)
		}
	}
	for _, c := range r.Coverage {
		if c.Name == "nginx_configuration" && c.Status != "INCOMPLETE" {
			t.Fatalf("variable backends should mark INCOMPLETE, got %s", c.Status)
		}
	}
}

func TestNginxNonPHPUpstreamNotEmittedAsPHPEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `
http {
  upstream static_assets {
    server 10.0.0.9:80;
  }
  upstream php_fpm {
    server 127.0.0.1:9000;
  }
  server {
    location /assets/ { proxy_pass http://static_assets; }
    location ~ \.php$ { fastcgi_pass php_fpm; }
  }
}
`,
	})
	r := NewReport("nginx-upfilter", "linux", "amd64")
	ParseNginxConfigForTest(r, nginxRoot)
	for _, e := range r.Evidence {
		if e.Type == "nginx_php_upstream_config" && e.Name == "static_assets" {
			t.Fatalf("non-PHP upstream must not be labelled php upstream evidence: %+v", e)
		}
	}
}

func TestPatchedCLIDoesNotClearUnverifiedFPMOrRemote(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	fpmRoot := filepath.Join(root, "pool.d")
	sock := filepath.Join(root, "php-fpm.sock")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `http { include conf.d/*.conf; }`,
		"conf.d/app.conf": `
server {
  location ~ \.php$ { fastcgi_pass unix:` + sock + `; }
}
server {
  server_name remote.example.local;
  location ~ \.php$ { fastcgi_pass 10.8.8.8:9000; }
}
`,
	})
	writeNginxTree(t, fpmRoot, map[string]string{
		"www.conf": "[www]\nlisten = " + sock + "\n",
	})
	r := NewReport("nginx-cli-patch", "linux", "amd64")
	r.AddEvidence(Evidence{
		Type: "binary_static_version", Name: "php", Version: "8.4.27",
		Source: "test CLI", Location: "/usr/bin/php",
		Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
	})
	ParseNginxConfigForTest(r, nginxRoot)
	ParseFPMPoolsForTest(r, fpmRoot)
	CorrelateNginxFPMBackends(r)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	if r.EffectiveWebRuntime == "VERIFIED" {
		t.Fatal("config + CLI must not verify HTTP runtime")
	}
	for _, e := range r.Evidence {
		if e.Type == "nginx_remote_php_backend" && e.Version != "" {
			t.Fatalf("remote backend must not inherit CLI version: %+v", e)
		}
		if e.Type == "php_fpm_pool_config" && e.Version != "" {
			t.Fatalf("FPM pool must not inherit CLI version: %+v", e)
		}
		if e.Type == "nginx_php_handler_config" && e.Version != "" {
			t.Fatalf("handler must not inherit CLI version: %+v", e)
		}
	}
	// Patch assessments may exist for the CLI binary only — never for remote IP / pool listen.
	for _, a := range r.PatchAssessments {
		if strings.Contains(a.Location, "10.8.8.8") || strings.Contains(a.Component, "www") && a.EvidenceType == "php_fpm_pool_config" {
			t.Fatalf("unexpected patch assessment for unverified FPM/remote: %+v", a)
		}
		if a.EvidenceType == "nginx_php_handler_config" || a.EvidenceType == "nginx_remote_php_backend" || a.EvidenceType == "php_fpm_pool_config" {
			t.Fatalf("nginx/FPM config must not produce patch assessments: %+v", a)
		}
	}
	rt, _ := humanRuntime(r)
	if rt == "Verified" {
		t.Fatalf("runtime label=%q", rt)
	}
}

func TestMultiPoolVersionsDoNotCrossInherit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	fpmRoot := filepath.Join(root, "pool.d")
	sockA := filepath.Join(root, "a.sock")
	sockB := filepath.Join(root, "b.sock")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `http { include conf.d/*.conf; }`,
		"conf.d/a.conf": `server { server_name a.local; location ~ \.php$ { fastcgi_pass unix:` + sockA + `; } }`,
		"conf.d/b.conf": `server { server_name b.local; location ~ \.php$ { fastcgi_pass unix:` + sockB + `; } }`,
	})
	writeNginxTree(t, fpmRoot, map[string]string{
		"a.conf": "[pool_a]\nlisten = " + sockA + "\n",
		"b.conf": "[pool_b]\nlisten = " + sockB + "\n",
	})
	r := NewReport("nginx-pool-iso", "linux", "amd64")
	// Two distinct binaries — must remain independent; pools must not absorb either version.
	r.AddEvidence(Evidence{
		Type: "binary_static_version", Name: "php-fpm", Version: "8.3.36",
		Source: "test", Location: "/usr/sbin/php-fpm8.3",
		Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
	})
	r.AddEvidence(Evidence{
		Type: "binary_static_version", Name: "php-fpm", Version: "8.4.27",
		Source: "test", Location: "/usr/sbin/php-fpm8.4",
		Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
	})
	ParseNginxConfigForTest(r, nginxRoot)
	ParseFPMPoolsForTest(r, fpmRoot)
	CorrelateNginxFPMBackends(r)
	EvaluatePatchPosture(r)

	poolVers := map[string]string{}
	for _, e := range r.Evidence {
		if e.Type == "php_fpm_pool_config" {
			poolVers[e.Name] = e.Version
		}
	}
	if poolVers["pool_a"] != "" || poolVers["pool_b"] != "" {
		t.Fatalf("pools must not inherit binary versions: %v", poolVers)
	}
	groups := GroupInstallations(r)
	for _, g := range groups {
		if strings.Contains(g.Label, "pool_a") && strings.Contains(g.Label, "8.4") {
			t.Fatalf("pool_a must not inherit 8.4: %+v", g)
		}
		if strings.Contains(g.Label, "pool_b") && strings.Contains(g.Label, "8.3") {
			t.Fatalf("pool_b must not inherit 8.3: %+v", g)
		}
	}
}

func TestConfiguredInactiveBackendStillCandidateNotVerified(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	fpmRoot := filepath.Join(root, "pool.d")
	// Socket path configured but no process evidence and no live listener check (passive).
	sock := filepath.Join(root, "inactive.sock")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `http { include conf.d/*.conf; }`,
		"conf.d/app.conf": `server { location ~ \.php$ { fastcgi_pass unix:` + sock + `; } }`,
	})
	writeNginxTree(t, fpmRoot, map[string]string{
		"www.conf": "[www]\nlisten = " + sock + "\n",
	})
	r := NewReport("nginx-inactive", "linux", "amd64")
	ParseNginxConfigForTest(r, nginxRoot)
	ParseFPMPoolsForTest(r, fpmRoot)
	CorrelateNginxFPMBackends(r)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	correlated := false
	for _, e := range r.Evidence {
		if e.Type == "nginx_php_handler_config" && strings.Contains(e.Detail, "correlated_fpm_pool=www") {
			correlated = true
		}
	}
	if !correlated {
		t.Fatalf("expected listen correlation without proving activity: %+v", r.Evidence)
	}
	if r.EffectiveWebRuntime != "NOT_VERIFIED" {
		t.Fatalf("inactive backend must leave runtime NOT_VERIFIED, got %s", r.EffectiveWebRuntime)
	}
}

func TestUnreadableFPMConfigMarksIncompleteNotSoftNone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	fpmRoot := filepath.Join(root, "pool.d")
	writeNginxTree(t, fpmRoot, map[string]string{
		"www.conf": "[www]\nlisten = /run/php/php-fpm.sock\n",
		"secret.conf": "[secret]\nlisten = /run/php/secret.sock\n",
	})
	secret := filepath.Join(fpmRoot, "secret.conf")
	if err := os.Chmod(secret, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0644) })
	// If we can still read it (e.g. running as root), skip the assert.
	if _, err := os.ReadFile(secret); err == nil {
		t.Skip("environment can read mode-000 files; cannot assert unreadable skip")
	}

	r := NewReport("fpm-denied", "linux", "amd64")
	r.AddCheck("packages", "PARTIAL", "Found 0")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0")
	r.AddCheck("processes", "PARTIAL", "Found 0")
	ParseFPMPoolsForTest(r, fpmRoot)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	sawSkip := false
	for _, e := range r.Evidence {
		if e.Type == "php_fpm_config_skip" && strings.Contains(e.Location, "secret.conf") {
			sawSkip = true
		}
	}
	if !sawSkip {
		t.Fatalf("expected php_fpm_config_skip: %+v", r.Evidence)
	}
	for _, c := range r.Coverage {
		if c.Name == "php_fpm_configuration" && c.Status != "INCOMPLETE" && c.Status != "TRUNCATED" {
			t.Fatalf("unreadable FPM config should mark incomplete, got %s", c.Status)
		}
	}
	if NoPHPDetectedWithinScanCoverage(r) {
		t.Fatal("must not claim soft no-PHP-within-coverage when FPM config skips remain")
	}
}

func TestSitesEnabledSymlinkWithinRootResolved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	// Real file lives outside seed globs (not conf.d / sites-available); only reachable
	// via sites-enabled symlink — exercises one-hop allowlisted symlink resolve.
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `http { include sites-enabled/*; }`,
		"vhosts/app.conf": `
server {
  server_name app.local;
  location ~ \.php$ { fastcgi_pass unix:/run/php/php-fpm.sock; }
}
`,
	})
	enabled := filepath.Join(nginxRoot, "sites-enabled")
	if err := os.MkdirAll(enabled, 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(nginxRoot, "vhosts", "app.conf")
	link := filepath.Join(enabled, "app.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	r := NewReport("nginx-symlink-site", "linux", "amd64")
	ParseNginxConfigForTest(r, nginxRoot)
	saw := false
	for _, e := range r.Evidence {
		if e.Type == "nginx_php_handler_config" && strings.Contains(e.Detail, "unix:/run/php/php-fpm.sock") {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("Debian-style sites-enabled symlink within root must be followed: %+v", r.Evidence)
	}
}

func TestCLIHTMLAgreeOnLocalRemoteAmbiguous(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	root := t.TempDir()
	nginxRoot := filepath.Join(root, "nginx")
	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `http { include conf.d/*.conf; }`,
		"conf.d/mix.conf": `
upstream php_mixed {
  server 10.0.0.5:9000;
  server 127.0.0.1:9000;
}
server {
  server_name local.example;
  location ~ \.php$ { fastcgi_pass 127.0.0.1:9000; }
}
server {
  server_name remote.example;
  location ~ \.php$ { fastcgi_pass 10.1.1.1:9000; }
}
server {
  server_name amb.example;
  location ~ \.php$ { fastcgi_pass php_mixed; }
}
`,
	})
	r := NewReport("nginx-cli-html", "linux", "amd64")
	ParseNginxConfigForTest(r, nginxRoot)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	html := string(EncodeHTML(r))
	rtLabel, rtDetail := humanRuntime(r)
	if rtLabel == "Verified" {
		t.Fatal(rtLabel)
	}
	if !strings.Contains(html, rtLabel) && !strings.Contains(html, "Candidates") && !strings.Contains(html, "Not verified") {
		t.Fatalf("HTML missing runtime posture; label=%q detail=%q", rtLabel, rtDetail)
	}
	needles := []string{"127.0.0.1:9000", "10.1.1.1:9000", "ambiguous"}
	for _, n := range needles {
		foundEv := false
		for _, e := range r.Evidence {
			if strings.Contains(e.Detail, n) {
				foundEv = true
				break
			}
		}
		if !foundEv {
			t.Fatalf("evidence missing %q: %+v", n, r.Evidence)
		}
		if !strings.Contains(html, n) && n != "ambiguous" {
			// remote/local backends appear in HTML runtime table details
			if n == "10.1.1.1:9000" || n == "127.0.0.1:9000" {
				t.Fatalf("HTML should surface backend %q", n)
			}
		}
	}
	_ = rtDetail
}
