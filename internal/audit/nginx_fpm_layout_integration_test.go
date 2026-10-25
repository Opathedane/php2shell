package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Realistic Debian/RHEL-style directory layouts (not live nginx/php-fpm processes).
// These fixtures mirror production filesystem shapes: sites-enabled symlinks,
// conf.d snippets, versioned pool.d trees, and mixed backends. The scanner remains
// passive — no nginx/php-fpm binaries are started and no sockets are dialed.
//
// Classification:
//   - REALISTIC_LAYOUT: this file
//   - SYNTHETIC_UNIT: nginx_fpm_test.go / nginx_fpm_review_test.go
// Live process / container integration is out of scope on this agent (no docker/nginx).

func buildDebianStyleNginxFPMLayout(t *testing.T) (nginxRoot, fpm83, fpm84, sock83, sock84, remoteNote string) {
	t.Helper()
	root := t.TempDir()
	nginxRoot = filepath.Join(root, "etc", "nginx")
	fpm83 = filepath.Join(root, "etc", "php", "8.3", "fpm", "pool.d")
	fpm84 = filepath.Join(root, "etc", "php", "8.4", "fpm", "pool.d")
	run := filepath.Join(root, "run", "php")
	if err := os.MkdirAll(run, 0755); err != nil {
		t.Fatal(err)
	}
	sock83 = filepath.Join(run, "php8.3-fpm.sock")
	sock84 = filepath.Join(run, "php8.4-fpm.sock")
	// Socket files may or may not exist; scanner must not require them.
	_ = os.WriteFile(sock83, []byte{}, 0644)

	writeNginxTree(t, nginxRoot, map[string]string{
		"nginx.conf": `
user www-data;
http {
  include /mime.types;
  include conf.d/*.conf;
  include sites-enabled/*;
}
`,
		"conf.d/gzip.conf": `gzip on;`,
		"sites-available/app83.conf": `
server {
  listen 80;
  server_name app83.example.local;
  root /var/www/app83;
  location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:` + sock83 + `;
  }
}
`,
		"sites-available/app84.conf": `
server {
  listen 80;
  server_name app84.example.local;
  root /var/www/app84;
  location ~ \.php$ {
    fastcgi_pass 127.0.0.1:9084;
  }
}
`,
		"sites-available/remote.conf": `
server {
  listen 80;
  server_name remote.example.local;
  root /var/www/remote;
  location ~ \.php$ {
    fastcgi_pass 10.20.30.40:9000;
  }
}
`,
		"sites-available/static.conf": `
server {
  listen 80;
  server_name static.example.local;
  root /var/www/static;
  location / { try_files $uri =404; }
}
`,
		"snippets/fastcgi-php.conf": `
fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
include fastcgi_params;
`,
	})
	enabled := filepath.Join(nginxRoot, "sites-enabled")
	if err := os.MkdirAll(enabled, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"app83.conf", "app84.conf", "remote.conf", "static.conf"} {
		if err := os.Symlink(filepath.Join(nginxRoot, "sites-available", name), filepath.Join(enabled, name)); err != nil {
			t.Fatal(err)
		}
	}

	writeNginxTree(t, fpm83, map[string]string{
		"www.conf": "[www]\nlisten = " + sock83 + "\n",
		"unused.conf": "[unused]\nlisten = " + filepath.Join(run, "unused.sock") + "\n",
	})
	writeNginxTree(t, fpm84, map[string]string{
		"www.conf": "[www84]\nlisten = 127.0.0.1:9084\n",
	})
	// Parent php-fpm.conf include (Debian).
	writeNginxTree(t, filepath.Dir(fpm83), map[string]string{
		"php-fpm.conf": "[global]\ninclude=" + fpm83 + "/*.conf\n",
	})
	remoteNote = "10.20.30.40:9000"
	return nginxRoot, fpm83, fpm84, sock83, sock84, remoteNote
}

func TestIntegrationDebianStyleLocalUnixTCPRemoteMultiPool(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	nginxRoot, fpm83, fpm84, sock83, _, remote := buildDebianStyleNginxFPMLayout(t)

	r := NewReport("layout-debian", "linux", "amd64")
	// Unrelated CLI install — must not become the web handler version.
	r.AddEvidence(Evidence{
		Type: "binary_static_version", Name: "php", Version: "8.2.35",
		Source: "unrelated CLI", Location: "/usr/bin/php",
		Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
	})
	ParseNginxConfigForTest(r, nginxRoot)
	ParseFPMPoolsForTest(r, fpm83, fpm84)
	CorrelateNginxFPMBackends(r)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	var (
		localUnix, localTCP, remoteHit, correlated, staticSite bool
		pools                                                  = map[string]bool{}
	)
	for _, e := range r.Evidence {
		switch e.Type {
		case "nginx_php_handler_config":
			if strings.Contains(e.Detail, "unix:"+sock83) && strings.Contains(e.Detail, "scope=local_candidate") {
				localUnix = true
				if strings.Contains(e.Detail, "correlated_fpm_pool=") {
					correlated = true
				}
			}
			if strings.Contains(e.Detail, "127.0.0.1:9084") {
				localTCP = true
			}
			if e.Version != "" {
				t.Fatalf("handler must not carry version: %+v", e)
			}
		case "nginx_remote_php_backend":
			if strings.Contains(e.Detail, remote) {
				remoteHit = true
			}
			if e.Version != "" {
				t.Fatalf("remote must not inherit CLI version: %+v", e)
			}
		case "nginx_site_config":
			if e.Name == "static.example.local" {
				staticSite = true
			}
		case "php_fpm_pool_config":
			pools[e.Name] = true
			if e.Version != "" {
				t.Fatalf("pool must not inherit version: %+v", e)
			}
		}
	}
	if !localUnix || !localTCP || !remoteHit {
		t.Fatalf("localUnix=%v localTCP=%v remote=%v evidence=%+v", localUnix, localTCP, remoteHit, r.Evidence)
	}
	if !correlated {
		t.Fatalf("expected unix socket correlation: %+v", r.Evidence)
	}
	if !pools["www"] || !pools["www84"] || !pools["unused"] {
		t.Fatalf("expected distinct pools including unused, got %v", pools)
	}
	if !staticSite {
		t.Fatal("static vhost should still appear as site config without PHP handler invent")
	}
	if r.EffectiveWebRuntime == "VERIFIED" {
		t.Fatal("layout inventory must not verify runtime")
	}
	for _, c := range r.Coverage {
		if c.Name == "nginx_configuration" && c.Status != "INCOMPLETE" {
			t.Fatalf("remote backend requires INCOMPLETE, got %s", c.Status)
		}
	}
}

func TestIntegrationInaccessiblePoolAndUnrelatedPHP(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM discovery is Unix-focused")
	}
	nginxRoot, fpm83, _, _, _, _ := buildDebianStyleNginxFPMLayout(t)
	denied := filepath.Join(fpm83, "denied.conf")
	if err := os.WriteFile(denied, []byte("[denied]\nlisten = /run/php/denied.sock\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(denied, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied, 0644) })
	if _, err := os.ReadFile(denied); err == nil {
		t.Skip("environment can read mode-000 files")
	}

	r := NewReport("layout-denied", "linux", "amd64")
	r.AddEvidence(Evidence{
		Type: "binary_static_version", Name: "php", Version: "8.3.36",
		Source: "unrelated", Location: "/opt/tools/php",
		Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
	})
	ParseNginxConfigForTest(r, nginxRoot)
	ParseFPMPoolsForTest(r, fpm83)
	CorrelateNginxFPMBackends(r)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	sawSkip := false
	for _, e := range r.Evidence {
		if e.Type == "php_fpm_config_skip" {
			sawSkip = true
		}
		if e.Type == "nginx_php_handler_config" && e.Version == "8.3.36" {
			t.Fatal("unrelated PHP binary version must not attach to nginx handler")
		}
	}
	if !sawSkip {
		t.Fatal("expected inaccessible pool skip evidence")
	}
	if NoPHPDetectedWithinScanCoverage(r) {
		t.Fatal("PHP binary present — must not soft-none")
	}
}
