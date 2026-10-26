package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWindowsWellKnownGlobsIncludeWampLaragonTools(t *testing.T) {
	globs := windowsWellKnownPHPGlobs()
	joined := strings.Join(globs, "\n")
	for _, need := range []string{
		`C:\wamp\bin\php\*\php.exe`,
		`C:\wamp64\bin\php\*\php.exe`,
		`C:\laragon\bin\php\*\php.exe`,
		`C:\tools\php\php.exe`,
		`C:\xampp\php\php.exe`,
	} {
		if !strings.Contains(joined, need) {
			t.Fatalf("missing well-known glob %q in %v", need, globs)
		}
	}
}

func TestLinuxWellKnownGlobsIncludeRemiCpanelLocalOpt(t *testing.T) {
	globs := linuxWellKnownPHPGlobs()
	joined := strings.Join(globs, "\n")
	for _, need := range []string{
		`/opt/remi/php*/root/usr/sbin/php-fpm*`,
		`/opt/cpanel/ea-php*/root/usr/sbin/php-fpm*`,
		`/usr/local/php*/bin/php*`,
		`/opt/php/*/bin/php*`,
		`/opt/plesk/php/*/bin/php*`,
	} {
		if !strings.Contains(joined, need) {
			t.Fatalf("missing well-known glob %q in %v", need, globs)
		}
	}
}

func TestWindowsStackFixtureDiscoveryViaGlob(t *testing.T) {
	// Simulate WAMP/Laragon/tools layouts under a temp drive-like root using Glob semantics.
	// Includes both bare X.Y.Z and WampServer phpX.Y.Z directory names.
	root := t.TempDir()
	layouts := []string{
		filepath.Join(root, "wamp", "bin", "php", "8.2.28", "php.exe"),
		filepath.Join(root, "wamp64", "bin", "php", "php7.4.33", "php.exe"),
		filepath.Join(root, "wamp64", "bin", "php", "8.3.36", "php-cgi.exe"),
		filepath.Join(root, "laragon", "bin", "php", "8.4.24", "php.exe"),
		filepath.Join(root, "tools", "php", "8.4.24", "php.exe"),
	}
	for _, p := range layouts {
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		_ = os.WriteFile(p, []byte("MZ PHP Version 8.4.24\x00"), 0644)
	}
	patterns := []string{
		filepath.Join(root, "wamp", "bin", "php", "*", "php.exe"),
		filepath.Join(root, "wamp64", "bin", "php", "*", "php.exe"),
		filepath.Join(root, "wamp64", "bin", "php", "*", "php-cgi.exe"),
		filepath.Join(root, "laragon", "bin", "php", "*", "php.exe"),
		filepath.Join(root, "tools", "php", "*", "php.exe"),
	}
	found := map[string]bool{}
	for _, pat := range patterns {
		matches, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range matches {
			found[normalizeInstallPath(m)] = true
		}
	}
	if len(found) != 5 {
		t.Fatalf("expected 5 stack binaries via bounded globs, got %d (%v)", len(found), found)
	}
	wampPHP := filepath.Join(root, "wamp64", "bin", "php", "php7.4.33", "php.exe")
	v, _ := VersionFromInstallPath(wampPHP)
	if v != "7.4.33" {
		t.Fatalf("phpX.Y.Z glob hit must still path-infer: %q", v)
	}
}

func TestLinuxStackFixtureDiscoveryViaGlob(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Slash patterns still work with filepath.Glob on Windows for temp fixtures.
	}
	root := t.TempDir()
	layouts := []string{
		filepath.Join(root, "opt", "remi", "php83", "root", "usr", "sbin", "php-fpm"),
		filepath.Join(root, "opt", "cpanel", "ea-php82", "root", "usr", "sbin", "php-fpm"),
		filepath.Join(root, "usr", "local", "php8.4", "bin", "php"),
		filepath.Join(root, "opt", "php", "8.3.36", "bin", "php"),
	}
	for _, p := range layouts {
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		_ = os.WriteFile(p, []byte("ELF PHP Version 8.3.36\x00"), 0755)
	}
	patterns := []string{
		filepath.Join(root, "opt", "remi", "php*", "root", "usr", "sbin", "php-fpm*"),
		filepath.Join(root, "opt", "cpanel", "ea-php*", "root", "usr", "sbin", "php-fpm*"),
		filepath.Join(root, "usr", "local", "php*", "bin", "php*"),
		filepath.Join(root, "opt", "php", "*", "bin", "php*"),
	}
	found := 0
	for _, pat := range patterns {
		matches, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		found += len(matches)
	}
	if found < 4 {
		t.Fatalf("expected >=4 linux stack hits, got %d", found)
	}
}

func TestPEVersionDoesNotTreatCOFFTimestampAsPHPBuildDate(t *testing.T) {
	// Guardrail: PE discovery uses COFF only for structure offsets, never as a PHP release date.
	src, err := os.ReadFile("pe_version.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if strings.Contains(text, "TimeDateStamp") && strings.Contains(strings.ToLower(text), "build date") {
		t.Fatal("PE path must not treat COFF TimeDateStamp as PHP build date")
	}
	if !strings.Contains(text, "eLfanew") && !strings.Contains(text, "coff") {
		t.Fatal("expected PE structure parsing via COFF offsets")
	}
}
