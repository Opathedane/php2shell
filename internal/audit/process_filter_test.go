package audit

import "testing"

func TestIsScannerProcessName(t *testing.T) {
	for _, name := range []string{"php2shell", "php2shell-linux", "php2shell-linux-amd64", "PHP2Shell.exe", "php2shell-windows-amd64.exe"} {
		if !IsScannerProcessName(name) {
			t.Fatalf("expected scanner exclusion for %q", name)
		}
	}
	for _, name := range []string{"php-fpm8.3", "php8.3", "lsphp83", "php-cgi", "w3wp.exe"} {
		if IsScannerProcessName(name) {
			t.Fatalf("must not exclude PHP runtime %q", name)
		}
	}
}

func TestIsPHPRuntimeProcessName(t *testing.T) {
	if IsPHPRuntimeProcessName("php2shell-linux") {
		t.Fatal("scanner must not match as PHP runtime")
	}
	if !IsPHPRuntimeProcessName("php-fpm8.3") {
		t.Fatal("expected php-fpm match")
	}
	if !IsPHPRuntimeProcessName("php8.3") {
		t.Fatal("expected php8.3 match")
	}
	// Overly broad historical matching: anything starting with "php" is no longer enough.
	if IsPHPRuntimeProcessName("phpmyadmin") || IsPHPRuntimeProcessName("phpunit") {
		t.Fatal("non-runtime names must not match")
	}
}
