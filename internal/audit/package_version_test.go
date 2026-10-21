package audit

import "testing"

func TestPackagePHPVersionRejectsUbuntuPHPCommon(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"php-common", "2:94ubuntu1", ""},
		{"php-common", "24.04.1", ""},
		{"php-cli", "2:94ubuntu1", ""},
		{"php8.3-common", "8.3.24-1ubuntu1", "8.3.24"},
		{"php8.3-fpm", "8.3.24-1ubuntu1", "8.3.24"},
		{"php8.4-cli", "8.4.11-1", "8.4.11"},
		{"php8.3-mysql", "8.3.24-1ubuntu1", "8.3.24"},
		{"php8.3-fpm", "24.04.1", ""}, // packaging number mismatches package branch
		{"libapache2-mod-php8.3", "8.3.24-1", "8.3.24"},
	}
	for _, tc := range cases {
		if got := PackagePHPVersion(tc.name, tc.raw); got != tc.want {
			t.Fatalf("PackagePHPVersion(%q, %q)=%q want %q", tc.name, tc.raw, got, tc.want)
		}
	}
}

func TestLooksLikePHPReleaseVersion(t *testing.T) {
	if looksLikePHPReleaseVersion("24.04.1") {
		t.Fatal("Ubuntu packaging revision must not look like PHP")
	}
	if !looksLikePHPReleaseVersion("8.3.24") {
		t.Fatal("expected PHP release")
	}
	if looksLikePHPReleaseVersion("8.3") {
		t.Fatal("major.minor alone is not enough")
	}
}

func TestIsPHPExtensionPackage(t *testing.T) {
	if IsPHPExtensionPackage("php8.3-fpm") || IsPHPExtensionPackage("php8.3-cli") || IsPHPExtensionPackage("php8.3-common") {
		t.Fatal("core packages must not be classified as extensions")
	}
	if !IsPHPExtensionPackage("php8.3-mysql") || !IsPHPExtensionPackage("php8.3-opcache") {
		t.Fatal("expected extension classification")
	}
}
