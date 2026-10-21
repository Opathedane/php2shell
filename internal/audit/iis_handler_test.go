package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseIISScriptProcessorPipeAndQuotes(t *testing.T) {
	exe, args := ParseIISScriptProcessor(`"C:\Program Files\PHP\8.4\php-cgi.exe"|"-d" "display_errors=0"`)
	if exe != `C:\Program Files\PHP\8.4\php-cgi.exe` || args == "" {
		t.Fatalf("got exe=%q args=%q", exe, args)
	}
	exe, args = ParseIISScriptProcessor(`C:\PHP\php-cgi.exe|-d open_basedir=C:\inetpub`)
	if exe != `C:\PHP\php-cgi.exe` || args != `-d open_basedir=C:\inetpub` {
		t.Fatalf("got exe=%q args=%q", exe, args)
	}
	exe, _ = ParseIISScriptProcessor(`C:\PHP\php-cgi.exe`)
	if exe != `C:\PHP\php-cgi.exe` {
		t.Fatal(exe)
	}
}

func TestHandlerExecutableFromDetail(t *testing.T) {
	detail := FormatIISHandlerDetail("*.php", "FastCgiModule", `C:\PHP\php-cgi.exe|-d foo=bar`)
	if got := HandlerExecutableFromDetail(detail); got != `C:\PHP\php-cgi.exe` {
		t.Fatal(got)
	}
}

func TestExpandWindowsPercentEnv(t *testing.T) {
	t.Setenv("PHP2SHELL_TEST_PHPROOT", "/tmp/phproot")
	got := expandWindowsPercentEnv(`%PHP2SHELL_TEST_PHPROOT%\php-cgi.exe`)
	want := `/tmp/phproot\php-cgi.exe`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if expandWindowsPercentEnv(`%UNSET_PHP2SHELL_TEST_VAR_xyz%`) != `%UNSET_PHP2SHELL_TEST_VAR_xyz%` {
		t.Fatal("unset var should remain literal")
	}
}

func TestIISFixturesScriptProcessorVariants(t *testing.T) {
	fixtures := []string{
		"iis/applicationhost-fastcgi-pipe.xml",
		"iis/applicationhost-quoted-path.xml",
		"iis/applicationhost-env-path.xml",
	}
	for _, rel := range fixtures {
		if rel == "iis/applicationhost-env-path.xml" {
			t.Setenv("PHP2SHELL_TEST_PHPROOT", t.TempDir())
		}
		path := moduleTestdataPath(t, rel)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		entries, err := parseIISHandlers(path, b)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if len(entries) == 0 {
			t.Fatalf("no handlers in %s", path)
		}
		exe := HandlerExecutableFromDetail(entries[0].Detail)
		resolved := ResolveHandlerExecutablePath(exe)
		candidate := exe
		if resolved != "" {
			candidate = resolved
		}
		if !HandlerExecutableLooksLikePHP(candidate) {
			t.Fatalf("%s: unexpected exe %q resolved %q detail=%q", path, exe, resolved, entries[0].Detail)
		}
	}
}

func TestResolveHandlerExecutablePathEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PHP2SHELL_TEST_PHPROOT", dir)
	fake := filepath.Join(dir, "php-cgi.exe")
	if err := os.WriteFile(fake, []byte("PHP Version 8.4.27"), 0600); err != nil {
		t.Fatal(err)
	}
	raw := `%PHP2SHELL_TEST_PHPROOT%\php-cgi.exe|-d display_errors=0`
	exe, _ := ParseIISScriptProcessor(raw)
	resolved := ResolveHandlerExecutablePath(exe)
	if filepath.Clean(resolved) != filepath.Clean(fake) {
		t.Fatalf("resolved %q want %q (GOOS=%s)", resolved, fake, runtime.GOOS)
	}
	ver, _, cov, err := VersionFromBinary(resolved)
	if err != nil || ver != "8.4.27" {
		t.Fatalf("version %q cov=%+v err=%v", ver, cov, err)
	}
}

func TestResolveHandlerExecutablePathBlocksShell(t *testing.T) {
	if got := ResolveHandlerExecutablePath(`C:\Windows\System32\cmd.exe /c php.exe`); got != "" {
		t.Fatal(got)
	}
}

func TestWindowsPathBaseCrossPlatform(t *testing.T) {
	cases := []struct {
		path, want string
	}{
		{`C:\Program Files\PHP\8.4\php-cgi.exe`, `php-cgi.exe`},
		{`C:/PHP/php-cgi.exe`, `php-cgi.exe`},
		{`php-cgi.exe`, `php-cgi.exe`},
		{`\\?\C:\PHP\php-cgi.exe`, `php-cgi.exe`},
	}
	for _, tc := range cases {
		if got := windowsPathBase(tc.path); got != tc.want {
			t.Fatalf("windowsPathBase(%q) = %q want %q", tc.path, got, tc.want)
		}
	}
}

func TestHandlerExecutableLooksLikePHPWindowsPaths(t *testing.T) {
	if !HandlerExecutableLooksLikePHP(`C:\inetpub\php\php-cgi.exe`) {
		t.Fatal("expected php-cgi on Windows-style path")
	}
	if HandlerExecutableLooksLikePHP(`C:\Windows\System32\cmd.exe`) {
		t.Fatal("cmd.exe should not match php binary pattern")
	}
}

func TestConfiguredWindowsHandlerPathMixedSeparators(t *testing.T) {
	got := ConfiguredWindowsHandlerPath(`C:/Program Files/PHP\8.4/php-cgi.exe`)
	want := `C:\Program Files\PHP\8.4\php-cgi.exe`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestResolveHandlerExecutablePathDriveLetterNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("drive-letter resolution differs on Windows")
	}
	if got := ResolveHandlerExecutablePath(`C:\PHP\php-cgi.exe`); got != "" {
		t.Fatalf("expected empty local path on %s, got %q", runtime.GOOS, got)
	}
}

func TestResolveHandlerExecutablePathMixedSeparatorsAfterEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses Unix-style env expansion fixture")
	}
	dir := t.TempDir()
	t.Setenv("PHP2SHELL_TEST_PHPROOT", dir)
	fake := filepath.Join(dir, "php-cgi.exe")
	if err := os.WriteFile(fake, []byte("stub"), 0600); err != nil {
		t.Fatal(err)
	}
	exe, _ := ParseIISScriptProcessor(`%PHP2SHELL_TEST_PHPROOT%/php-cgi.exe`)
	resolved := ResolveHandlerExecutablePath(exe)
	if filepath.Clean(resolved) != filepath.Clean(fake) {
		t.Fatalf("resolved %q want %q", resolved, fake)
	}
}
