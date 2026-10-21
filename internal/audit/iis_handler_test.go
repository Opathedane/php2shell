package audit

import (
	"os"
	"path/filepath"
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

func TestIISFixturesScriptProcessorVariants(t *testing.T) {
	fixtures := []string{
		"testdata/iis/applicationhost-fastcgi-pipe.xml",
		"testdata/iis/applicationhost-quoted-path.xml",
		"testdata/iis/applicationhost-env-path.xml",
	}
	for _, path := range fixtures {
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
		if !HandlerExecutableLooksLikePHP(exe) && !HandlerExecutableLooksLikePHP(ResolveHandlerExecutablePath(exe)) {
			t.Fatalf("%s: unexpected exe %q detail=%q", path, exe, entries[0].Detail)
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
		t.Fatalf("resolved %q want %q", resolved, fake)
	}
	ver, _, cov, err := VersionFromBinary(resolved)
	if err != nil || ver != "8.4.27" {
		t.Fatalf("version %q cov=%+v err=%v", ver, cov, err)
	}
}
