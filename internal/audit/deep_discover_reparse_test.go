package audit

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// createDirReparse creates a directory junction (Windows mklink /J) or symlink.
// Prefer junctions on Windows: they do not require Developer Mode for local volumes.
func createDirReparse(t *testing.T, link, target string) {
	t.Helper()
	target = filepath.Clean(target)
	link = filepath.Clean(link)
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "mklink", "/J", link, target)
		if out, err := cmd.CombinedOutput(); err == nil {
			return
		} else {
			t.Logf("mklink /J failed (%v): %s; trying os.Symlink", err, strings.TrimSpace(string(out)))
		}
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("directory junction/symlink required for this regression: %v", err)
	}
}

func TestPathUnderAuthorizedWindowsSpelling(t *testing.T) {
	auth := `C:\Temp\PHP`
	if !pathUnderAuthorized(auth, `C:\Temp\PHP\8.4.24`) {
		t.Fatal("child must be under root")
	}
	if !pathUnderAuthorized(auth, `c:/temp/php/current`) {
		t.Fatal("case and slash spelling must still be under root")
	}
	if pathUnderAuthorized(auth, `C:\Temp\PHPish\bin`) {
		t.Fatal("prefix-adjacent path must not count as under root")
	}
	if pathUnderAuthorized(auth, `C:\Temp`) {
		t.Fatal("parent must not count as under root")
	}
	if pathUnderAuthorized(auth, `D:\Temp\PHP\8.4`) {
		t.Fatal("other volume must not count as under root")
	}
	if pathUnderAuthorized(auth, `\\fileserver\share\PHP`) {
		t.Fatal("UNC must not count as under a local root")
	}
}

func TestValidateDeepRootRejectsExtendedUNC(t *testing.T) {
	for _, p := range []string{
		`\\?\UNC\fileserver\share\php`,
		`//?/unc/fileserver/share/php`,
	} {
		if _, err := validateDeepRoot(p); err == nil {
			t.Fatalf("expected reject for %q", p)
		}
	}
}

func TestDeepDiscoverWithinRootAlias(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "8.4.24", "nts", "x64")
	_ = os.MkdirAll(real, 0755)
	bin := filepath.Join(real, phpName("php"))
	writeFakePHP(t, bin, "8.4.24")
	current := filepath.Join(root, "current")
	createDirReparse(t, current, filepath.Join(root, "8.4.24"))

	out := deepDiscoverUnderRoot(root, time.Now().Add(time.Minute), 50, 50)
	saw := false
	for _, b := range out.Binaries {
		if normalizeInstallPath(b) == normalizeInstallPath(bin) {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("within-root current alias must surface binary: binaries=%v skipped_outside=%d skipped_symlink=%d", out.Binaries, out.SkippedOutside, out.SkippedSymlinks)
	}
}

func TestDeepDiscoverOutsideRootReparseSkipped(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outBin := filepath.Join(outside, phpName("php"))
	writeFakePHP(t, outBin, "8.0.0")
	escape := filepath.Join(root, "escape")
	createDirReparse(t, escape, outside)

	inside := filepath.Join(root, "local", phpName("php"))
	writeFakePHP(t, inside, "8.4.24")

	out := deepDiscoverUnderRoot(root, time.Now().Add(time.Minute), 50, 50)
	for _, b := range out.Binaries {
		if normalizeInstallPath(b) == normalizeInstallPath(outBin) {
			t.Fatal("must not follow reparse outside authorized root")
		}
	}
	saw := false
	for _, b := range out.Binaries {
		if normalizeInstallPath(b) == normalizeInstallPath(inside) {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("expected inside binary, got %v skipped_outside=%d", out.Binaries, out.SkippedOutside)
	}
	if out.SkippedOutside < 1 {
		t.Fatalf("expected skipped_outside >= 1, got %+v", out)
	}
}

func TestDeepDiscoverCyclicReparseNoHang(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	_ = os.MkdirAll(filepath.Join(root, "plain"), 0755)
	// Prefer symlink cycle (works on Unix and Windows Developer Mode). Junctions to each other are harder.
	if err := os.Symlink(b, a); err != nil {
		t.Skipf("symlink required for cycle fixture: %v", err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Skipf("symlink required for cycle fixture: %v", err)
	}
	bin := filepath.Join(root, "plain", phpName("php"))
	writeFakePHP(t, bin, "8.4.24")

	done := make(chan deepDiscoverOutcome, 1)
	go func() {
		done <- deepDiscoverUnderRoot(root, time.Now().Add(5*time.Second), 50, 50)
	}()
	select {
	case out := <-done:
		saw := false
		for _, p := range out.Binaries {
			if normalizeInstallPath(p) == normalizeInstallPath(bin) {
				saw = true
			}
		}
		if !saw {
			t.Fatalf("plain sibling binary must still be found despite cycle: %+v", out)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("deep discovery hung on cyclic reparse")
	}
}

func TestDeepDiscoverInaccessibleReparseSkipped(t *testing.T) {
	root := t.TempDir()
	dangling := filepath.Join(root, "broken")
	missing := filepath.Join(root, "does-not-exist-target")
	if err := os.Symlink(missing, dangling); err != nil {
		t.Skipf("symlink required: %v", err)
	}
	bin := filepath.Join(root, "ok", phpName("php"))
	writeFakePHP(t, bin, "8.3.36")

	out := deepDiscoverUnderRoot(root, time.Now().Add(time.Minute), 50, 50)
	saw := false
	for _, p := range out.Binaries {
		if normalizeInstallPath(p) == normalizeInstallPath(bin) {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("accessible binary must remain discoverable: %+v", out)
	}
	if out.SkippedSymlinks < 1 {
		t.Fatalf("expected skipped_symlink for dangling reparse, got %+v", out)
	}
}
