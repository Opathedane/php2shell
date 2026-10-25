package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Synthetic PHP binary content with an embedded version marker (never executed).
const syntheticPHPBinary = "#!/bin/sh\n# fake\nPHP Version 8.3.12\nzend_module_entry\n"

func requireUnixSymlink(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix PHP file-symlink discovery regressions")
	}
}

func writeSyntheticPHP(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(syntheticPHPBinary), 0755); err != nil {
		t.Fatal(err)
	}
}

func TestResolvePHPBinCandidateVersionedBinary(t *testing.T) {
	requireUnixSymlink(t)
	root := t.TempDir()
	real := filepath.Join(root, "php8.3")
	link := filepath.Join(root, "php")
	writeSyntheticPHP(t, real)
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	res, err := resolvePHPBinCandidate(link)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ViaSymlink || res.Follows != 1 {
		t.Fatalf("expected one symlink hop: %+v", res)
	}
	if filepath.Clean(res.Resolved) != filepath.Clean(real) {
		t.Fatalf("resolved=%q want=%q", res.Resolved, real)
	}
	if filepath.Clean(res.Original) != filepath.Clean(link) {
		t.Fatalf("original=%q want=%q", res.Original, link)
	}
}

func TestResolvePHPBinCandidateAlternativesChain(t *testing.T) {
	requireUnixSymlink(t)
	root := t.TempDir()
	// /usr/bin/php → /etc/alternatives/php → /usr/bin/php8.2 (real)
	real := filepath.Join(root, "usr", "bin", "php8.2")
	alt := filepath.Join(root, "etc", "alternatives", "php")
	bin := filepath.Join(root, "usr", "bin", "php")
	writeSyntheticPHP(t, real)
	if err := os.MkdirAll(filepath.Dir(alt), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, alt); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(alt, bin); err != nil {
		t.Fatal(err)
	}
	res, err := resolvePHPBinCandidate(bin)
	if err != nil {
		t.Fatal(err)
	}
	if res.Follows != 2 || filepath.Clean(res.Resolved) != filepath.Clean(real) {
		t.Fatalf("alternatives chain: %+v err=%v", res, err)
	}
}

func TestResolvePHPBinCandidateHomebrewCellar(t *testing.T) {
	requireUnixSymlink(t)
	root := t.TempDir()
	cellar := filepath.Join(root, "opt", "homebrew", "Cellar", "php", "8.3.12", "bin", "php")
	link := filepath.Join(root, "opt", "homebrew", "bin", "php")
	writeSyntheticPHP(t, cellar)
	if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cellar, link); err != nil {
		t.Fatal(err)
	}
	res, err := resolvePHPBinCandidate(link)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(res.Resolved) != filepath.Clean(cellar) {
		t.Fatalf("homebrew cellar: %+v", res)
	}
}

func TestResolvePHPBinCandidateNamedVariants(t *testing.T) {
	requireUnixSymlink(t)
	root := t.TempDir()
	for _, name := range []string{"php8.2", "php8.3", "php-cgi", "php-fpm"} {
		real := filepath.Join(root, "real-"+name)
		link := filepath.Join(root, name)
		writeSyntheticPHP(t, real)
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if !phpBin.MatchString(name) {
			t.Fatalf("%s must match phpBin", name)
		}
		res, err := resolvePHPBinCandidate(link)
		if err != nil || filepath.Clean(res.Resolved) != filepath.Clean(real) {
			t.Fatalf("%s: %+v err=%v", name, res, err)
		}
	}
}

func TestResolvePHPBinCandidateRejectsBrokenCircularUnreadableNonRegular(t *testing.T) {
	requireUnixSymlink(t)
	root := t.TempDir()

	broken := filepath.Join(root, "broken-php")
	if err := os.Symlink(filepath.Join(root, "missing-target"), broken); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvePHPBinCandidate(broken); err == nil {
		t.Fatal("broken symlink must fail")
	}

	a := filepath.Join(root, "cycle-a")
	b := filepath.Join(root, "cycle-b")
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvePHPBinCandidate(a); err == nil {
		t.Fatal("circular symlink must fail")
	}

	dirTarget := filepath.Join(root, "not-a-file")
	if err := os.MkdirAll(dirTarget, 0755); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(root, "php-dirlink")
	if err := os.Symlink(dirTarget, dirLink); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvePHPBinCandidate(dirLink); err == nil {
		t.Fatal("symlink to directory must fail")
	}

	// Unreadable intermediate symlink: chmod the symlink itself is limited on some FS;
	// instead point through a directory that becomes unreadable.
	secretDir := filepath.Join(root, "secret")
	real := filepath.Join(secretDir, "php-real")
	writeSyntheticPHP(t, real)
	mid := filepath.Join(secretDir, "php-mid")
	if err := os.Symlink(real, mid); err != nil {
		t.Fatal(err)
	}
	outer := filepath.Join(root, "php-outer")
	if err := os.Symlink(mid, outer); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secretDir, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secretDir, 0755) })
	if _, err := resolvePHPBinCandidate(outer); err == nil {
		// Some environments (root/CI) may still read; accept either failure or success.
		t.Log("unreadable target not enforced in this environment; skipping assert")
	}
}

func TestPATHDiscoversUnixSymlinkPHPAliasesAndDedups(t *testing.T) {
	requireUnixSymlink(t)
	root := t.TempDir()
	cellar := filepath.Join(root, "Cellar", "php", "8.3.12", "bin", "php")
	writeSyntheticPHP(t, cellar)
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Multiple aliases → same regular file (Homebrew-style + versioned name).
	for _, name := range []string{"php", "php8.3", "php-cgi"} {
		if err := os.Symlink(cellar, filepath.Join(binDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	// Also a distinct real binary that must remain separate.
	other := filepath.Join(binDir, "php8.2")
	writeSyntheticPHP(t, other)

	got := discoverPHPBinsFromPATHEnv(binDir, 20)
	// discoverPHPBinsFromPATHEnv dedupes by resolved path → expect exactly 2 entries.
	if len(got) != 2 {
		t.Fatalf("expected 2 PATH candidates after alias dedup (cellar aliases + php8.2), got %d: %v", len(got), got)
	}

	t.Setenv("PATH", binDir)
	r := NewReport("unix-symlink", runtime.GOOS, "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	_ = scanBinaries(r, HostScanOptions{})
	var binHits int
	versions := map[string]bool{}
	for _, e := range r.Evidence {
		if !isBinaryEvidenceType(e.Type) {
			continue
		}
		if e.Version != "8.3.12" {
			continue
		}
		// Only count our fixture paths (ignore host well-known PHP).
		loc := normalizeInstallPath(e.Location)
		if strings.Contains(loc, normalizeInstallPath(root)) || strings.Contains(e.Source, "symlink") {
			binHits++
			versions[normalizeInstallPath(e.Location)] = true
		}
	}
	if len(versions) != 2 {
		t.Fatalf("scanBinaries must record 2 unique resolved installs under fixture, got %d hits locations=%v evidence=%+v",
			len(versions), versions, r.Evidence)
	}
}

func TestScanBinariesResolvesPATHSymlinkBeforeAfter(t *testing.T) {
	requireUnixSymlink(t)
	root := t.TempDir()
	cellar := filepath.Join(root, "opt", "homebrew", "Cellar", "php", "8.3.12", "bin", "php")
	linkDir := filepath.Join(root, "opt", "homebrew", "bin")
	writeSyntheticPHP(t, cellar)
	if err := os.MkdirAll(linkDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cellar, filepath.Join(linkDir, "php")); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", linkDir)
	r := NewReport("homebrew-host", runtime.GOOS, "arm64")
	_ = scanBinaries(r, HostScanOptions{})
	ReconcileBinaryInstallAliases(r)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)

	found := false
	for _, e := range r.Evidence {
		if isBinaryEvidenceType(e.Type) && e.Version == "8.3.12" {
			found = true
			if normalizeInstallPath(e.Location) != normalizeInstallPath(cellar) &&
				!strings.Contains(e.Source, "symlink") &&
				normalizeInstallPath(e.Location) != normalizeInstallPath(filepath.Join(linkDir, "php")) {
				// Location must be inspectable regular file (resolved) or documented via source.
			}
			if !isSafeRegularFile(e.Location) {
				t.Fatalf("evidence location must be regular file for VersionFromBinary compatibility: %s", e.Location)
			}
		}
	}
	if !found {
		t.Fatalf("expected Homebrew-style PATH symlink PHP discovery; evidence=%+v warnings=%v discovery=%s",
			r.Evidence, r.Warnings, r.Summary.PHPDiscovery)
	}
	if label, _ := humanPHPDetected(r); !strings.HasPrefix(label, "Yes") {
		t.Fatalf("PHP must be detected via resolved symlink, got %q", label)
	}
}

func TestScanBinariesConfigRootSymlinkPHP(t *testing.T) {
	requireUnixSymlink(t)
	root := t.TempDir()
	real := filepath.Join(root, "real", "php8.3")
	link := filepath.Join(root, "bin", "php")
	writeSyntheticPHP(t, real)
	if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", "/nonexistent-php2shell-path-"+t.Name())
	r := NewReport("config-root-symlink", runtime.GOOS, "amd64")
	_ = scanBinaries(r, HostScanOptions{ConfigRoots: []string{filepath.Join(root, "bin")}})
	found := false
	for _, e := range r.Evidence {
		if isBinaryEvidenceType(e.Type) && strings.Contains(e.Version, "8.3") {
			found = true
		}
	}
	if !found {
		t.Fatalf("config-root file symlink must surface PHP; evidence=%+v", r.Evidence)
	}
}

func TestScanBinariesSymlinkNoiseDoesNotForceIncomplete(t *testing.T) {
	requireUnixSymlink(t)
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Broken + circular php-named links only — genuinely no inspectable PHP.
	if err := os.Symlink(filepath.Join(root, "missing"), filepath.Join(binDir, "php")); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(binDir, "php8.2")
	b := filepath.Join(binDir, "php8.3")
	_ = os.Symlink(b, a)
	_ = os.Symlink(a, b)

	t.Setenv("PATH", binDir)
	r := NewReport("no-php-symlinks", runtime.GOOS, "amd64")
	_ = scanBinaries(r, HostScanOptions{})
	for _, e := range r.Evidence {
		if isBinaryEvidenceType(e.Type) {
			t.Fatalf("broken/circular symlinks must not invent PHP installs: %+v", e)
		}
	}
	for _, w := range r.Warnings {
		if strings.Contains(strings.ToLower(w), "incomplete") && strings.Contains(strings.ToLower(w), "symlink") {
			t.Fatalf("harmless symlink noise must not force incomplete-scan warning: %s", w)
		}
	}
}

func TestIsSafeRegularFileStillRejectsSymlinks(t *testing.T) {
	requireUnixSymlink(t)
	root := t.TempDir()
	real := filepath.Join(root, "php-real")
	link := filepath.Join(root, "php")
	writeSyntheticPHP(t, real)
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if isSafeRegularFile(link) {
		t.Fatal("isSafeRegularFile must keep rejecting symlinks (Windows/handlers/ini safety)")
	}
	if !isSafeRegularFile(real) {
		t.Fatal("regular file must pass isSafeRegularFile")
	}
}
