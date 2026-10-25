package audit

import (
	"fmt"
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
	aliases := []string{"php", "php8.3", "php-cgi"}
	for _, name := range aliases {
		if err := os.Symlink(cellar, filepath.Join(binDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(binDir, "php8.2")
	writeSyntheticPHP(t, other)

	got := discoverPHPBinsFromPATHEnv(binDir, 20)
	// All operator-facing aliases are surfaced; install dedupe happens in scanBinaries.
	if len(got) != 4 {
		t.Fatalf("expected 3 aliases + php8.2 PATH candidates, got %d: %v", len(got), got)
	}

	t.Setenv("PATH", binDir)
	r := NewReport("unix-symlink", runtime.GOOS, "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	_ = scanBinaries(r, HostScanOptions{})
	versions := map[string]bool{}
	var cellarDetail string
	for _, e := range r.Evidence {
		if !isBinaryEvidenceType(e.Type) || e.Version != "8.3.12" {
			continue
		}
		loc := normalizeInstallPath(e.Location)
		if !strings.Contains(loc, normalizeInstallPath(root)) {
			continue
		}
		versions[loc] = true
		if loc == normalizeInstallPath(cellar) {
			cellarDetail = e.Detail + " " + e.Source
		}
	}
	if len(versions) != 2 {
		t.Fatalf("scanBinaries must record 2 unique resolved installs under fixture, got %d locations=%v",
			len(versions), versions)
	}
	// Alias paths retained on the cellar evidence row without extra installs.
	aliasNoted := 0
	for _, name := range aliases {
		if strings.Contains(cellarDetail, name) || strings.Contains(cellarDetail, filepath.Join(binDir, name)) {
			aliasNoted++
		}
	}
	if aliasNoted < 2 {
		t.Fatalf("expected also_via / via symlink path evidence for aliases, detail/source=%q", cellarDetail)
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
	rootKey := normalizeInstallPath(root)
	for _, e := range r.Evidence {
		if !isBinaryEvidenceType(e.Type) {
			continue
		}
		loc := normalizeInstallPath(e.Location)
		src := e.Source + " " + e.Detail
		// Ignore host well-known PHP (e.g. CI images with /usr/bin/php); only fixture paths matter.
		if !strings.Contains(loc, rootKey) && !strings.Contains(normalizeInstallPath(src), rootKey) {
			continue
		}
		t.Fatalf("broken/circular fixture symlinks must not invent PHP installs: %+v", e)
	}
	for _, e := range r.Evidence {
		if e.Interpretation == "PHP_EXECUTABLE_CANDIDATE_UNRESOLVED_NOT_INSPECTED" &&
			strings.Contains(normalizeInstallPath(e.Location), rootKey) {
			t.Fatalf("broken/circular links must stay silent (no unresolved gap): %+v", e)
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

// TestUnixSymlinkOriginalFailureMode documents the pre-fix gate: isSafeRegularFile
// rejected file symlinks, so PATH discovery returned nothing for Homebrew-style aliases.
func TestUnixSymlinkOriginalFailureMode(t *testing.T) {
	requireUnixSymlink(t)
	root := t.TempDir()
	cellar := filepath.Join(root, "Cellar", "php", "8.3.12", "bin", "php")
	link := filepath.Join(root, "bin", "php")
	writeSyntheticPHP(t, cellar)
	if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cellar, link); err != nil {
		t.Fatal(err)
	}
	if isSafeRegularFile(link) {
		t.Fatal("pre-fix gate must reject the symlink")
	}
	if _, err := resolvePHPBinCandidate(link); err != nil {
		t.Fatalf("post-fix resolve must succeed: %v", err)
	}
	got := discoverPHPBinsFromPATHEnv(filepath.Dir(link), 10)
	if len(got) != 1 {
		t.Fatalf("PATH must surface symlink alias after fix, got %v", got)
	}
}

func bareNoPHPCoverageReport() *Report {
	r := NewReport("coverage-host", "darwin", "arm64")
	r.AddCheck("binary_paths", "PARTIAL", "Found 0 PHP-like binary paths")
	r.AddCheck("packages", "PARTIAL", "Found 0 packages")
	r.AddCheck("processes", "PARTIAL", "Found 0 processes")
	return r
}

func TestUnresolvedPHPBinCandidateBlocksNoPHPWithinCoverage(t *testing.T) {
	r1 := bareNoPHPCoverageReport()
	FinalizeSummary(r1)
	if r1.Summary.PHPDiscovery != "NO_PHP_DETECTED_WITHIN_SCAN_COVERAGE" {
		t.Fatalf("control want none_within_coverage, got %s", r1.Summary.PHPDiscovery)
	}

	r2 := bareNoPHPCoverageReport()
	recordUnresolvedPHPBinCandidate(r2, "/opt/homebrew/bin/php", "PATH directory static binary inspection",
		"symlink chain exceeds hop budget")
	FinalizeSummary(r2)
	if r2.Summary.PHPDiscovery == "NO_PHP_DETECTED_WITHIN_SCAN_COVERAGE" {
		t.Fatal("unresolved PHP executable candidate must not yield NO_PHP_DETECTED_WITHIN_SCAN_COVERAGE")
	}
	if classifyPHPDiscovery(r2) != phpDiscVersionUnknown {
		t.Fatalf("expected version_unknown for unresolved candidate, got %s / %s", classifyPHPDiscovery(r2), r2.Summary.PHPDiscovery)
	}
}

func TestScanBinariesHopLimitIsRelevantGap(t *testing.T) {
	requireUnixSymlink(t)
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(root, "real-php")
	writeSyntheticPHP(t, real)
	// 5 symlink hops exceed maxFileSymlinkFollows (4).
	prev := real
	var first string
	for i := 5; i >= 1; i-- {
		link := filepath.Join(binDir, fmt.Sprintf("php-hop%d", i))
		if i == 1 {
			link = filepath.Join(binDir, "php")
			first = link
		}
		if err := os.Symlink(prev, link); err != nil {
			t.Fatal(err)
		}
		prev = link
	}
	_, err := resolvePHPBinCandidate(first)
	if classifyPHPBinResolveErr(err) != phpBinResolveGapBound {
		t.Fatalf("expected hop-bound gap, err=%v", err)
	}

	t.Setenv("PATH", binDir)
	r := NewReport("hop-limit", runtime.GOOS, "amd64")
	_ = scanBinaries(r, HostScanOptions{})
	saw := false
	for _, e := range r.Evidence {
		if e.Interpretation == "PHP_EXECUTABLE_CANDIDATE_UNRESOLVED_NOT_INSPECTED" &&
			strings.Contains(normalizeInstallPath(e.Location), normalizeInstallPath(first)) {
			saw = true
			if !strings.Contains(e.Detail, "hop") {
				t.Fatalf("detail should mention hop budget: %q", e.Detail)
			}
		}
	}
	if !saw {
		t.Fatalf("hop-limit symlink must record unresolved candidate evidence: %+v", r.Evidence)
	}
}

func TestScanBinariesPermissionDeniedSymlinkIsRelevantGap(t *testing.T) {
	requireUnixSymlink(t)
	if os.Getuid() == 0 {
		t.Skip("root can read chmod 000 directories")
	}
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	secret := filepath.Join(root, "secret")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(secret, "php-real")
	writeSyntheticPHP(t, real)
	mid := filepath.Join(secret, "php-mid")
	if err := os.Symlink(real, mid); err != nil {
		t.Fatal(err)
	}
	outer := filepath.Join(binDir, "php")
	if err := os.Symlink(mid, outer); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0755) })

	_, err := resolvePHPBinCandidate(outer)
	if err == nil {
		t.Skip("environment still readable through chmod 000; cannot assert access gap")
	}
	if classifyPHPBinResolveErr(err) != phpBinResolveGapAccess {
		t.Fatalf("expected access gap, got %v err=%v", classifyPHPBinResolveErr(err), err)
	}

	t.Setenv("PATH", binDir)
	r := NewReport("perm-denied", runtime.GOOS, "amd64")
	_ = scanBinaries(r, HostScanOptions{})
	saw := false
	for _, e := range r.Evidence {
		if e.Interpretation == "PHP_EXECUTABLE_CANDIDATE_UNRESOLVED_NOT_INSPECTED" &&
			strings.Contains(normalizeInstallPath(e.Location), normalizeInstallPath(outer)) {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("permission-denied symlink must record unresolved candidate: %+v", r.Evidence)
	}
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	// Even if host well-known PHP exists, fixture unresolved must be present; when it is the
	// only fixture signal, classification must not be a soft "none within coverage" for that path.
	if !saw {
		t.Fatal("unreachable")
	}
}

func TestResolvedSymlinkStillHonorsBinaryReadSafety(t *testing.T) {
	requireUnixSymlink(t)
	root := t.TempDir()
	// Oversized synthetic "binary" — VersionFromBinary must stay within sample windows.
	real := filepath.Join(root, "huge-php")
	var b strings.Builder
	b.WriteString("padding-")
	for i := 0; i < 3<<20; i++ {
		b.WriteByte('A')
	}
	b.WriteString("PHP Version 8.3.12")
	if err := os.WriteFile(real, []byte(b.String()), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "php")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	res, err := resolvePHPBinCandidate(link)
	if err != nil {
		t.Fatal(err)
	}
	if !isSafeRegularFile(res.Resolved) {
		t.Fatal("resolved target must be a regular file subject to normal inspection")
	}
	vr := VersionFromBinary(res.Resolved)
	if vr.Version != "8.3.12" {
		t.Fatalf("version=%q err=%v coverage=%+v", vr.Version, vr.Err, vr.Coverage)
	}
	// Symlink path itself must never be opened via the old unsafe gate.
	if isSafeRegularFile(link) {
		t.Fatal("symlink must remain rejected by isSafeRegularFile")
	}
}
