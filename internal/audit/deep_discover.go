package audit

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Conservative Deep Discovery limits (operator --deep-root only; off by default).
const (
	maxDeepRoots            = 8
	maxDeepDepth            = 6
	maxDeepEntries          = 25000
	maxDeepBinaries         = 400 // shared with global binary discovery budget
	maxDeepIniCandidates    = 200 // shared with global php.ini budget
	maxDeepDiscoverDuration = 90 * time.Second
)

// Runtime caps (default to consts). Tests may lower these for deterministic truncation.
var (
	deepDepthCap    = maxDeepDepth
	deepEntriesCap  = maxDeepEntries
	deepDurationCap = maxDeepDiscoverDuration
)

// deepDiscoverHit is one filesystem hit under an authorized --deep-root.
type deepDiscoverHit struct {
	Path string
	Kind string // "binary" or "ini"
}

// deepDiscoverOutcome summarizes one authorized root walk.
type deepDiscoverOutcome struct {
	Root              string
	Start             string // plain directory actually walked (after optional root reparse)
	Binaries          []string
	Inis              []string
	EntriesInspected  int
	PermissionErrors  int
	SkippedSymlinks   int
	SkippedOutside    int
	Truncated         bool
	TruncReason       string // entry_limit|depth_budget|binary_limit|ini_limit|duration|cancelled
	Duration          time.Duration
}

// ValidateDeepRootForCLI rejects unsafe --deep-root values before scan starts.
func ValidateDeepRootForCLI(raw string) (string, error) {
	return validateDeepRoot(raw)
}

// validateDeepRoot rejects unsafe or unauthorized scan roots before any walk.
// Returns a cleaned absolute-ish path suitable for Lstat (operator path as given, cleaned).
func validateDeepRoot(raw string) (root string, err error) {
	root = filepath.Clean(strings.TrimSpace(raw))
	if root == "" || root == "." {
		return "", fmt.Errorf("empty --deep-root path")
	}
	if isNetworkOrUNCPath(root) {
		return "", fmt.Errorf("--deep-root refuses UNC/network paths (%s); map a local authorized directory instead", root)
	}
	if isFilesystemVolumeRoot(root) {
		return "", fmt.Errorf("--deep-root refuses volume/filesystem roots (%s); specify a narrower authorized directory", root)
	}
	fi, lerr := os.Lstat(root)
	if lerr != nil {
		if os.IsNotExist(lerr) {
			return "", fmt.Errorf("--deep-root not found: %s", root)
		}
		return "", fmt.Errorf("--deep-root inaccessible: %s (%v)", root, lerr)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		resolved, _, rerr := resolvePlainDir(root)
		if rerr != nil {
			return "", fmt.Errorf("--deep-root reparse not resolved: %s (%v)", root, rerr)
		}
		if isNetworkOrUNCPath(resolved) {
			return "", fmt.Errorf("--deep-root resolves to UNC/network path (%s → %s)", root, resolved)
		}
		if isFilesystemVolumeRoot(resolved) {
			return "", fmt.Errorf("--deep-root resolves to volume root (%s → %s)", root, resolved)
		}
		return root, nil // keep operator-facing path; walk resolves start separately
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("--deep-root is not a directory: %s", root)
	}
	return root, nil
}

func isNetworkOrUNCPath(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	// Windows UNC: \\server\share or //server/share (including long-path prefixes).
	if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `//`) {
		return true
	}
	low := strings.ToLower(strings.ReplaceAll(p, `/`, `\`))
	if strings.HasPrefix(low, `\\?\unc\`) || strings.HasPrefix(low, `//?/unc/`) {
		return true
	}
	if runtime.GOOS == "windows" {
		// Device namespace UNC forms occasionally seen in junction targets.
		if strings.HasPrefix(low, `\??\unc\`) {
			return true
		}
	}
	return false
}

func isFilesystemVolumeRoot(p string) bool {
	p = filepath.Clean(strings.TrimSpace(p))
	if p == "" {
		return false
	}
	if runtime.GOOS == "windows" {
		vol := filepath.VolumeName(p)
		if vol == "" {
			return false
		}
		rest := strings.TrimPrefix(p, vol)
		rest = strings.Trim(rest, `/\`)
		return rest == ""
	}
	return p == string(filepath.Separator)
}

// pathUnderAuthorized reports whether candidate is inside authorizedStart
// (the plain directory that began the walk). Uses slash-normalized, lower-cased
// paths so Windows case and separator spelling cannot escape the authorized root.
func pathUnderAuthorized(authorizedStart, candidate string) bool {
	auth := normalizeInstallPath(authorizedStart)
	cand := normalizeInstallPath(candidate)
	if auth == "" || cand == "" {
		return false
	}
	if cand == auth {
		return true
	}
	// Require a path separator after the root so /opt/php does not match /opt/phpish.
	return strings.HasPrefix(cand, auth+"/")
}

func isDeepIniBasename(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	switch low {
	case "php.ini", "php.ini-production", "php.ini-development", "php.ini-dist":
		return true
	}
	if strings.HasPrefix(low, "php.ini-") {
		return true
	}
	// conf.d-style fragments only when suffix is .ini and name looks PHP-related
	if strings.HasSuffix(low, ".ini") && (strings.Contains(low, "php") || strings.Contains(low, "opcache") ||
		strings.Contains(low, "xdebug") || strings.Contains(low, "fpm")) {
		return true
	}
	return false
}

// deepDiscoverUnderRoot walks one authorized root for PHP binaries and ini-like files.
// It never executes binaries, never follows file symlinks, and only follows directory
// reparse points when the resolved target remains under the authorized start directory.
func deepDiscoverUnderRoot(root string, deadline time.Time, remainBins, remainInis int) deepDiscoverOutcome {
	out := deepDiscoverOutcome{Root: root}
	start := root
	fi, err := os.Lstat(root)
	if err != nil {
		out.Truncated = true
		out.TruncReason = "inaccessible"
		out.PermissionErrors++
		return out
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		resolved, _, rerr := resolvePlainDir(root)
		if rerr != nil {
			out.Truncated = true
			out.TruncReason = "reparse_failed"
			return out
		}
		start = resolved
	}
	out.Start = start

	begun := time.Now()
	defer func() { out.Duration = time.Since(begun) }()

	seenBin := map[string]bool{}
	seenIni := map[string]bool{}
	visitedWalk := map[string]bool{}

	markTrunc := func(reason string) {
		if !out.Truncated {
			out.Truncated = true
			out.TruncReason = reason
		}
	}

	pastDeadline := func() bool {
		if !deadline.IsZero() && time.Now().After(deadline) {
			markTrunc("duration")
			return true
		}
		return false
	}

	var walk func(walkRoot string, depthBudget int)
	walk = func(walkRoot string, depthBudget int) {
		if pastDeadline() || out.Truncated {
			return
		}
		if depthBudget < 0 {
			markTrunc("depth_budget")
			return
		}
		key := normalizeInstallPath(walkRoot)
		if visitedWalk[key] {
			return
		}
		visitedWalk[key] = true

		_ = filepath.WalkDir(walkRoot, func(path string, d fs.DirEntry, err error) error {
			if pastDeadline() {
				return fs.SkipAll
			}
			switch out.TruncReason {
			case "entry_limit", "binary_limit", "ini_limit", "duration":
				return fs.SkipAll
			}
			if err != nil {
				out.PermissionErrors++
				// Keep walking siblings; do not abort whole root on one denial.
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			out.EntriesInspected++
			if out.EntriesInspected > deepEntriesCap {
				markTrunc("entry_limit")
				return fs.SkipAll
			}

			rel, relErr := filepath.Rel(walkRoot, path)
			if relErr != nil {
				return nil
			}
			depth := 0
			if rel != "." {
				depth = len(strings.Split(rel, string(filepath.Separator)))
			}

			info, infoErr := d.Info()
			if infoErr != nil {
				out.PermissionErrors++
				return nil
			}

			if info.Mode()&os.ModeSymlink != 0 {
				// Symlink-to-directory: DirEntry.IsDir is often false on Unix; try resolve.
				// Never return SkipDir for a non-directory DirEntry — WalkDir would skip the
				// parent directory and drop sibling installs (e.g. local/ next to escape/).
				resolved, _, rerr := resolvePlainDir(path)
				if rerr != nil {
					out.SkippedSymlinks++
					return nil // file symlink or unresolvable reparse: never follow
				}
				if !pathUnderAuthorized(start, resolved) {
					out.SkippedOutside++
					return nil
				}
				remaining := depthBudget - depth
				if remaining < 0 {
					remaining = 0
				}
				walk(resolved, remaining)
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}

			if d.IsDir() {
				if depth > depthBudget {
					markTrunc("depth_budget")
					return fs.SkipDir
				}
				return nil
			}

			if !info.Mode().IsRegular() {
				return nil
			}
			base := d.Name()
			if phpBin.MatchString(base) {
				if remainBins >= 0 && len(out.Binaries) >= remainBins {
					markTrunc("binary_limit")
					return fs.SkipAll
				}
				bkey := normalizeInstallPath(path)
				if !seenBin[bkey] {
					seenBin[bkey] = true
					out.Binaries = append(out.Binaries, path)
					if len(out.Binaries) >= maxDeepBinaries || (remainBins > 0 && len(out.Binaries) >= remainBins) {
						markTrunc("binary_limit")
						return fs.SkipAll
					}
				}
				return nil
			}
			if isDeepIniBasename(base) {
				if remainInis >= 0 && len(out.Inis) >= remainInis {
					markTrunc("ini_limit")
					return fs.SkipAll
				}
				ikey := normalizeInstallPath(path)
				if !seenIni[ikey] {
					seenIni[ikey] = true
					out.Inis = append(out.Inis, path)
					if len(out.Inis) >= maxDeepIniCandidates || (remainInis > 0 && len(out.Inis) >= remainInis) {
						markTrunc("ini_limit")
						return fs.SkipAll
					}
				}
			}
			return nil
		})
	}

	walk(start, deepDepthCap)
	return out
}

func deepTruncationDetail(o deepDiscoverOutcome) string {
	parts := []string{
		fmt.Sprintf("root=%s", o.Root),
		fmt.Sprintf("entries=%d", o.EntriesInspected),
		fmt.Sprintf("binaries=%d", len(o.Binaries)),
		fmt.Sprintf("ini_candidates=%d", len(o.Inis)),
	}
	if o.Start != "" && normalizeInstallPath(o.Start) != normalizeInstallPath(o.Root) {
		parts = append(parts, "start="+o.Start)
	}
	if o.Truncated {
		parts = append(parts, "stopped="+o.TruncReason)
	}
	if o.PermissionErrors > 0 {
		parts = append(parts, fmt.Sprintf("permission_errors=%d", o.PermissionErrors))
	}
	if o.SkippedOutside > 0 {
		parts = append(parts, fmt.Sprintf("skipped_outside_scope=%d", o.SkippedOutside))
	}
	if o.SkippedSymlinks > 0 {
		parts = append(parts, fmt.Sprintf("skipped_symlink=%d", o.SkippedSymlinks))
	}
	parts = append(parts, fmt.Sprintf("duration=%s", o.Duration.Round(time.Millisecond)))
	return strings.Join(parts, "; ")
}
