package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxFileSymlinkFollows caps file-symlink hops when resolving PHP executables.
// Matches the directory reparse budget (path_resolve.go) so discovery stays bounded.
const maxFileSymlinkFollows = 4

// maxPATHDirEntries caps ReadDir results when expanding Unix PATH names (php8.3, php-fpm, …).
const maxPATHDirEntries = 512

// phpBinResolveResult is a PHP executable path after bounded file-symlink resolution.
// Inspection always uses Resolved (regular file). Original is the operator-facing candidate.
type phpBinResolveResult struct {
	Original   string
	Resolved   string
	ViaSymlink bool
	Follows    int
}

// phpBinResolveGap classifies why resolvePHPBinCandidate failed.
// Irrelevant gaps (broken/cycle/non-regular) stay silent.
// Relevant gaps (access / hop bound) must not disappear into "no PHP within coverage".
type phpBinResolveGap int

const (
	phpBinResolveGapNone phpBinResolveGap = iota
	phpBinResolveGapIrrelevant
	phpBinResolveGapAccess
	phpBinResolveGapBound
)

// resolvePHPBinCandidate follows a bounded chain of file symlinks to a regular file.
// It never executes the target, never walks directory trees, and rejects cycles,
// over-long chains, dangling links, and non-regular final targets.
//
// Callers that must keep Windows/handler/ini semantics unchanged should continue
// using isSafeRegularFile, which still rejects all symlinks without following.
func resolvePHPBinCandidate(path string) (phpBinResolveResult, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" || path == "." {
		return phpBinResolveResult{}, fmt.Errorf("empty binary path")
	}
	seen := map[string]bool{}
	cur := path
	follows := 0
	for {
		key := normalizeInstallPath(cur)
		if seen[key] {
			return phpBinResolveResult{}, fmt.Errorf("file symlink cycle at %s", cur)
		}
		seen[key] = true

		fi, err := os.Lstat(cur)
		if err != nil {
			return phpBinResolveResult{}, err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if follows >= maxFileSymlinkFollows {
				return phpBinResolveResult{}, fmt.Errorf("file symlink chain exceeds %d hops: %s", maxFileSymlinkFollows, path)
			}
			target, rerr := os.Readlink(cur)
			if rerr != nil {
				return phpBinResolveResult{}, rerr
			}
			target = strings.TrimSpace(target)
			if target == "" {
				return phpBinResolveResult{}, fmt.Errorf("empty symlink target: %s", cur)
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(cur), target)
			}
			cur = filepath.Clean(target)
			follows++
			continue
		}
		if !fi.Mode().IsRegular() {
			return phpBinResolveResult{}, fmt.Errorf("not a regular file: %s", cur)
		}
		return phpBinResolveResult{
			Original:   path,
			Resolved:   cur,
			ViaSymlink: follows > 0,
			Follows:    follows,
		}, nil
	}
}

// classifyPHPBinResolveErr distinguishes harmless non-installs from relevant
// uninspectable PHP executable candidates.
func classifyPHPBinResolveErr(err error) phpBinResolveGap {
	if err == nil {
		return phpBinResolveGapNone
	}
	msg := strings.ToLower(err.Error())
	if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) || strings.Contains(msg, "no such file") {
		return phpBinResolveGapIrrelevant
	}
	if strings.Contains(msg, "cycle") {
		return phpBinResolveGapIrrelevant
	}
	if strings.Contains(msg, "not a regular file") || strings.Contains(msg, "empty binary") || strings.Contains(msg, "empty symlink") {
		return phpBinResolveGapIrrelevant
	}
	if strings.Contains(msg, "exceeds") && strings.Contains(msg, "hops") {
		return phpBinResolveGapBound
	}
	if os.IsPermission(err) || errors.Is(err, fs.ErrPermission) ||
		strings.Contains(msg, "permission denied") || strings.Contains(msg, "access is denied") {
		return phpBinResolveGapAccess
	}
	// Other I/O failures while resolving a phpBin-named path are treated as
	// uninspectable candidates (not proof of absence).
	return phpBinResolveGapAccess
}

func phpBinResolveGapReason(gap phpBinResolveGap, err error) string {
	switch gap {
	case phpBinResolveGapBound:
		return "symlink chain exceeds hop budget"
	case phpBinResolveGapAccess:
		if err != nil {
			return "unreadable or inaccessible symlink target (" + err.Error() + ")"
		}
		return "unreadable or inaccessible symlink target"
	default:
		return ""
	}
}

// recordUnresolvedPHPBinCandidate records a phpBin-named path that could not be
// inspected so discovery does not conclude NO_PHP_DETECTED_WITHIN_SCAN_COVERAGE.
func recordUnresolvedPHPBinCandidate(r *Report, path, source, reason string) {
	if r == nil || path == "" || reason == "" {
		return
	}
	r.AddEvidence(Evidence{
		Type:           "binary_path",
		Name:           filepath.Base(path),
		Source:         source,
		Location:       path,
		Detail:         "PHP executable candidate not inspected: " + reason,
		Interpretation: "PHP_EXECUTABLE_CANDIDATE_UNRESOLVED_NOT_INSPECTED",
	})
}

// noteResolvedPHPBinAliasPath records an additional operator-facing symlink alias
// on an existing install evidence row without creating a duplicate installation.
func noteResolvedPHPBinAliasPath(r *Report, resolved, alias string) {
	if r == nil || resolved == "" || alias == "" {
		return
	}
	rkey := normalizeInstallPath(resolved)
	akey := normalizeInstallPath(alias)
	if rkey == akey {
		return
	}
	for i := range r.Evidence {
		e := &r.Evidence[i]
		if !isBinaryEvidenceType(e.Type) {
			continue
		}
		if normalizeInstallPath(e.Location) != rkey {
			continue
		}
		marker := "also_via_symlink=" + alias
		if strings.Contains(e.Detail, marker) || strings.Contains(e.Source, alias) {
			return
		}
		if e.Detail == "" {
			e.Detail = marker
		} else {
			e.Detail = e.Detail + "; " + marker
		}
		return
	}
}
