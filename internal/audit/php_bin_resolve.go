package audit

import (
	"fmt"
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
