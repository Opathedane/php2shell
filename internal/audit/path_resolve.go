package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxDirReparseFollows = 4

// resolvePlainDir follows a bounded chain of directory symlinks/junctions to a
// plain directory. It never executes files, never walks trees, and rejects cycles
// and over-long chains. File symlinks are not accepted as a final target.
//
// On Windows this is required for PATH entries such as C:\Temp\PHP\current when
// "current" is a junction to a real install directory: Lstat on the PATH entry
// reports ModeSymlink, and older discovery skipped the entire entry.
func resolvePlainDir(dir string) (resolved string, follows int, err error) {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if dir == "" || dir == "." {
		return "", 0, fmt.Errorf("empty directory path")
	}
	seen := map[string]bool{}
	cur := dir
	for follows = 0; follows <= maxDirReparseFollows; follows++ {
		key := normalizeInstallPath(cur)
		if seen[key] {
			return "", follows, fmt.Errorf("directory reparse cycle at %s", cur)
		}
		seen[key] = true

		fi, lerr := os.Lstat(cur)
		if lerr != nil {
			return "", follows, lerr
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if follows >= maxDirReparseFollows {
				return "", follows, fmt.Errorf("directory reparse chain exceeds %d hops: %s", maxDirReparseFollows, dir)
			}
			target, rerr := os.Readlink(cur)
			if rerr != nil {
				return "", follows, rerr
			}
			target = strings.TrimSpace(target)
			if target == "" {
				return "", follows, fmt.Errorf("empty reparse target: %s", cur)
			}
			// Windows junction targets may be absolute; symlink targets may be relative.
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(cur), target)
			}
			cur = filepath.Clean(target)
			continue
		}
		if !fi.IsDir() {
			return "", follows, fmt.Errorf("not a directory: %s", cur)
		}
		return cur, follows, nil
	}
	return "", follows, fmt.Errorf("directory reparse chain exceeds %d hops: %s", maxDirReparseFollows, dir)
}

// pathDirInspectPlan describes how a PATH (or similar) directory should be inspected.
type pathDirInspectPlan struct {
	// Inspect is the plain directory to list for php.exe / php.ini.
	Inspect string
	// Reported is the operator-visible path (usually the original PATH entry).
	Reported string
	// ViaReparse is true when Inspect was reached through a junction/symlink.
	ViaReparse bool
}

// planPATHDirInspect resolves a PATH directory for read-only PHP binary/config
// inspection. Symlink/junction directories are followed within maxDirReparseFollows;
// plain directories are used as-is. Missing or unsafe entries return ok=false.
func planPATHDirInspect(dir string) (plan pathDirInspectPlan, ok bool) {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if dir == "" || dir == "." {
		return plan, false
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return plan, false
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		resolved, _, rerr := resolvePlainDir(dir)
		if rerr != nil {
			return plan, false
		}
		return pathDirInspectPlan{Inspect: resolved, Reported: dir, ViaReparse: true}, true
	}
	if !fi.IsDir() {
		return plan, false
	}
	return pathDirInspectPlan{Inspect: dir, Reported: dir, ViaReparse: false}, true
}
