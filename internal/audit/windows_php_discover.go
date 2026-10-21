package audit

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	maxWindowsPHPDiscover = 400
	maxPATHDirInspect     = 80
	maxProgramsPHPDepth   = 6
)

// windowsWellKnownPHPGlobs returns static search patterns for common Windows PHP layouts.
// Includes the official php.net PowerShell installer tree under LocalAppData\Programs\PHP.
func windowsWellKnownPHPGlobs() []string {
	patterns := []string{
		`C:\php\php.exe`,
		`C:\php\php-cgi.exe`,
		`C:\xampp\php\php.exe`,
		`C:\xampp\php\php-cgi.exe`,
		`C:\inetpub\PHP\*\php-cgi.exe`,
		`C:\Program Files\PHP\*\php.exe`,
		`C:\Program Files\PHP\*\php-cgi.exe`,
		`C:\Program Files (x86)\PHP\*\php.exe`,
		`C:\Program Files (x86)\PHP\*\php-cgi.exe`,
	}
	if local := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); local != "" {
		base := filepath.Join(local, "Programs", "PHP")
		// Official installer: ...\PHP\<version>\nts|ts\x64|x86\php.exe
		patterns = append(patterns,
			filepath.Join(base, "*", "php.exe"),
			filepath.Join(base, "*", "php-cgi.exe"),
			filepath.Join(base, "*", "*", "php.exe"),
			filepath.Join(base, "*", "*", "php-cgi.exe"),
			filepath.Join(base, "*", "*", "*", "php.exe"),
			filepath.Join(base, "*", "*", "*", "php-cgi.exe"),
		)
	}
	if pf := strings.TrimSpace(os.Getenv("ProgramFiles")); pf != "" {
		patterns = append(patterns,
			filepath.Join(pf, "PHP", "*", "php.exe"),
			filepath.Join(pf, "PHP", "*", "php-cgi.exe"),
		)
	}
	return patterns
}

// discoverPHPBinsFromPATHEnv finds php.exe / php-cgi.exe sitting directly in PATH directories.
// It never executes candidates and does not recurse into PATH entries.
// Directory junctions/symlinks (e.g. ...\PHP\current) are resolved with a bounded
// reparse follow so PATH entries that PowerShell resolves via Get-Command are not skipped.
func discoverPHPBinsFromPATHEnv(pathEnv string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	sep := ":"
	if runtime.GOOS == "windows" || strings.Contains(pathEnv, ";") {
		sep = ";"
	}
	var out []string
	seen := map[string]bool{}
	dirs := 0
	for _, dir := range strings.Split(pathEnv, sep) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		dirs++
		if dirs > maxPATHDirInspect {
			break
		}
		plan, ok := planPATHDirInspect(dir)
		if !ok {
			continue
		}
		for _, name := range []string{"php.exe", "php-cgi.exe", "php", "php-cgi"} {
			if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(name), ".exe") {
				continue
			}
			if runtime.GOOS != "windows" && strings.HasSuffix(strings.ToLower(name), ".exe") {
				continue
			}
			// Prefer the resolved plain directory for Lstat (regular file check).
			candidate := filepath.Join(plan.Inspect, name)
			if !phpBin.MatchString(filepath.Base(candidate)) {
				continue
			}
			if !isSafeRegularFile(candidate) {
				continue
			}
			key := normalizeInstallPath(candidate)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, candidate)
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

// discoverPHPBinsUnderProgramsPHP walks a Programs\PHP root (or test fixture) for php binaries.
// Plain directory trees are walked with a depth cap. Directory junctions/symlinks
// (e.g. current → versioned install) are resolved once with a bounded reparse follow,
// then walked under the same depth/file caps with a visited-set to prevent loops.
func discoverPHPBinsUnderProgramsPHP(root string, limit int) ([]string, string) {
	if limit <= 0 || strings.TrimSpace(root) == "" {
		return nil, ""
	}
	fi, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ""
		}
		return nil, "Programs PHP root inaccessible: " + err.Error()
	}
	start := root
	if fi.Mode()&os.ModeSymlink != 0 {
		resolved, _, rerr := resolvePlainDir(root)
		if rerr != nil {
			return nil, "Programs PHP root reparse not resolved: " + rerr.Error()
		}
		start = resolved
	} else if !fi.IsDir() {
		return nil, "Programs PHP root is not a plain directory"
	}
	var out []string
	seenBin := map[string]bool{}
	visitedWalk := map[string]bool{}
	warn := ""
	var walk func(walkRoot string, depthBudget int)
	walk = func(walkRoot string, depthBudget int) {
		if len(out) >= limit || depthBudget < 0 {
			return
		}
		key := normalizeInstallPath(walkRoot)
		if visitedWalk[key] {
			return
		}
		visitedWalk[key] = true
		_ = filepath.WalkDir(walkRoot, func(path string, d fs.DirEntry, err error) error {
			if err != nil || len(out) >= limit {
				if len(out) >= limit {
					warn = "Programs PHP discovery truncated"
					return fs.SkipAll
				}
				return nil
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
				return nil
			}
			if info.Mode()&os.ModeSymlink != 0 {
				if !d.IsDir() {
					return nil // file symlink: never follow
				}
				// Bounded one-shot resolve of a directory junction (e.g. current).
				resolved, _, rerr := resolvePlainDir(path)
				if rerr != nil {
					return fs.SkipDir
				}
				remaining := depthBudget - depth
				if remaining < 0 {
					remaining = 0
				}
				walk(resolved, remaining)
				return fs.SkipDir
			}
			if d.IsDir() {
				if depth > depthBudget {
					return fs.SkipDir
				}
				return nil
			}
			base := d.Name()
			if !phpBin.MatchString(base) || !info.Mode().IsRegular() {
				return nil
			}
			bkey := normalizeInstallPath(path)
			if seenBin[bkey] {
				return nil
			}
			seenBin[bkey] = true
			out = append(out, path)
			if len(out) >= limit {
				warn = "Programs PHP discovery truncated"
				return fs.SkipAll
			}
			return nil
		})
	}
	walk(start, maxProgramsPHPDepth)
	return out, warn
}

func isSafeRegularFile(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return fi.Mode().IsRegular()
}

// collectWindowsPHPBinaryCandidates returns candidate PHP executable paths for Windows discovery.
func collectWindowsPHPBinaryCandidates(limit int) (paths []string, warnings []string) {
	if limit <= 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	add := func(p string) {
		p = filepath.Clean(p)
		key := normalizeInstallPath(p)
		if seen[key] || !isSafeRegularFile(p) || !phpBin.MatchString(filepath.Base(p)) {
			return
		}
		seen[key] = true
		paths = append(paths, p)
	}

	for _, pattern := range windowsWellKnownPHPGlobs() {
		if len(paths) >= limit {
			warnings = append(warnings, "Windows PHP path discovery truncated at limit")
			return paths, warnings
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, m := range matches {
			add(m)
			if len(paths) >= limit {
				warnings = append(warnings, "Windows PHP path discovery truncated at limit")
				return paths, warnings
			}
		}
	}

	if local := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); local != "" {
		root := filepath.Join(local, "Programs", "PHP")
		found, warn := discoverPHPBinsUnderProgramsPHP(root, limit-len(paths))
		if warn != "" {
			warnings = append(warnings, warn)
		}
		for _, p := range found {
			add(p)
			if len(paths) >= limit {
				break
			}
		}
	}

	remain := limit - len(paths)
	if remain > 0 {
		for _, p := range discoverPHPBinsFromPATHEnv(os.Getenv("PATH"), remain) {
			add(p)
		}
	}
	return paths, warnings
}
