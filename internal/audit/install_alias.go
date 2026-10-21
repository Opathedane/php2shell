package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// binaryEvidenceTypes are inventory rows that describe discovered PHP executables.
func isBinaryEvidenceType(t string) bool {
	switch t {
	case "binary_path", "binary_static_version", "binary_path_inferred_version":
		return true
	default:
		return false
	}
}

// ReconcileBinaryInstallAliases corroborates whether "current" (or similar) paths
// reference the same on-disk content as a versioned install tree. It never assumes
// identity without SameFile or matching passive content fingerprints, and never
// executes binaries.
//
// When corroborated, path-only "current" rows may inherit a labelled path-inferred
// version from the versioned tree. Install keys are assigned later from directories.
func ReconcileBinaryInstallAliases(r *Report) {
	type binMeta struct {
		idx   int
		path  string
		dir   string
		base  string
		fp    string
		same  os.FileInfo
		hasFP bool
	}
	var bins []binMeta
	for i, e := range r.Evidence {
		if !isBinaryEvidenceType(e.Type) || e.Location == "" {
			continue
		}
		fi, err := os.Lstat(e.Location)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		m := binMeta{idx: i, path: e.Location, dir: filepath.Dir(e.Location), base: strings.ToLower(filepath.Base(e.Location)), same: fi}
		if size, sum, err := binaryFingerprint(e.Location); err == nil {
			m.fp = fmt.Sprintf("%d:%s", size, sum)
			m.hasFP = true
		}
		bins = append(bins, m)
	}

	// Map normalized directory -> canonical versioned directory when corroborated.
	aliasDir := map[string]string{}
	for i := 0; i < len(bins); i++ {
		for j := i + 1; j < len(bins); j++ {
			a, b := bins[i], bins[j]
			if a.base != b.base {
				continue
			}
			aCurrent, bCurrent := pathContainsCurrentAlias(a.path), pathContainsCurrentAlias(b.path)
			if aCurrent == bCurrent {
				continue
			}
			corroborated := false
			if os.SameFile(a.same, b.same) {
				corroborated = true
			} else if a.hasFP && b.hasFP && a.fp == b.fp {
				corroborated = true
			}
			if !corroborated {
				r.AddWarning(fmt.Sprintf("PHP path %s and %s share basename %s but were not corroborated as the same file; keeping separate install records", a.path, b.path, a.base))
				continue
			}
			var currentDir, versionedDir string
			if aCurrent {
				currentDir, versionedDir = a.dir, b.dir
			} else {
				currentDir, versionedDir = b.dir, a.dir
			}
			// Prefer a directory that itself embeds an x.y.z segment as canonical.
			if ver, _ := VersionFromInstallPath(versionedDir); ver == "" {
				if ver2, _ := VersionFromInstallPath(currentDir); ver2 != "" {
					currentDir, versionedDir = versionedDir, currentDir
				}
			}
			aliasDir[normalizeInstallPath(currentDir)] = normalizeInstallPath(versionedDir)
			r.AddCheck("binary_path_alias", "CORROBORATED", fmt.Sprintf("Treating %s as an alias of %s for install grouping (%s content match); not proof both are the active web runtime", currentDir, versionedDir, a.base))
		}
	}

	// Promote version onto corroborated "current" rows that still lack a version.
	for i := range r.Evidence {
		e := &r.Evidence[i]
		if !isBinaryEvidenceType(e.Type) || e.Version != "" {
			continue
		}
		dirKey := normalizeInstallPath(filepath.Dir(e.Location))
		canon, ok := aliasDir[dirKey]
		if !ok {
			continue
		}
		var donor *Evidence
		for j := range r.Evidence {
			o := &r.Evidence[j]
			if !isBinaryEvidenceType(o.Type) || o.Version == "" {
				continue
			}
			if normalizeInstallPath(filepath.Dir(o.Location)) != canon {
				continue
			}
			if strings.ToLower(filepath.Base(o.Location)) != strings.ToLower(filepath.Base(e.Location)) {
				continue
			}
			donor = o
			break
		}
		if donor == nil {
			// Fall back to any versioned evidence under the canonical directory.
			for j := range r.Evidence {
				o := &r.Evidence[j]
				if !isBinaryEvidenceType(o.Type) || o.Version == "" {
					continue
				}
				if normalizeInstallPath(filepath.Dir(o.Location)) == canon {
					donor = o
					break
				}
			}
		}
		if donor == nil {
			continue
		}
		e.Version = donor.Version
		e.Type = "binary_path_inferred_version"
		e.Interpretation = "PATH_INFERRED_VERSION_VIA_CORROBORATED_ALIAS_NOT_RUNTIME_ATTESTATION"
		e.Detail = strings.TrimSpace(e.Detail + "; version_inherited_from_corroborated_alias=" + donor.Location + "; provenance=path_inferred; confidence=MEDIUM")
	}

	// Stash alias map on the report via a synthetic check detail is enough for keys;
	// assignInstallKeys reads directories + re-derives alias from pathContainsCurrentAlias
	// by comparing fingerprints again would be expensive. Store in a package-level
	// side channel is bad. Instead encode alias into evidence Detail and parse in
	// assignInstallKeys — cleaner: return alias map and set on Report.
	r.aliasDirs = aliasDir
}

// Report carries an optional alias map populated during reconcile (not serialized).
func (r *Report) binaryAliasDirs() map[string]string {
	if r == nil || r.aliasDirs == nil {
		return map[string]string{}
	}
	return r.aliasDirs
}
