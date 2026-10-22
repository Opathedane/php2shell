package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ScanWebrootInvestigation walks an authorized --webroot for filesystem
// investigation leads. It never opens file contents, never executes PHP, and
// never treats modification time as proof of file creation.
//
// Location context (PHP in upload paths / unusual extensions) is distinct from
// timestamp evidence (birth/mtime in the investigation window). Path context is
// only emitted when at least one timestamp corroborates window relevance.
// Birth-in-window remains detectable even when mtime is old (preserved or
// altered modification times). All leads are unconfirmed / weaker than EDR.
func ScanWebrootInvestigation(r *Report, root string, from, to time.Time) (leads []WebrootLead) {
	item := WebrootInvestigationCoverage{Root: root, Status: "NOT_ASSESSED"}
	fi, err := os.Lstat(root)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		item.Status = "UNAVAILABLE"
		item.Detail = "No accessible regular directory at supplied --webroot (symlinks rejected)"
		r.WebrootInvestigation = append(r.WebrootInvestigation, item)
		r.AddWarning("Webroot investigation unavailable: " + root)
		return nil
	}

	seen, phpLike, errorsCount := 0, 0, 0
	truncated := false
	var out []WebrootLead
	seenKeys := map[string]bool{}

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			errorsCount++
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if path != root && pathDepth(root, path) > webrootInvestMaxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		seen++
		if seen > webrootInvestMaxEntries {
			truncated = true
			return filepath.SkipAll
		}
		name := d.Name()
		if !isPHPLikeName(name) {
			return nil
		}
		phpLike++
		info, ierr := d.Info()
		if ierr != nil || !info.Mode().IsRegular() {
			errorsCount++
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		mtime := info.ModTime().UTC()
		birth, birthOK := fileBirthTimeUTC(info)
		if birthOK {
			item.BirthAvailable++
		} else {
			item.BirthUnavailable++
		}

		for _, lead := range webrootLeadsForFile(webrootFileMeta{
			Path: path, RelPath: rel, Name: name,
			Mtime: mtime, Birth: birth, BirthOK: birthOK,
		}, from, to) {
			if len(out) >= webrootInvestMaxLeads {
				break
			}
			if seenKeys[lead.DedupKey] {
				continue
			}
			seenKeys[lead.DedupKey] = true
			out = append(out, lead)
		}
		return nil
	})
	if err != nil {
		errorsCount++
	}

	item.EntriesSeen = seen
	item.PHPLikeSeen = phpLike
	item.Leads = len(out)
	item.Truncated = truncated
	if truncated {
		item.Status = "TRUNCATED"
		item.Detail = fmt.Sprintf("Walk truncated at %d entries (depth≤%d). Leads=%d php-like=%d errors=%d. Incomplete discovery is not absence of artifacts; do not treat as clearance.",
			webrootInvestMaxEntries, webrootInvestMaxDepth, len(out), phpLike, errorsCount)
		r.AddWarning("Webroot investigation truncated; do not treat as complete filesystem coverage")
	} else if seen == 0 && errorsCount > 0 {
		item.Status = "INCOMPLETE"
		item.Detail = "Webroot walk encountered errors and saw no entries"
	} else {
		item.Status = "ASSESSED_SCOPE_LIMITED"
		item.Detail = fmt.Sprintf(
			"Reviewed %d entries (%d PHP-like) under authorized webroot; depth≤%d; symlinks skipped; file contents never read. "+
				"Leads=%d (all unconfirmed metadata heuristics; weaker than EDR process evidence). "+
				"Path location context is separate from birth/mtime timestamp evidence. "+
				"Birth timestamps available=%d unavailable=%d. mtime is never treated as creation. Not a webshell scanner.",
			seen, phpLike, webrootInvestMaxDepth, len(out), item.BirthAvailable, item.BirthUnavailable,
		)
	}
	r.WebrootInvestigation = append(r.WebrootInvestigation, item)
	return out
}

// webrootFileMeta is the metadata inputs for deterministic lead evaluation.
type webrootFileMeta struct {
	Path, RelPath, Name string
	Mtime               time.Time
	Birth               time.Time
	BirthOK             bool
}

// webrootLeadsForFile evaluates location context vs timestamp evidence.
// Historical CMS files (both timestamps outside the window) produce no leads.
// In-window birth is reported even when mtime is old.
func webrootLeadsForFile(meta webrootFileMeta, from, to time.Time) []WebrootLead {
	upload := pathLooksLikeUploadDir(meta.RelPath)
	unusual := isUnusualPHPExtension(meta.Name)
	if !upload && !unusual {
		return nil
	}

	mtime := meta.Mtime.UTC()
	birth := meta.Birth.UTC()
	mtimeIn := !mtime.IsZero() && inInvestigationWindow(mtime, from, to)
	birthIn := meta.BirthOK && !birth.IsZero() && inInvestigationWindow(birth, from, to)
	temporalCorroboration := mtimeIn || birthIn

	var out []WebrootLead
	add := func(kind, detail string) {
		key := kind + "|" + meta.RelPath
		out = append(out, WebrootLead{
			Path: meta.Path, RelPath: meta.RelPath, Kind: kind,
			Confidence: "unconfirmed",
			MtimeUTC: mtime, BirthUTC: birth, BirthAvailable: meta.BirthOK,
			Detail: detail, DedupKey: key,
		})
	}

	weakPrefix := "WEAK METADATA-ONLY LEAD (unconfirmed; weaker than EDR process evidence). "

	// Location context only accompanies timestamp corroboration — never alone as
	// evidence of recent compromise for long-lived CMS trees.
	if temporalCorroboration && upload {
		add("webroot_php_in_upload_dir", weakPrefix+fmt.Sprintf(
			"LOCATION CONTEXT (not timestamp proof of recent compromise by itself): PHP-related file %q under upload/writable path %s. "+
				"Ordinary CMS media/plugins often live here. mtime=%s; birth=%s. Modification time is never treated as file creation.",
			truncateRunes(meta.Name, 80), meta.RelPath,
			formatTSOrDash(mtime), formatBirthOrUnavailable(birth, meta.BirthOK),
		))
	}
	if temporalCorroboration && unusual {
		add("webroot_unusual_extension", weakPrefix+fmt.Sprintf(
			"LOCATION CONTEXT (not timestamp proof of recent compromise by itself): unusual PHP-related extension or double-extension name %q at %s. "+
				"Not proof the file is executable PHP or a webshell. mtime=%s; birth=%s. Modification time is never treated as file creation.",
			truncateRunes(meta.Name, 80), meta.RelPath,
			formatTSOrDash(mtime), formatBirthOrUnavailable(birth, meta.BirthOK),
		))
	}

	// Timestamp evidence: birth in window is independent of mtime (preserved/altered mtime cases).
	if birthIn {
		add("webroot_birth_in_window", weakPrefix+fmt.Sprintf(
			"TIMESTAMP EVIDENCE: filesystem birth/creation timestamp %s falls inside the investigation window for %s. "+
				"OS-reported birth is still not proof of attacker write. mtime=%s is not creation or execution. Not a webshell confirmation.",
			birth.Format(time.RFC3339), meta.RelPath, formatTSOrDash(mtime),
		))
	}
	if mtimeIn && !birthIn {
		add("webroot_mtime_in_window", weakPrefix+fmt.Sprintf(
			"TIMESTAMP EVIDENCE: modification time %s falls inside the investigation window for %s. "+
				"CRITICAL: mtime is not file creation and must not be treated as execution time "+
				"(timestamps can be altered or preserved by deploy/copy). Birth unavailable=%v. Not a webshell confirmation.",
			mtime.Format(time.RFC3339), meta.RelPath, !meta.BirthOK,
		))
	}
	return out
}

// webrootLeadIsTimestampEvidence reports whether a lead is timestamp-based
// (drives possible-compromise review). Path-context kinds alone must not.
func webrootLeadIsTimestampEvidence(kind string) bool {
	switch kind {
	case "webroot_birth_in_window", "webroot_mtime_in_window":
		return true
	default:
		return false
	}
}

func formatTSOrDash(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func formatBirthOrUnavailable(t time.Time, ok bool) string {
	if !ok || t.IsZero() {
		return "unavailable"
	}
	return t.UTC().Format(time.RFC3339)
}

func preferTS(birth time.Time, birthOK bool, mtime time.Time) time.Time {
	if birthOK && !birth.IsZero() {
		return birth
	}
	return mtime
}

func countWebrootUsable(items []WebrootInvestigationCoverage) (usable, unusable int) {
	for _, it := range items {
		switch strings.ToUpper(it.Status) {
		case "UNAVAILABLE", "INCOMPLETE":
			unusable++
		case "TRUNCATED", "ASSESSED_SCOPE_LIMITED":
			usable++
		default:
			if it.EntriesSeen > 0 {
				usable++
			} else {
				unusable++
			}
		}
	}
	return
}

// possibleCompromiseIsWebrootMetadataOnly reports whether POSSIBLE_COMPROMISE_REVIEW
// rests only on weak webroot metadata (no EDR process leads).
func possibleCompromiseIsWebrootMetadataOnly(r *Report) bool {
	if r == nil || r.PossibleCompromiseStatus != "POSSIBLE_COMPROMISE_REVIEW" {
		return false
	}
	hasProc, hasWeb := false, false
	for _, f := range r.InvestigationFindings {
		switch {
		case strings.HasPrefix(f.Kind, "web_parent_"), strings.HasPrefix(f.Kind, "correlated_process"):
			hasProc = true
		case strings.HasPrefix(f.Kind, "webroot_"), strings.HasPrefix(f.Kind, "correlated_webroot"):
			hasWeb = true
		}
	}
	return hasWeb && !hasProc
}
