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
// All leads are weak metadata heuristics (confidence=unconfirmed), weaker than
// EDR process-relationship evidence. Upload/unusual path leads require at least
// one timestamp inside the investigation window to limit long-lived CMS FPs.
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

		upload := pathLooksLikeUploadDir(rel)
		unusual := isUnusualPHPExtension(name)
		mtimeIn := !mtime.IsZero() && inInvestigationWindow(mtime, from, to)
		birthIn := birthOK && inInvestigationWindow(birth, from, to)
		// Require window relevance for path/extension heuristics so long-lived
		// CMS files in uploads/ do not all become compromise leads.
		inWindow := mtimeIn || birthIn
		tsUnknown := mtime.IsZero() && !birthOK

		add := func(kind, detail string) {
			if len(out) >= webrootInvestMaxLeads {
				return
			}
			key := kind + "|" + rel
			if seenKeys[key] {
				return
			}
			seenKeys[key] = true
			out = append(out, WebrootLead{
				Path: path, RelPath: rel, Kind: kind,
				Confidence: "unconfirmed", // metadata-only: never EDR-strength
				MtimeUTC: mtime, BirthUTC: birth, BirthAvailable: birthOK,
				Detail: detail, DedupKey: key,
			})
		}

		weakPrefix := "WEAK METADATA-ONLY LEAD (unconfirmed; weaker than EDR process evidence). "

		if upload && (inWindow || tsUnknown) {
			detail := weakPrefix + fmt.Sprintf(
				"PHP-related file %q under path segment consistent with upload/writable directories (%s). "+
					"Not proof of a webshell or successful exploitation — ordinary CMS media/plugins often live here. "+
					"mtime=%s; birth=%s. Modification time is never treated as file creation.",
				truncateRunes(name, 80), rel,
				formatTSOrDash(mtime), formatBirthOrUnavailable(birth, birthOK),
			)
			add("webroot_php_in_upload_dir", detail)
		}
		if unusual && (inWindow || tsUnknown) {
			detail := weakPrefix + fmt.Sprintf(
				"Unusual PHP-related extension or double-extension name %q at %s. "+
					"Not proof the file is executable PHP or a webshell. mtime=%s; birth=%s. "+
					"Modification time is never treated as file creation.",
				truncateRunes(name, 80), rel,
				formatTSOrDash(mtime), formatBirthOrUnavailable(birth, birthOK),
			)
			add("webroot_unusual_extension", detail)
		}
		if birthIn && (upload || unusual) {
			detail := weakPrefix + fmt.Sprintf(
				"Filesystem birth/creation timestamp %s falls inside the investigation window for %s. "+
					"OS-reported birth when available is still not proof of attacker write (deploy tools may set it; platforms may lack birth). "+
					"mtime=%s is not creation. Not a webshell confirmation.",
				birth.Format(time.RFC3339), rel, formatTSOrDash(mtime),
			)
			add("webroot_birth_in_window", detail)
		}
		if mtimeIn && (upload || unusual) && !birthIn {
			detail := weakPrefix + fmt.Sprintf(
				"Modification time %s falls inside the investigation window for %s. "+
					"CRITICAL: mtime is not file creation and must not be treated as execution time "+
					"(timestamps can be altered or preserved by deploy/copy). Birth unavailable=%v. Not a webshell confirmation.",
				mtime.Format(time.RFC3339), rel, !birthOK,
			)
			add("webroot_mtime_in_window", detail)
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
				"Birth timestamps available=%d unavailable=%d. mtime is never treated as creation. Not a webshell scanner.",
			seen, phpLike, webrootInvestMaxDepth, len(out), item.BirthAvailable, item.BirthUnavailable,
		)
	}
	r.WebrootInvestigation = append(r.WebrootInvestigation, item)
	return out
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
