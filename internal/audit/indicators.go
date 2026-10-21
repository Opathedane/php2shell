package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Opathedane/php2shell/internal/rules"
)

// ScanFileHashes only inspects an explicitly authorized document root and only
// when the verified bundle includes exact SHA256 file hashes. No files execute.
func ScanFileHashes(r *Report, root string, indicators []rules.Indicator) {
	hashes := map[string][]rules.Indicator{}
	for _, in := range indicators {
		if in.Type == "file_sha256" {
			key := strings.ToLower(in.Value)
			hashes[key] = append(hashes[key], in)
		}
	}
	if len(hashes) == 0 {
		r.AddCheck("file_hash_indicators", "NOT_REQUESTED", "No file hashes in verified bundle")
		return
	}
	if root == "" {
		r.AddCheck("file_hash_indicators", "NOT_REQUESTED", "Supply --webroot to compare hashes of authorized local files")
		return
	}
	fi, e := os.Lstat(root)
	if e != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		r.AddCheck("file_hash_indicators", "UNAVAILABLE", "Invalid webroot; only real directories accepted")
		return
	}
	count := 0
	skipped := 0
	truncated := false
	const maxFiles = 3000
	const maxBytes = 256 << 20
	var bytesRead int64
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			skipped++
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			skipped++
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if count >= maxFiles || bytesRead >= maxBytes {
			truncated = true
			return filepath.SkipAll
		}
		info, e := d.Info()
		if e != nil || !info.Mode().IsRegular() {
			skipped++
			return nil
		}
		if info.Size() > 16<<20 {
			skipped++
			return nil
		}
		f, e := os.Open(p)
		if e != nil {
			skipped++
			return nil
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(f, 16<<20+1))
		f.Close()
		if e != nil || n > 16<<20 {
			skipped++
			return nil
		}
		count++
		bytesRead += n
		for _, in := range hashes[hex.EncodeToString(h.Sum(nil))] {
			if len(r.Findings) >= 200 {
				truncated = true
				return filepath.SkipAll
			}
			r.Findings = append(r.Findings, IndicatorFinding{RuleID: in.ID, Type: in.Type, Severity: in.Severity, Confidence: in.Confidence, Source: in.Source, Location: p, Detail: "Verified file SHA-256 matched signed indicator; analyst validation required"})
		}
		return nil
	})
	status := "PARTIAL"
	if truncated {
		status = "TRUNCATED"
	}
	r.AddCheck("file_hash_indicators", status, fmt.Sprintf("Hashed %d local regular files (%d bytes); skipped %d, max %d files / 256MiB total / 16MiB each; symlinks ignored", count, bytesRead, skipped, maxFiles))
}
