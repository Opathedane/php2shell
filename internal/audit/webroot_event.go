package audit

import (
	"path/filepath"
	"strings"
	"time"
)

// Webroot investigation resource bounds (offline, read-only; never execute PHP).
const (
	webrootInvestMaxEntries = 25000
	webrootInvestMaxDepth   = 8
	webrootInvestMaxLeads   = 100
)

// WebrootLead is a sanitized filesystem investigation lead from an authorized --webroot.
// Never proof of a webshell. Modification time is never treated as file creation.
type WebrootLead struct {
	Path           string
	RelPath        string
	Kind           string // webroot_php_in_upload_dir | webroot_unusual_extension | webroot_birth_in_window | webroot_mtime_in_window
	Confidence     string // suspected | unconfirmed
	MtimeUTC       time.Time
	BirthUTC       time.Time
	BirthAvailable bool
	Detail         string
	DedupKey       string
}

// WebrootInvestigationCoverage summarizes one --webroot investigation walk.
type WebrootInvestigationCoverage struct {
	Root            string `json:"root"`
	Status          string `json:"status"`
	EntriesSeen     int    `json:"entries_seen"`
	PHPLikeSeen     int    `json:"php_like_seen"`
	Leads           int    `json:"leads"`
	BirthAvailable  int    `json:"birth_timestamps_available"`
	BirthUnavailable int   `json:"birth_timestamps_unavailable"`
	Truncated       bool   `json:"truncated,omitempty"`
	Detail          string `json:"detail,omitempty"`
}

var uploadDirTokens = []string{
	"upload", "uploads", "uploaded", "userfiles", "user_files",
	"tmp", "temp", "cache", "writable", "files", "media",
	"wp-content/uploads", "storage/app", "public/uploads",
}

var unusualPHPExt = map[string]bool{
	".phtml": true, ".php3": true, ".php4": true, ".php5": true,
	".php7": true, ".php8": true, ".phar": true, ".phps": true,
}

// Outer extensions that are not typically executed as PHP by web servers.
// Double names like readme.php.txt / config.php.bak are not unusual-PHP leads.
var nonExecutableOuterExt = map[string]bool{
	".txt": true, ".md": true, ".bak": true, ".old": true, ".orig": true,
	".dist": true, ".sample": true, ".disabled": true, ".swp": true,
	".log": true, ".csv": true, ".json": true, ".xml": true, ".yml": true,
	".yaml": true, ".ini": true, ".conf": true, ".example": true,
}

func isPHPLikeName(name string) bool {
	lower := strings.ToLower(name)
	ext := strings.ToLower(filepath.Ext(lower))
	if ext == ".php" || unusualPHPExt[ext] {
		return true
	}
	// Double extension: foo.php.jpg / bar.phtml.png
	base := strings.TrimSuffix(lower, ext)
	inner := strings.ToLower(filepath.Ext(base))
	if inner == ".php" || unusualPHPExt[inner] {
		return true
	}
	return false
}

func isUnusualPHPExtension(name string) bool {
	lower := strings.ToLower(name)
	ext := strings.ToLower(filepath.Ext(lower))
	if unusualPHPExt[ext] {
		return true
	}
	base := strings.TrimSuffix(lower, ext)
	inner := strings.ToLower(filepath.Ext(base))
	if (inner == ".php" || unusualPHPExt[inner]) && ext != "" && ext != ".php" {
		if nonExecutableOuterExt[ext] {
			return false // e.g. readme.php.txt — not treated as executable PHP lead
		}
		return true // e.g. shell.php.jpg
	}
	return false
}

func pathLooksLikeUploadDir(rel string) bool {
	norm := strings.ToLower(filepath.ToSlash(rel))
	for _, tok := range uploadDirTokens {
		if strings.Contains(norm, tok) {
			return true
		}
	}
	return false
}

func pathDepth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return 0
	}
	rel = filepath.Clean(rel)
	if rel == "." {
		return 0
	}
	return len(strings.Split(filepath.ToSlash(rel), "/"))
}
