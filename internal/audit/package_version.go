package audit

import (
	"regexp"
	"strconv"
	"strings"
)

// Unversioned meta/transitional packages (e.g. Ubuntu php-common) often carry
// packaging revisions such as 24.04.1 that are not PHP runtime releases.
var unversionedPHPMeta = regexp.MustCompile(`(?i)^php-(?:common|cli|fpm|cgi|mysql|opcache|xml|curl|mbstring|gd|zip|bcmath|intl|soap|readline|sqlite3|pgsql|ldap|snmp|tidy|xsl|enchant|gmp|imap|interbase|odbc|pspell|sybase|dba|dev|pear|phpdbg)$`)

var debianBranchInPackage = regexp.MustCompile(`(?i)^(?:libapache2-mod-)?php(\d)(?:\.(\d))?`)

// PackagePHPVersion extracts a comparable PHP release from package metadata.
// Packaging revisions and dependency metapackage versions are rejected.
func PackagePHPVersion(packageName, rawVersion string) string {
	name := strings.TrimSpace(packageName)
	raw := strings.TrimSpace(rawVersion)
	if name == "" || raw == "" {
		return ""
	}
	if isUnversionedPHPMetaPackage(name) {
		return ""
	}
	ver := versionNumber.FindString(raw)
	if ver == "" || !looksLikePHPReleaseVersion(ver) {
		return ""
	}
	// Prefer branch encoded in the package name when present (php8.3-fpm → 8.3.x).
	if branch := debianPHPBranch(name); branch != "" {
		if !strings.HasPrefix(ver, branch+".") && ver != branch {
			// Version does not match the package's PHP branch (e.g. stray packaging number).
			return ""
		}
	}
	return ver
}

func isUnversionedPHPMetaPackage(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "php" {
		return true
	}
	return unversionedPHPMeta.MatchString(n)
}

func looksLikePHPReleaseVersion(v string) bool {
	match := cleanPHPVersion.FindStringSubmatch(strings.TrimSpace(v))
	if match == nil || match[3] == "" {
		return false
	}
	major, _ := strconv.Atoi(match[1])
	// Supported historical and current PHP majors used in production inventories.
	return major >= 5 && major <= 8
}

func debianPHPBranch(packageName string) string {
	m := debianBranchInPackage.FindStringSubmatch(packageName)
	if m == nil {
		return ""
	}
	if m[2] == "" {
		// php83-fpm style (two-digit minor encoding) is handled elsewhere; bare php8 is incomplete.
		return ""
	}
	return m[1] + "." + m[2]
}

// IsPHPExtensionPackage reports packages that share an install's version but are not the SAPI binary itself.
func IsPHPExtensionPackage(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if debianPHPPackage.MatchString(n) {
		return false
	}
	if strings.HasPrefix(n, "libapache2-mod-php") {
		return false
	}
	if m := debianBranchInPackage.FindStringSubmatch(n); m != nil && m[2] != "" {
		// php8.3-common is core metadata for the install; treat as install member, not a separate SAPI.
		rest := n[len(m[0]):]
		if rest == "" || rest == "-common" {
			return false
		}
		if strings.HasPrefix(rest, "-") {
			return true
		}
	}
	return false
}
