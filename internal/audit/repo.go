package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var dockerPHP = regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(?:\S+/)?php:([^\s]+)`)
var dockerLike = regexp.MustCompile(`(?im)^\s*(?:image|container):\s*["']?(?:\S+/)?php:([^\s"']+)`)
var composerPHP = regexp.MustCompile(`(?i)"php"\s*:\s*"([^"]+)"`)
var actionPHP = regexp.MustCompile(`(?im)^\s*php-version\s*:\s*["']?([0-9][^\s"']*)`)
var explicitVer = regexp.MustCompile(`(?m)^\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*$`)

func relevantRepoFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base == ".php-version" || base == ".tool-versions" || base == "composer.json" || base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") || base == "docker-compose.yml" || base == "docker-compose.yaml" || base == "compose.yml" || base == "compose.yaml" || base == ".gitlab-ci.yml" {
		return true
	}
	norm := filepath.ToSlash(path)
	return strings.Contains(norm, "/.github/workflows/") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"))
}

func ScanRepository(r *Report, root string) {
	rc := RepoCoverage{Root: root, Status: "PARTIAL"}
	fi, err := os.Lstat(root)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		rc.Status = "UNAVAILABLE"
		rc.Detail = "Not an accessible real directory"
		r.Repositories = append(r.Repositories, rc)
		return
	}
	walked, found := 0, 0
	truncated := false
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			rc.SkippedFiles++
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			rc.SkippedFiles++
			return nil
		}
		if d.IsDir() {
			if path != root && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor" || d.Name() == ".venv") {
				return filepath.SkipDir
			}
			return nil
		}
		walked++
		if walked > 40000 || found >= 500 {
			truncated = true
			return filepath.SkipAll
		}
		if !relevantRepoFile(path) {
			return nil
		}
		b, err := ReadRegular(path, 2<<20)
		if err != nil {
			rc.SkippedFiles++
			return nil
		}
		rc.InspectedFiles++
		txt := string(b)
		record := func(kind, version string) {
			if found >= 500 {
				truncated = true
				return
			}
			r.AddEvidence(Evidence{Type: "repository_declaration", Name: kind, Version: strings.TrimSpace(version), Source: "static repository manifest", Location: path, Interpretation: "DECLARED_ONLY_NOT_DEPLOYED_OR_PATCH_VERIFIED"})
			found++
		}
		for _, m := range dockerPHP.FindAllStringSubmatch(txt, 80) {
			record("Docker PHP image tag", m[1])
		}
		for _, m := range dockerLike.FindAllStringSubmatch(txt, 80) {
			record("PHP container image declaration", m[1])
		}
		if filepath.Base(path) == "composer.json" {
			for _, m := range composerPHP.FindAllStringSubmatch(txt, 20) {
				record("Composer PHP requirement", m[1])
			}
		}
		if strings.Contains(filepath.ToSlash(path), "/.github/workflows/") || strings.HasSuffix(path, ".gitlab-ci.yml") {
			for _, m := range actionPHP.FindAllStringSubmatch(txt, 30) {
				record("CI PHP version", m[1])
			}
		}
		if filepath.Base(path) == ".php-version" {
			if m := explicitVer.FindStringSubmatch(txt); len(m) > 1 {
				record(".php-version", m[1])
			}
		}
		if filepath.Base(path) == ".tool-versions" {
			for _, line := range strings.Split(txt, "\n") {
				part := strings.Fields(line)
				if len(part) > 1 && part[0] == "php" {
					record("asdf PHP declaration", part[1])
				}
			}
		}
		return nil
	})
	if err != nil {
		rc.Detail = "Some repository entries could not be scanned: " + err.Error()
		rc.SkippedFiles++
	}
	if truncated {
		rc.Status = "TRUNCATED"
		r.AddWarning("Repository scan limited to 40,000 files / 500 findings: " + root)
	}
	if rc.Detail == "" {
		rc.Detail = fmt.Sprintf("Read %d relevant manifest files, skipped %d files; no deployed runtime verification", rc.InspectedFiles, rc.SkippedFiles)
	}
	r.Repositories = append(r.Repositories, rc)
}
