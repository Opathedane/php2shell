package audit

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxIISHandlerEvidence = 128
	maxIISSiteEvidence    = 256
	maxWebConfigBytes     = 2 << 20
	maxSiteWebConfigs     = 64
)

// IISSiteMapping is one virtualDirectory physical mapping under a site/application.
// Nested applications and non-root vdirs are included when present in applicationHost.config.
type IISSiteMapping struct {
	SiteName     string
	AppPath      string // e.g. "/" or "/api"
	VDirPath     string // e.g. "/" or "/static"
	PhysicalPath string // configured path (may be on non-system drives)
}

// parseIISHandlers extracts FastCGI/handler entries that appear PHP-related.
// Handlers may appear under <location> sections; this walk records matches but does
// not fully simulate IIS lock/clear/remove inheritance merges.
func parseIISHandlers(path string, data []byte) ([]Evidence, error) {
	return parseIISHandlersWithContext(path, data, "", "", "")
}

func parseIISHandlersWithContext(configPath string, data []byte, siteName, appPath, sitePhysical string) ([]Evidence, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	result := []Evidence{}
	source := "IIS applicationHost.config (static XML)"
	if strings.HasSuffix(strings.ToLower(filepath.Base(configPath)), "web.config") {
		source = "IIS site/application web.config (static XML)"
	}
	// Track <location path="..."> ancestry for site association. Does not merge
	// lockItem/clear/remove inheritance — each matching add/application is recorded as-is.
	var locationStack []string
	for {
		token, e := decoder.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		switch el := token.(type) {
		case xml.StartElement:
			lname := strings.ToLower(el.Name.Local)
			if lname == "location" {
				locPath := ""
				for _, a := range el.Attr {
					if strings.EqualFold(a.Name.Local, "path") {
						locPath = a.Value
					}
				}
				locationStack = append(locationStack, locPath)
				continue
			}
			if lname != "add" && lname != "application" {
				continue
			}
			attrs := map[string]string{}
			for _, a := range el.Attr {
				attrs[strings.ToLower(a.Name.Local)] = a.Value
			}
			module := strings.ToLower(attrs["modules"])
			exec := attrs["scriptprocessor"]
			if exec == "" {
				exec = attrs["fullpath"]
			}
			if (strings.Contains(module, "fastcgi") && strings.Contains(strings.ToLower(attrs["path"]), "php")) ||
				strings.Contains(strings.ToLower(exec), "php") ||
				strings.Contains(strings.ToLower(attrs["path"]), "*.php") {
				detail := FormatIISHandlerDetail(attrs["path"], attrs["modules"], exec)
				effSite := siteName
				if effSite == "" && len(locationStack) > 0 {
					// location path is typically "SiteName" or "SiteName/app"
					effSite = locationStack[len(locationStack)-1]
				}
				if effSite != "" {
					detail += "; site=" + effSite
				}
				if appPath != "" {
					detail += "; app_path=" + appPath
				}
				if sitePhysical != "" {
					detail += "; site_physical_path=" + normalizeWindowsConfigPath(sitePhysical)
				}
				if len(locationStack) > 0 && locationStack[len(locationStack)-1] != "" {
					detail += "; location_path=" + locationStack[len(locationStack)-1]
				}
				result = append(result, Evidence{
					Type: "iis_php_handler_config", Name: attrs["name"], Source: source, Location: configPath,
					Detail: detail, Interpretation: "CONFIGURED_HANDLER_NOT_VERIFIED_SERVING_RUNTIME",
				})
				if len(result) >= maxIISHandlerEvidence {
					return result, nil
				}
			}
		case xml.EndElement:
			if strings.EqualFold(el.Name.Local, "location") && len(locationStack) > 0 {
				locationStack = locationStack[:len(locationStack)-1]
			}
		}
	}
	return result, nil
}

// parseIISSiteMappings extracts site / application / virtualDirectory physical paths.
func parseIISSiteMappings(data []byte) ([]IISSiteMapping, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var out []IISSiteMapping
	var siteName, appPath string
	inSite, inApp := false, false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch el := token.(type) {
		case xml.StartElement:
			switch strings.ToLower(el.Name.Local) {
			case "site":
				inSite = true
				siteName = ""
				for _, a := range el.Attr {
					if strings.EqualFold(a.Name.Local, "name") {
						siteName = a.Value
					}
				}
			case "application":
				if !inSite {
					continue
				}
				inApp = true
				appPath = "/"
				for _, a := range el.Attr {
					if strings.EqualFold(a.Name.Local, "path") {
						appPath = a.Value
					}
				}
			case "virtualdirectory":
				if !inSite || !inApp || siteName == "" {
					continue
				}
				attrs := map[string]string{}
				for _, a := range el.Attr {
					attrs[strings.ToLower(a.Name.Local)] = a.Value
				}
				phys := strings.TrimSpace(attrs["physicalpath"])
				if phys == "" {
					continue
				}
				vpath := attrs["path"]
				if vpath == "" {
					vpath = "/"
				}
				out = append(out, IISSiteMapping{
					SiteName: siteName, AppPath: appPath, VDirPath: vpath, PhysicalPath: phys,
				})
				if len(out) >= maxIISSiteEvidence {
					return out, nil
				}
			}
		case xml.EndElement:
			switch strings.ToLower(el.Name.Local) {
			case "site":
				inSite, inApp, siteName, appPath = false, false, "", ""
			case "application":
				inApp, appPath = false, ""
			}
		}
	}
	return out, nil
}

// parseIISSites returns one mapping per site preferring the site root application "/" + vdir "/".
// Retained for simpler callers; prefer parseIISSiteMappings for nested apps.
func parseIISSites(data []byte) ([]IISSite, error) {
	maps, err := parseIISSiteMappings(data)
	if err != nil {
		return nil, err
	}
	var sites []IISSite
	seen := map[string]bool{}
	// Prefer root app+vdir, else first mapping per site.
	for _, m := range maps {
		if m.AppPath == "/" && m.VDirPath == "/" && !seen[m.SiteName] {
			sites = append(sites, IISSite{Name: m.SiteName, PhysicalPath: m.PhysicalPath})
			seen[m.SiteName] = true
		}
	}
	for _, m := range maps {
		if seen[m.SiteName] {
			continue
		}
		sites = append(sites, IISSite{Name: m.SiteName, PhysicalPath: m.PhysicalPath})
		seen[m.SiteName] = true
	}
	return sites, nil
}

// IISSite is a backwards-compatible site root summary.
type IISSite struct {
	Name         string
	PhysicalPath string
}

func mappingEvidence(configPath string, m IISSiteMapping) Evidence {
	label := m.SiteName
	if m.AppPath != "" && m.AppPath != "/" {
		label += m.AppPath
	}
	if m.VDirPath != "" && m.VDirPath != "/" {
		label += " vdir:" + m.VDirPath
	}
	return Evidence{
		Type:     "iis_site_config",
		Name:     label,
		Source:   "IIS applicationHost.config site/application/vdir (static XML)",
		Location: normalizeWindowsConfigPath(m.PhysicalPath),
		Detail: fmt.Sprintf(
			"site=%s; app_path=%s; vdir_path=%s; physical_path=%s; php_filenames_require_explicit_webroot; handler_inheritance_not_fully_simulated",
			m.SiteName, m.AppPath, m.VDirPath, normalizeWindowsConfigPath(m.PhysicalPath),
		),
		Interpretation: "CONFIGURED_SITE_PATH_NOT_PROOF_PHP_IS_SERVED_OR_ACTIVE_RUNTIME",
	}
}

func siteEvidence(configPath string, site IISSite) Evidence {
	return mappingEvidence(configPath, IISSiteMapping{SiteName: site.Name, AppPath: "/", VDirPath: "/", PhysicalPath: site.PhysicalPath})
}

// ingestIISHandlerEvidence records handler rows and inspects referenced PHP binaries when accessible.
func ingestIISHandlerEvidence(r *Report, entries []Evidence) (inspected, inaccessible int) {
	seenExe := map[string]bool{}
	for _, v := range entries {
		r.AddEvidence(v)
		configured := HandlerExecutableFromDetail(v.Detail)
		if !HandlerExecutableLooksLikePHP(configured) {
			continue
		}
		exe := ResolveHandlerExecutablePath(configured)
		key := normalizeInstallPath(configured)
		if exe != "" {
			key = normalizeInstallPath(exe)
		}
		if seenExe[key] {
			continue
		}
		seenExe[key] = true
		target := exe
		if target == "" {
			target = configured
		}
		if target == "" || !isSafeRegularFile(target) {
			inaccessible++
			r.AddEvidence(Evidence{
				Type: "binary_path", Name: windowsPathBase(configured), Source: "IIS handler scriptProcessor (inaccessible or unresolved)",
				Location: configured,
				Detail:   "configured_handler_binary_not_readable; version unknown; site patch status incomplete for this handler",
				Interpretation: "PRESENT_VERSION_UNKNOWN_NOT_RUNTIME_VERIFIED",
			})
			r.AddWarning(fmt.Sprintf("IIS PHP handler binary not accessible for version inspection: %s", configured))
			continue
		}
		inspected++
		AddBinaryVersionEvidence(r, target, filepath.Base(target), "IIS handler scriptProcessor static binary inspection")
	}
	return inspected, inaccessible
}

// ApplyIISApplicationHostInventory records site/app/vdir paths, global handlers, and per-path web.config
// PHP handlers without walking website trees for .php files or simulating full IIS inheritance.
func ApplyIISApplicationHostInventory(r *Report, configPath string, data []byte) {
	entries, e := parseIISHandlers(configPath, data)
	if e != nil {
		r.AddCheck("windows_iis_configuration", "INCOMPLETE", "Invalid IIS config XML: "+e.Error())
		return
	}
	inspected, inaccessible := ingestIISHandlerEvidence(r, entries)

	maps, siteErr := parseIISSiteMappings(data)
	if siteErr != nil {
		r.AddWarning("IIS site inventory parse incomplete: " + siteErr.Error())
	}
	webConfigHandlers := 0
	webConfigsRead := 0
	seenPhys := map[string]bool{}
	for _, m := range maps {
		r.AddEvidence(mappingEvidence(configPath, m))
		physKey := normalizeInstallPath(m.PhysicalPath)
		if seenPhys[physKey] {
			continue
		}
		if webConfigsRead >= maxSiteWebConfigs {
			continue
		}
		seenPhys[physKey] = true
		n, _, st, wi, wa := inspectMappingWebConfig(r, m)
		webConfigsRead++
		inspected += wi
		inaccessible += wa
		if st == "read" {
			webConfigHandlers += n
		}
	}

	status := "PARTIAL"
	if inaccessible > 0 {
		status = "INCOMPLETE"
	}
	if len(entries) >= maxIISHandlerEvidence || len(maps) >= maxIISSiteEvidence {
		status = "TRUNCATED"
	}
	r.AddCheck("windows_iis_configuration", status, fmt.Sprintf(
		"Read IIS applicationHost.config; %d PHP-related handler/FastCGI entries; %d site/app/vdir physical paths; %d web.config files examined (%d PHP handlers); %d handler binaries version-inspected; %d handler binaries inaccessible; active serving runtime unverified; IIS location/lock inheritance not fully simulated; .php filenames require explicit --webroot (no drive-wide scan)",
		len(entries), len(maps), webConfigsRead, webConfigHandlers, inspected, inaccessible,
	))
}

func inspectSiteWebConfig(r *Report, site IISSite) (handlers int, webConfigPath string, status string) {
	n, p, st, _, _ := inspectMappingWebConfig(r, IISSiteMapping{SiteName: site.Name, AppPath: "/", VDirPath: "/", PhysicalPath: site.PhysicalPath})
	return n, p, st
}

func inspectMappingWebConfig(r *Report, m IISSiteMapping) (handlers int, webConfigPath string, status string, inspected, inaccessible int) {
	resolved := ResolveConfiguredWindowsPath(m.PhysicalPath)
	if resolved == "" {
		return 0, "", "unresolved_path", 0, 0
	}
	fi, err := os.Lstat(resolved)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return 0, "", "inaccessible", 0, 0
	}
	webConfigPath = filepath.Join(resolved, "web.config")
	b, err := ReadRegular(webConfigPath, maxWebConfigBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, webConfigPath, "no_web_config", 0, 0
		}
		return 0, webConfigPath, "unreadable", 0, 0
	}
	entries, err := parseIISHandlersWithContext(webConfigPath, b, m.SiteName, m.AppPath, m.PhysicalPath)
	if err != nil {
		r.AddWarning(fmt.Sprintf("IIS site %q app %q web.config parse incomplete: %v", m.SiteName, m.AppPath, err))
		return 0, webConfigPath, "parse_error", 0, 0
	}
	inspected, inaccessible = ingestIISHandlerEvidence(r, entries)
	return len(entries), webConfigPath, "read", inspected, inaccessible
}
