package audit

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ConfiguredSAPIContext summarizes inventory hints that help analysts reason about
// Calif-documented mod_php vs PHP-FPM interrupt differences. It never attests the
// active HTTP-serving SAPI and never claims PHP-FPM is safe.
type ConfiguredSAPIContext struct {
	ModPHPConfigured bool
	PHPFPMHints      bool
	PHPCGIHints      bool
	LiteSpeedHints   bool
	IISHints         bool
	Label            string // short card label
	Detail           string // full coverage/check detail
}

// ClassifyConfiguredSAPIContext inspects evidence already collected on the report.
// Configuration artifacts and process/binary names are hints only — not active-runtime proof.
func ClassifyConfiguredSAPIContext(r *Report) ConfiguredSAPIContext {
	ctx := ConfiguredSAPIContext{}
	if r == nil {
		ctx.Label = "Unknown / unverified"
		ctx.Detail = "No report evidence available to classify configured PHP SAPI hints."
		return ctx
	}
	for _, e := range r.Evidence {
		switch e.Type {
		case "apache_php_module_config":
			ctx.ModPHPConfigured = true
		case "apache_php_handler_config", "apache_remote_php_backend":
			low := strings.ToLower(e.Detail + " " + e.Location + " " + e.Name)
			if strings.Contains(low, "php-fpm") || strings.Contains(low, "fcgi") || strings.Contains(low, "proxy:unix") {
				ctx.PHPFPMHints = true
			}
			if strings.Contains(low, "php-cgi") || strings.Contains(low, "cgi") {
				ctx.PHPCGIHints = true
			}
		case "iis_php_handler_config":
			ctx.IISHints = true
			ctx.PHPCGIHints = true
		case "installed_package", "binary_path", "binary_static_version", "binary_path_inferred_version", "running_process":
			classifySAPINameHint(&ctx, e.Name, e.Location)
		}
	}
	ctx.Label, ctx.Detail = formatConfiguredSAPIContext(ctx)
	return ctx
}

func classifySAPINameHint(ctx *ConfiguredSAPIContext, name, location string) {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(name)))
	if base == "" {
		base = strings.ToLower(filepath.Base(strings.TrimSpace(location)))
	}
	base = strings.TrimSuffix(base, ".exe")
	loc := strings.ToLower(location)
	switch {
	case strings.HasPrefix(base, "php-fpm") || strings.Contains(base, "php-fpm") || strings.Contains(loc, "php-fpm"):
		ctx.PHPFPMHints = true
	case strings.HasPrefix(base, "lsphp") || strings.Contains(base, "lsphp"):
		ctx.LiteSpeedHints = true
	case strings.Contains(base, "php-cgi") || base == "php-cgi":
		ctx.PHPCGIHints = true
	case base == "w3wp" || base == "w3wp.exe":
		ctx.IISHints = true
	case strings.Contains(base, "libphp") || strings.Contains(loc, "libphp"):
		ctx.ModPHPConfigured = true
	}
}

func formatConfiguredSAPIContext(ctx ConfiguredSAPIContext) (label, detail string) {
	var kinds []string
	if ctx.ModPHPConfigured {
		kinds = append(kinds, "Apache mod_php (LoadModule / libphp evidence)")
	}
	if ctx.PHPFPMHints {
		kinds = append(kinds, "PHP-FPM (binary/package/process or FastCGI proxy hints)")
	}
	if ctx.PHPCGIHints {
		kinds = append(kinds, "PHP-CGI / FastCGI handler hints")
	}
	if ctx.LiteSpeedHints {
		kinds = append(kinds, "LiteSpeed lsphp hints")
	}
	if ctx.IISHints {
		kinds = append(kinds, "IIS/w3wp handler hints")
	}
	if len(kinds) == 0 {
		return "Unknown / unverified",
			"No configured mod_php, PHP-FPM, CGI, LiteSpeed, or IIS PHP handler hints were observed in this scan. " +
				"Missing inventory hints do not prove that PHP is missing from the host. Active HTTP-serving SAPI remains unverified. " +
				"Calif-documented interrupt behavior differs by SAPI: mod_php may reuse a worker after some startup fatals; " +
				"PHP-FPM exits on php_request_startup failure but remains exploitable via post-startup paths — do not treat FPM as safe."
	}
	label = "Configured SAPI hints (unverified active runtime)"
	detail = fmt.Sprintf(
		"Observed configured/inventory hints: %s. "+
			"These artifacts do NOT prove which SAPI currently serves HTTP. "+
			"Calif research: mod_php may continue into request shutdown / worker reuse after some startup fatals; "+
			"PHP-FPM terminates the worker on php_request_startup failure (FPM_EXIT_SOFTWARE) but can still be exploited "+
			"after successful startup (application-dependent decode + upload-progress paths). "+
			"Do not infer that PHP-FPM cannot be exploited. Patch and verify the active serving runtime separately.",
		strings.Join(kinds, "; "),
	)
	return label, detail
}
