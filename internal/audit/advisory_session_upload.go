package audit

import (
	"fmt"
	"strings"
)

// Informational advisory CVE-2026-115560 (PHP.net 2026-10-23).
// No official fixed versions published as of that announcement — do not invent them.
const (
	AdvisoryCVE115560     = "CVE-2026-115560"
	AdvisoryURL115560     = "https://www.php.net/archive/2026.php#2026-10-23-1"
	AdvisoryDate115560    = "2026-10-23"
	Advisory115560Summary = "Potential RCE vector involving session upload progress with an unusual serialize_handler change (php_binary/php_serialize → php via ini_set before session_start). Separate from CVE-2026-109618 / CVE-2026-109619."
)

// AdditionalAdvisory is a conservative, evidence-qualified review of a secondary PHP advisory.
// It never claims definitive vulnerability or safety from static configuration alone.
type AdditionalAdvisory struct {
	CVE              string `json:"cve"`
	Title            string `json:"title"`
	Status           string `json:"status"`
	Priority         string `json:"priority"` // REVIEW only — never CRITICAL from static config alone
	ObservedConfig   string `json:"observed_config,omitempty"`
	MissingEvidence  string `json:"missing_evidence,omitempty"`
	RequiredAction   string `json:"required_action"`
	Qualification    string `json:"qualification"`
	AdvisoryURL      string `json:"advisory_url"`
	SourceFiles      string `json:"source_files,omitempty"`
	SampleOrTemplate bool   `json:"sample_or_template_only,omitempty"`
}

type iniObs struct {
	value    string
	location string
	class    string // primary | scan_dir_fragment | sample_or_template | unknown
}

// EvaluateSessionUploadProgressAdvisory assesses CVE-2026-115560 from observed php.ini text only.
// Does not change VulnerabilityStatus / PatchAssessments for 109618/109619, and never flips ScanIncomplete.
func EvaluateSessionUploadProgressAdvisory(r *Report) {
	if r == nil {
		return
	}
	handlers, uploads := collectSessionIniObservations(r)
	adv := assessSessionUpload115560(handlers, uploads)
	if adv.Status == "" {
		return
	}
	r.AdditionalAdvisories = append(r.AdditionalAdvisories, adv)
	// Concise operator guidance — not a host-wide CRITICAL finding.
	switch adv.Status {
	case "MANUAL_VERIFICATION_REQUIRED":
		r.AddAction("CVE-2026-115560: verify whether any application calls ini_set('session.serialize_handler','php') before session_start() while upload progress remains enabled; prefer session.upload_progress.enabled=0 until PHP publishes a regular fix release. Static config cannot prove runtime behavior: " + AdvisoryURL115560)
	case "MITIGATION_CONFIGURED_NOT_RUNTIME_VERIFIED":
		r.AddAction("CVE-2026-115560: observed session.upload_progress.enabled appears disabled (PHP recommended temporary mitigation); restart workers and confirm the effective SAPI setting — not runtime-verified: " + AdvisoryURL115560)
	case "UNDETERMINED":
		if strings.Contains(adv.MissingEvidence, "conflict") || strings.Contains(strings.ToLower(adv.Qualification), "conflict") {
			r.AddAction("CVE-2026-115560: resolve conflicting php.ini observations for session.serialize_handler / session.upload_progress.enabled, then re-scan: " + AdvisoryURL115560)
		}
	}
}

func collectSessionIniObservations(r *Report) (handlers, uploads []iniObs) {
	for _, e := range r.Evidence {
		if e.Type != "configuration_observation" {
			continue
		}
		val := firstIniValueToken(e.Detail)
		class := iisDetailField(e.Detail, "ini_class")
		if class == "" {
			class = "unknown"
		}
		o := iniObs{value: val, location: e.Location, class: class}
		switch strings.ToLower(strings.TrimSpace(e.Name)) {
		case "session.serialize_handler":
			handlers = append(handlers, o)
		case "session.upload_progress.enabled":
			uploads = append(uploads, o)
		}
	}
	return handlers, uploads
}

func firstIniValueToken(detail string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return ""
	}
	// Detail begins with the setting value, then optional "; key=..." annotations.
	if i := strings.Index(detail, ";"); i >= 0 {
		detail = strings.TrimSpace(detail[:i])
	}
	return detail
}

func preferNonSample(obs []iniObs) (chosen []iniObs, sampleOnly bool) {
	var primary, other, sample []iniObs
	for _, o := range obs {
		switch o.class {
		case "sample_or_template":
			sample = append(sample, o)
		case "primary_candidate", "scan_dir_fragment", "fpm_pool_fragment", "named_variant", "primary":
			primary = append(primary, o)
		default:
			if o.class == "" || o.class == "unknown" {
				other = append(other, o)
			} else {
				other = append(other, o)
			}
		}
	}
	if len(primary) > 0 {
		return primary, false
	}
	if len(other) > 0 {
		return other, false
	}
	return sample, len(sample) > 0
}

func normalizeHandler(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func parseUploadProgressEnabled(v string) (enabled bool, known bool) {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.Trim(s, `"'`)
	switch s {
	case "1", "on", "true", "yes":
		return true, true
	case "0", "off", "false", "no":
		return false, true
	default:
		return false, false
	}
}

func uniqueValues(obs []iniObs, norm func(string) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range obs {
		v := norm(o.value)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func joinLocations(obs []iniObs) string {
	seen := map[string]bool{}
	var parts []string
	for _, o := range obs {
		if o.location == "" || seen[o.location] {
			continue
		}
		seen[o.location] = true
		parts = append(parts, o.location)
		if len(parts) >= 4 {
			parts = append(parts, "…")
			break
		}
	}
	return strings.Join(parts, "; ")
}

func assessSessionUpload115560(handlers, uploads []iniObs) AdditionalAdvisory {
	base := AdditionalAdvisory{
		CVE:         AdvisoryCVE115560,
		Title:       "Session upload progress / serialize_handler (informational)",
		Priority:    "REVIEW",
		AdvisoryURL: AdvisoryURL115560,
		Qualification: "Static php.ini text only. PHP documents that exploitation also requires application code to ini_set serialize_handler to php before session_start(). " +
			"No official fixed version list was published with the 2026-10-23 informational advisory. Not a definitive vulnerable/safe verdict.",
	}

	hChosen, hSampleOnly := preferNonSample(handlers)
	uChosen, uSampleOnly := preferNonSample(uploads)
	base.SampleOrTemplate = (len(handlers)+len(uploads) > 0) && hSampleOnly && uSampleOnly &&
		len(handlers) == len(filterSample(handlers)) && len(uploads) == len(filterSample(uploads))
	// If we fell back to samples because no primary exists for a key side, mark sample influence.
	if hSampleOnly && len(handlers) > 0 {
		base.SampleOrTemplate = true
	}
	if uSampleOnly && len(uploads) > 0 && len(filterNonSample(uploads)) == 0 {
		base.SampleOrTemplate = true
	}

	hVals := uniqueValues(hChosen, normalizeHandler)
	// Upload progress: track distinct boolean interpretations
	var upEnabled, upDisabled, upUnknown int
	for _, o := range uChosen {
		en, ok := parseUploadProgressEnabled(o.value)
		if !ok {
			upUnknown++
			continue
		}
		if en {
			upEnabled++
		} else {
			upDisabled++
		}
	}

	locs := joinLocations(append(append([]iniObs{}, hChosen...), uChosen...))
	base.SourceFiles = locs

	obsParts := []string{}
	if len(hVals) > 0 {
		obsParts = append(obsParts, "session.serialize_handler="+strings.Join(hVals, "|"))
	} else {
		obsParts = append(obsParts, "session.serialize_handler=(not observed)")
	}
	switch {
	case upEnabled > 0 && upDisabled > 0:
		obsParts = append(obsParts, "session.upload_progress.enabled=(conflicting On/Off)")
	case upEnabled > 0:
		obsParts = append(obsParts, "session.upload_progress.enabled=On")
	case upDisabled > 0:
		obsParts = append(obsParts, "session.upload_progress.enabled=Off")
	case upUnknown > 0:
		obsParts = append(obsParts, "session.upload_progress.enabled=(unparseable)")
	default:
		obsParts = append(obsParts, "session.upload_progress.enabled=(not observed)")
	}
	base.ObservedConfig = strings.Join(obsParts, "; ")

	// Conflicts → UNDETERMINED
	if len(hVals) > 1 || (upEnabled > 0 && upDisabled > 0) {
		base.Status = "UNDETERMINED"
		base.MissingEvidence = "conflicting configuration observations across inspected php.ini candidates"
		base.RequiredAction = "Identify which php.ini (and SAPI) is active for the HTTP-serving runtime, resolve conflicting session.serialize_handler / session.upload_progress.enabled values, restart workers, and re-scan."
		base.Qualification += " Conflicting observed values prevent a single status."
		if base.SampleOrTemplate {
			base.Qualification += " Some or all observations came from sample/template ini names only."
		}
		return base
	}

	// Explicit mitigation: upload progress disabled (PHP recommended temporary measure).
	if upDisabled > 0 && upEnabled == 0 && upUnknown == 0 {
		base.Status = "MITIGATION_CONFIGURED_NOT_RUNTIME_VERIFIED"
		base.MissingEvidence = "effective runtime SAPI setting and worker restart not verified; application ini_set behavior not inspected"
		base.RequiredAction = "Confirm session.upload_progress.enabled=0 is effective for the serving SAPI (not only a sample file), restart all PHP workers, and keep the mitigation until PHP publishes a regular fix release."
		if len(hVals) == 0 {
			base.MissingEvidence += "; session.serialize_handler not observed in scanned configuration"
		}
		if base.SampleOrTemplate {
			base.Status = "UNDETERMINED"
			base.MissingEvidence = "upload progress Off observed only in sample/template ini candidates"
			base.RequiredAction = "Inspect the active (non-sample) php.ini for the HTTP-serving SAPI and confirm session.upload_progress.enabled=0 there."
		}
		return base
	}

	riskyHandler := false
	phpHandler := false
	for _, v := range hVals {
		switch v {
		case "php_binary", "php_serialize":
			riskyHandler = true
		case "php":
			phpHandler = true
		}
	}

	// Scenario A: risky initial handler + upload progress enabled
	if riskyHandler && upEnabled > 0 {
		base.Status = "MANUAL_VERIFICATION_REQUIRED"
		base.MissingEvidence = "whether application code calls ini_set('session.serialize_handler','php') before session_start(); effective runtime settings; which SAPI serves HTTP"
		base.RequiredAction = "Until a regular PHP bugfix addresses CVE-2026-115560, set session.upload_progress.enabled=0 in a pre-request config (php.ini / FPM pool / server config — not ini_set/.user.ini alone), restart workers, and review apps that change serialize_handler at runtime. Do not treat this finding as confirmed RCE."
		if base.SampleOrTemplate {
			base.Qualification += " Observations may include sample/template ini files only — verify the active SAPI config."
		}
		return base
	}

	// Risky handler but upload progress not observed as enabled
	if riskyHandler && upEnabled == 0 && upDisabled == 0 {
		base.Status = "UNDETERMINED"
		base.MissingEvidence = "session.upload_progress.enabled not observed (or unparseable); runtime ini_set behavior unknown"
		base.RequiredAction = "Locate the active php.ini for the serving SAPI, confirm session.upload_progress.enabled, and prefer disabling it until the next regular PHP release if serialize_handler is php_binary/php_serialize."
		return base
	}

	// Scenario C: handler configured as php (static only)
	if phpHandler && !riskyHandler {
		base.Status = "NO_RISKY_INITIAL_HANDLER_OBSERVED"
		base.MissingEvidence = "runtime ini_set changes; effective SAPI config; upload-progress effective state if not observed"
		base.RequiredAction = "No risky initial serialize_handler (php_binary/php_serialize) was observed in scanned non-conflicting config. This does not prove the host is unaffected — applications can still change handlers at runtime. Keep upload-progress mitigation under review per PHP.net."
		if upEnabled > 0 {
			base.ObservedConfig += " (upload progress still observed On — mitigation optional per PHP if apps never change handler)"
		}
		return base
	}

	// Upload progress enabled but handler missing/unknown
	if upEnabled > 0 && len(hVals) == 0 {
		base.Status = "UNDETERMINED"
		base.MissingEvidence = "session.serialize_handler not observed in scanned configuration; runtime application behavior unknown"
		base.RequiredAction = "Inspect active php.ini for session.serialize_handler. If it is php_binary or php_serialize, or if apps call ini_set before session_start(), disable session.upload_progress.enabled until PHP's regular fix release."
		return base
	}

	// Nothing useful observed
	if len(hVals) == 0 && upEnabled == 0 && upDisabled == 0 {
		base.Status = "UNDETERMINED"
		base.MissingEvidence = "neither session.serialize_handler nor session.upload_progress.enabled observed in inspected configuration candidates"
		base.RequiredAction = "Supply readable active php.ini paths (--php-ini / --config-root) for the HTTP-serving SAPI, or verify settings manually. Prefer session.upload_progress.enabled=0 until PHP publishes a regular fix if you cannot confirm application behavior."
		return base
	}

	// Handler present but not php/php_binary/php_serialize (unusual), or other residual cases
	base.Status = "UNDETERMINED"
	base.MissingEvidence = "observed serialize_handler value is not one of php / php_binary / php_serialize, or evidence is incomplete"
	base.RequiredAction = "Review the observed session.serialize_handler value against application requirements and PHP's CVE-2026-115560 notes; confirm upload-progress policy for the serving SAPI."
	return base
}

func filterSample(obs []iniObs) []iniObs {
	var out []iniObs
	for _, o := range obs {
		if o.class == "sample_or_template" {
			out = append(out, o)
		}
	}
	return out
}

func filterNonSample(obs []iniObs) []iniObs {
	var out []iniObs
	for _, o := range obs {
		if o.class != "sample_or_template" {
			out = append(out, o)
		}
	}
	return out
}

// Format helper for tests / diagnostics.
func FormatAdditionalAdvisoryLine(a AdditionalAdvisory) string {
	return fmt.Sprintf("%s status=%s observed=%s", a.CVE, a.Status, a.ObservedConfig)
}
