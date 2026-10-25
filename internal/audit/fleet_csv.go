package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Fleet CSV schema versions. Writers emit v3; rollup/parsers accept v1–v3.
const (
	FleetCSVSchemaV1 = "php2shell-fleet-csv/v1"
	FleetCSVSchemaV2 = "php2shell-fleet-csv/v2"
	FleetCSVSchemaV3 = "php2shell-fleet-csv/v3"
	FleetCSVSchema   = FleetCSVSchemaV3
)

// FleetCSVColumns is the stable header for scan CSV output and fleet rollup (v3).
// v3 appends independent investigation statuses; v1/v2 remain readable by name.
var FleetCSVColumns = []string{
	"schema_version",
	"scan_id",
	"hostname",
	"os",
	"architecture",
	"scan_timestamp_utc",
	"scanner_version",
	"customer_label",
	"install_id",
	"php_version",
	"version_confidence",
	"version_evidence",
	"install_path",
	"component_name",
	"upstream_minimum_fixed",
	"patch_status",
	"remediation_priority",
	"recommended_action",
	"qualification",
	"active_http_runtime_status",
	"compromise_status",
	"host_vulnerability_status",
	"discovery_completeness",
	"limitations_summary",
	// v2 configuration discovery (supplementary; never version/runtime authority)
	"config_discovery_status",
	"config_candidate_count",
	"config_setting_observation_count",
	"config_correlated_to_install",
	"config_primary_ini_path",
	"config_ini_classes",
	// v3 compromise investigation (independent axes; never CLEAN / CONFIRMED)
	"exploitation_attempt_status",
	"possible_compromise_status",
	"investigation_coverage",
	"investigation_window_from_utc",
	"investigation_window_to_utc",
}

// FleetRow is one logical PHP installation (or one host-level placeholder).
type FleetRow struct {
	SchemaVersion            string
	ScanID                   string
	Hostname                 string
	OS                       string
	Architecture             string
	ScanTimestampUTC         string
	ScannerVersion           string
	CustomerLabel            string
	InstallID                string
	PHPVersion               string
	VersionConfidence        string
	VersionEvidence          string
	InstallPath              string
	ComponentName            string
	UpstreamMinimumFixed     string
	PatchStatus              string
	RemediationPriority      string
	RecommendedAction        string
	Qualification            string
	ActiveHTTPRuntimeStatus  string
	CompromiseStatus         string
	HostVulnerabilityStatus  string
	DiscoveryCompleteness    string
	LimitationsSummary       string
	// v2 fields (empty when parsing legacy v1 rows)
	ConfigDiscoveryStatus          string
	ConfigCandidateCount           string
	ConfigSettingObservationCount  string
	ConfigCorrelatedToInstall      string
	ConfigPrimaryIniPath           string
	ConfigIniClasses               string
	// v3 investigation fields (empty when parsing legacy v1/v2 rows)
	ExploitationAttemptStatus string
	PossibleCompromiseStatus  string
	InvestigationCoverage     string
	InvestigationWindowFrom   string
	InvestigationWindowTo     string
}

// ScanIDForReport returns a stable, non-secret identifier for one scan result.
func ScanIDForReport(r *Report) string {
	if r == nil {
		return ""
	}
	ts := r.GeneratedUTC.UTC().Format(time.RFC3339Nano)
	material := strings.Join([]string{
		r.Hostname, r.OS, r.Architecture, r.ToolVersion, ts,
		r.VulnerabilityStatus, r.CompromiseStatus, r.EffectiveWebRuntime,
	}, "|")
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:16]) // 128-bit truncated id; full uniqueness via fields
}

// BuildFleetRows derives one row per independently identified PHP installation.
// When no comparable installation exists, a single host-level row is emitted.
func BuildFleetRows(r *Report) []FleetRow {
	if r == nil {
		return nil
	}
	scanID := ScanIDForReport(r)
	ts := r.GeneratedUTC.UTC().Format(time.RFC3339)
	runtimeStatus := fleetRuntimeStatus(r)
	discovery := fleetDiscoveryCompleteness(r)
	limits := fleetLimitationsSummary(r)
	hostCfg := summarizeHostConfigDiscovery(r)
	invFrom, invTo := "", ""
	if r.InvestigationWindow != nil {
		invFrom, invTo = r.InvestigationWindow.FromUTC, r.InvestigationWindow.ToUTC
	}
	base := FleetRow{
		SchemaVersion:                 FleetCSVSchema,
		ScanID:                        scanID,
		Hostname:                      r.Hostname,
		OS:                            r.OS,
		Architecture:                  r.Architecture,
		ScanTimestampUTC:              ts,
		ScannerVersion:                r.ToolVersion,
		CustomerLabel:                 r.CustomerLabel,
		ActiveHTTPRuntimeStatus:       runtimeStatus,
		CompromiseStatus:              r.CompromiseStatus,
		HostVulnerabilityStatus:       r.VulnerabilityStatus,
		DiscoveryCompleteness:         discovery,
		LimitationsSummary:            limits,
		ConfigDiscoveryStatus:         hostCfg.Status,
		ConfigCandidateCount:          fmt.Sprintf("%d", hostCfg.Candidates),
		ConfigSettingObservationCount: fmt.Sprintf("%d", hostCfg.Settings),
		ConfigIniClasses:              hostCfg.Classes,
		ExploitationAttemptStatus:     r.ExploitationAttemptStatus,
		PossibleCompromiseStatus:      r.PossibleCompromiseStatus,
		InvestigationCoverage:         r.InvestigationCoverage,
		InvestigationWindowFrom:       invFrom,
		InvestigationWindowTo:         invTo,
	}

	groups := GroupInstallations(r)
	if len(groups) == 0 {
		row := base
		row.InstallID = "host:no_comparable_install"
		row.VersionEvidence, row.VersionConfidence, row.PHPVersion = fleetHostVersionEvidence(r)
		row.PatchStatus = r.VulnerabilityStatus
		row.RemediationPriority = "REVIEW"
		row.RecommendedAction = firstNonEmpty(firstSummaryAction(r), "Inventory the exact active PHP patch versions for all production web handlers.")
		row.Qualification = "No independently assessed PHP installation version in this scan scope. Not proof PHP is absent."
		row.ComponentName = "(host)"
		row.ConfigCorrelatedToInstall = "NO"
		row.ConfigPrimaryIniPath = FirstUncorrelatedPrimaryIni(r)
		if row.ConfigPrimaryIniPath == "" {
			for _, e := range r.Evidence {
				if e.Type == "php_ini_candidate" {
					row.ConfigPrimaryIniPath = e.Location
					break
				}
			}
		}
		// php.ini-only hosts must never look like a confirmed install/version.
		if row.VersionEvidence == "php_not_observed_in_scope" || row.PHPVersion == "" {
			row.VersionEvidence, row.VersionConfidence, row.PHPVersion = fleetHostVersionEvidence(r)
		}
		return []FleetRow{row}
	}

	out := make([]FleetRow, 0, len(groups))
	for _, g := range groups {
		row := base
		row.InstallID = g.Key
		row.PHPVersion = g.Version
		row.UpstreamMinimumFixed = g.MinimumFixed
		row.PatchStatus = g.Status
		row.RemediationPriority = g.Priority
		if len(g.Assessments) > 0 {
			a := primaryAssessment(g)
			row.ComponentName = a.Component
			row.InstallPath = a.Location
			row.RecommendedAction = a.RequiredAction
			row.Qualification = a.Qualification
			row.VersionConfidence = a.Confidence
			if row.VersionConfidence == "" {
				row.VersionConfidence = confidenceFromEvidenceType(a.EvidenceType)
			}
			row.VersionEvidence = evidenceKindFromType(a.EvidenceType)
			if row.PHPVersion == "" {
				row.PHPVersion = a.ObservedVersion
			}
			if row.UpstreamMinimumFixed == "" {
				row.UpstreamMinimumFixed = a.MinimumFixed
			}
			if row.PatchStatus == "" {
				row.PatchStatus = a.Status
			}
		} else {
			row.VersionEvidence = "unknown"
			row.VersionConfidence = "NONE"
		}
		corr := correlateConfigToInstall(r, g)
		row.ConfigCorrelatedToInstall = corr.Correlated
		row.ConfigPrimaryIniPath = corr.PrimaryPath
		if corr.Classes != "" {
			row.ConfigIniClasses = corr.Classes
		}
		out = append(out, row)
	}
	return out
}

type hostConfigSummary struct {
	Status     string
	Candidates int
	Settings   int
	Classes    string
}

func summarizeHostConfigDiscovery(r *Report) hostConfigSummary {
	classSet := map[string]struct{}{}
	primaries, templates, other := 0, 0, 0
	settings, skips, uncorrelated := 0, 0, 0
	truncated := false
	for _, c := range r.Coverage {
		if c.Name == "configuration" && strings.EqualFold(c.Status, "TRUNCATED") {
			truncated = true
		}
	}
	for _, e := range r.Evidence {
		switch e.Type {
		case "php_ini_candidate":
			class := iisDetailField(e.Detail, "ini_class")
			if class == "" {
				class = classifyPHPIniBasename(e.Name)
			}
			classSet[class] = struct{}{}
			switch class {
			case "sample_or_template":
				templates++
			case "primary_candidate":
				primaries++
			default:
				other++
			}
			if iisDetailField(e.Detail, "related_binary") == "" {
				uncorrelated++
			}
		case "configuration_observation":
			settings++
		case "php_ini_skip", "nginx_config_skip", "php_fpm_config_skip", "nginx_include_unresolved":
			skips++
		}
	}
	candidates := primaries + templates + other
	classes := sortedKeys(classSet)
	// Classify successfully inspected candidates first. Skips are coverage gaps
	// layered on via _WITH_SKIPS — do not collapse a clear UNCORRELATED/PRIMARY
	// result into a generic gaps status when host scans also hit unreadable paths.
	status := "NONE"
	switch {
	case truncated:
		status = "TRUNCATED"
	case candidates == 0 && skips > 0:
		status = "COVERAGE_GAPS_ONLY"
	case candidates == 0:
		status = "NONE"
	case uncorrelated > 0 && primaries > 0 && (templates > 0 || other > 0):
		status = "MIXED_PRIMARY_AND_TEMPLATE"
	case primaries > 0 && templates > 0:
		status = "MIXED_PRIMARY_AND_TEMPLATE"
	case primaries > 0 && other > 0:
		status = "CANDIDATES_OBSERVED"
	case primaries > 0 && uncorrelated == candidates:
		status = "UNCORRELATED_PRIMARY_CANDIDATES"
	case primaries > 0:
		status = "PRIMARY_CANDIDATES_OBSERVED"
	case templates > 0 && other == 0:
		status = "TEMPLATES_ONLY"
	default:
		status = "CANDIDATES_OBSERVED"
	}
	if skips > 0 && status != "TRUNCATED" && status != "COVERAGE_GAPS_ONLY" {
		status = status + "_WITH_SKIPS"
	}
	return hostConfigSummary{Status: status, Candidates: candidates, Settings: settings, Classes: strings.Join(classes, ";")}
}

type installConfigCorr struct {
	Correlated  string // YES / NO
	PrimaryPath string
	Classes     string
}

func correlateConfigToInstall(r *Report, g InstallGroup) installConfigCorr {
	classSet := map[string]struct{}{}
	primary := ""
	matched := false
	for _, e := range r.Evidence {
		if e.Type != "php_ini_candidate" && e.Type != "configuration_observation" {
			continue
		}
		related := iisDetailField(e.Detail, "related_binary")
		if related == "" {
			continue
		}
		relKey := normalizeInstallPath(related)
		for _, a := range g.Assessments {
			aLoc := normalizeInstallPath(a.Location)
			if aLoc == relKey || normalizeInstallPath(parentDirAnyOS(a.Location)) == normalizeInstallPath(parentDirAnyOS(related)) {
				matched = true
				if e.Type == "php_ini_candidate" {
					class := iisDetailField(e.Detail, "ini_class")
					if class == "" {
						class = classifyPHPIniBasename(e.Name)
					}
					classSet[class] = struct{}{}
					if primary == "" && class == "primary_candidate" {
						primary = e.Location
					}
					if primary == "" {
						primary = e.Location
					}
				}
			}
		}
	}
	if !matched {
		return installConfigCorr{Correlated: "NO"}
	}
	return installConfigCorr{Correlated: "YES", PrimaryPath: primary, Classes: strings.Join(sortedKeys(classSet), ";")}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func primaryAssessment(g InstallGroup) PatchAssessment {
	for _, a := range g.Assessments {
		if a.EvidenceType == "binary_static_version" {
			return a
		}
	}
	for _, a := range g.Assessments {
		if a.EvidenceType == "binary_path_inferred_version" {
			return a
		}
	}
	return g.Assessments[0]
}

func evidenceKindFromType(t string) string {
	switch t {
	case "binary_static_version":
		return "verified_binary_metadata"
	case "binary_path_inferred_version":
		return "path_inferred"
	case "installed_package":
		return "package_metadata"
	case "operator_reported_web_runtime":
		return "operator_reported"
	case "repository_declaration":
		return "repository_declaration"
	default:
		return "unknown"
	}
}

func confidenceFromEvidenceType(t string) string {
	switch t {
	case "binary_static_version":
		return "HIGH"
	case "binary_path_inferred_version", "installed_package", "operator_reported_web_runtime", "repository_declaration":
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func fleetRuntimeStatus(r *Report) string {
	switch r.EffectiveWebRuntime {
	case "OPERATOR_REPORTED_NOT_ATTESTED":
		return "OPERATOR_REPORTED_NOT_ATTESTED"
	case "NOT_VERIFIED", "":
		return "NOT_VERIFIED"
	default:
		return r.EffectiveWebRuntime
	}
}

func fleetDiscoveryCompleteness(r *Report) string {
	if ScanIncomplete(r) {
		return "INCOMPLETE"
	}
	hasPHP := false
	unknownOnly := true
	for _, e := range r.Evidence {
		switch e.Type {
		case "binary_path", "binary_static_version", "binary_path_inferred_version", "installed_package", "iis_php_handler_config", "apache_php_handler_config", "apache_php_module_config", "nginx_php_handler_config", "php_fpm_pool_config", "operator_reported_web_runtime", "running_process":
			if e.Type == "running_process" && e.Name == "w3wp.exe" {
				continue
			}
			hasPHP = true
			if e.Version != "" || e.Type == "binary_static_version" || e.Type == "binary_path_inferred_version" || e.Type == "installed_package" {
				unknownOnly = false
			}
		}
	}
	if !hasPHP {
		if NoPHPWithIncompleteInventory(r) || !hasApplicablePHPDiscoveryChecks(r) {
			return "INCOMPLETE"
		}
		return "NO_PHP_OBSERVED_IN_SCOPE"
	}
	if len(r.PatchAssessments) == 0 && unknownOnly {
		return "PARTIAL_VERSION_UNKNOWN"
	}
	return "PARTIAL"
}

func fleetHostVersionEvidence(r *Report) (evidence, confidence, version string) {
	hasPath := false
	for _, e := range r.Evidence {
		switch e.Type {
		case "binary_path":
			hasPath = true
		case "binary_static_version", "binary_path_inferred_version", "installed_package", "operator_reported_web_runtime":
			if e.Version != "" {
				return evidenceKindFromType(e.Type), confidenceFromEvidenceType(e.Type), e.Version
			}
		}
	}
	if hasPath {
		return "version_unknown", "NONE", ""
	}
	return "php_not_observed_in_scope", "NONE", ""
}

func fleetLimitationsSummary(r *Report) string {
	parts := []string{
		"Not an active HTTP runtime attestation",
		"Vendor backports require separate verification",
		"No IOC match is not a compromise clearance",
		"Discovery scope is bounded; not complete host coverage",
	}
	if r.CompromiseStatus == "NOT_ASSESSED" {
		parts = append(parts, "Signed-IOC rollup not assessed (no trusted pack)")
	}
	if r.ExploitationAttemptStatus == "NOT_ASSESSED" {
		parts = append(parts, "Exploitation attempts NOT_ASSESSED (no investigation inputs — not a negative finding)")
	} else if r.ExploitationAttemptStatus == "NO_MATCHES_IN_SCOPE" {
		parts = append(parts, "No exploitation-attempt matches in assessed scope (not a clearance)")
	}
	if r.PossibleCompromiseStatus == "NOT_ASSESSED" {
		parts = append(parts, "Possible compromise NOT_ASSESSED (no usable offline process/EDR telemetry or webroot investigation — not a negative finding)")
	} else if r.PossibleCompromiseStatus == "POSSIBLE_COMPROMISE_REVIEW" && possibleCompromiseIsWebrootMetadataOnly(r) {
		parts = append(parts, "POSSIBLE_COMPROMISE_REVIEW is low-confidence webroot metadata only (not EDR-strength; not confirmed webshell or successful exploitation)")
	} else if r.PossibleCompromiseStatus == "NO_MATCHES_IN_SCOPE" {
		parts = append(parts, "No process/webroot compromise matches in assessed scope (not a clearance)")
	}
	if r.InvestigationCoverage == "INCOMPLETE" {
		parts = append(parts, "Investigation coverage incomplete; gaps cannot be ruled out from first/last timestamps")
	}
	iniCandidates, settingObs, skips, uncorrelated := 0, 0, 0, 0
	for _, e := range r.Evidence {
		switch e.Type {
		case "php_ini_candidate":
			iniCandidates++
			if iisDetailField(e.Detail, "related_binary") == "" {
				uncorrelated++
			}
		case "configuration_observation":
			settingObs++
		case "php_ini_skip", "nginx_config_skip", "php_fpm_config_skip", "nginx_include_unresolved":
			skips++
		}
	}
	if iniCandidates > 0 || settingObs > 0 {
		parts = append(parts, fmt.Sprintf(
			"PHP config candidates observed (%d files, %d whitelisted settings, %d uncorrelated); not proof of effective SAPI settings or PHP version",
			iniCandidates, settingObs, uncorrelated,
		))
	}
	if skips > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d PHP config candidate(s) skipped (unreadable/oversized/symlink); paths only, secrets not reported",
			skips,
		))
	}
	deepRoots, deepTrunc := 0, false
	for _, e := range r.Evidence {
		if e.Type == "deep_discovery_coverage" {
			deepRoots++
			if strings.Contains(e.Detail, "stopped=") {
				deepTrunc = true
			}
		}
	}
	for _, c := range r.Coverage {
		if c.Name == "deep_discovery" && (strings.EqualFold(c.Status, "TRUNCATED") || strings.EqualFold(c.Status, "INCOMPLETE")) {
			deepTrunc = true
		}
	}
	if deepRoots > 0 {
		msg := fmt.Sprintf("Deep Discovery authorized (%d root(s)); weaker evidence than well-known/PATH sources; not complete host coverage", deepRoots)
		if deepTrunc {
			msg += "; truncated or incomplete — do not treat empty results as proof PHP is absent"
		}
		parts = append(parts, msg)
	}
	return strings.Join(parts, "; ")
}

func firstSummaryAction(r *Report) string {
	if len(r.Summary.NextSteps) > 0 {
		return r.Summary.NextSteps[0]
	}
	if len(r.RecommendedActions) > 0 {
		return r.RecommendedActions[0]
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (row FleetRow) csvFields() []string {
	vals := []string{
		row.SchemaVersion,
		row.ScanID,
		row.Hostname,
		row.OS,
		row.Architecture,
		row.ScanTimestampUTC,
		row.ScannerVersion,
		row.CustomerLabel,
		row.InstallID,
		row.PHPVersion,
		row.VersionConfidence,
		row.VersionEvidence,
		row.InstallPath,
		row.ComponentName,
		row.UpstreamMinimumFixed,
		row.PatchStatus,
		row.RemediationPriority,
		row.RecommendedAction,
		row.Qualification,
		row.ActiveHTTPRuntimeStatus,
		row.CompromiseStatus,
		row.HostVulnerabilityStatus,
		row.DiscoveryCompleteness,
		row.LimitationsSummary,
		row.ConfigDiscoveryStatus,
		row.ConfigCandidateCount,
		row.ConfigSettingObservationCount,
		row.ConfigCorrelatedToInstall,
		row.ConfigPrimaryIniPath,
		row.ConfigIniClasses,
		row.ExploitationAttemptStatus,
		row.PossibleCompromiseStatus,
		row.InvestigationCoverage,
		row.InvestigationWindowFrom,
		row.InvestigationWindowTo,
	}
	for i := range vals {
		vals[i] = SpreadsheetSafe(vals[i])
	}
	return vals
}

// EncodeFleetCSV writes UTF-8 CSV (with BOM for Excel) for consultant fleet use.
func EncodeFleetCSV(r *Report) ([]byte, error) {
	rows := BuildFleetRows(r)
	var b bytes.Buffer
	// UTF-8 BOM helps Excel open Unicode paths/hostnames correctly.
	b.Write([]byte{0xEF, 0xBB, 0xBF})
	w := csv.NewWriter(&b)
	if err := w.Write(FleetCSVColumns); err != nil {
		return nil, err
	}
	for _, row := range rows {
		if err := w.Write(row.csvFields()); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// EncodeCSV remains available for legacy evidence dumps / tests.
// Prefer EncodeFleetCSV for operator-facing scan output and rollup.
func EncodeCSVLegacyEvidence(r *Report) ([]byte, error) {
	return EncodeCSV(r)
}

// ParseFleetCSV reads fleet CSV produced by EncodeFleetCSV (v1 or v2).
// v2 configuration columns are optional when reading legacy v1 files.
func ParseFleetCSV(data []byte) ([]FleetRow, error) {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = -1
	records, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("invalid CSV: %w", err)
	}
	if len(records) < 1 {
		return nil, fmt.Errorf("CSV has no header")
	}
	header := records[0]
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.TrimSpace(h)] = i
	}
	for _, col := range requiredFleetColumns() {
		if _, ok := idx[col]; !ok {
			return nil, fmt.Errorf("CSV missing required column %q", col)
		}
	}
	var rows []FleetRow
	for line, rec := range records[1:] {
		get := func(name string) string {
			i, ok := idx[name]
			if !ok || i >= len(rec) {
				return ""
			}
			return rec[i]
		}
		schema := get("schema_version")
		if schema == "" {
			return nil, fmt.Errorf("row %d: empty schema_version", line+2)
		}
		if schema != FleetCSVSchemaV1 && schema != FleetCSVSchemaV2 && schema != FleetCSVSchemaV3 {
			return nil, fmt.Errorf("row %d: unsupported schema_version %q (supported: %s, %s, %s)", line+2, schema, FleetCSVSchemaV1, FleetCSVSchemaV2, FleetCSVSchemaV3)
		}
		rows = append(rows, FleetRow{
			SchemaVersion:                 schema,
			ScanID:                        get("scan_id"),
			Hostname:                      get("hostname"),
			OS:                            get("os"),
			Architecture:                  get("architecture"),
			ScanTimestampUTC:              get("scan_timestamp_utc"),
			ScannerVersion:                get("scanner_version"),
			CustomerLabel:                 get("customer_label"),
			InstallID:                     get("install_id"),
			PHPVersion:                    get("php_version"),
			VersionConfidence:             get("version_confidence"),
			VersionEvidence:               get("version_evidence"),
			InstallPath:                   get("install_path"),
			ComponentName:                 get("component_name"),
			UpstreamMinimumFixed:          get("upstream_minimum_fixed"),
			PatchStatus:                   get("patch_status"),
			RemediationPriority:           get("remediation_priority"),
			RecommendedAction:             get("recommended_action"),
			Qualification:                 get("qualification"),
			ActiveHTTPRuntimeStatus:       get("active_http_runtime_status"),
			CompromiseStatus:              get("compromise_status"),
			HostVulnerabilityStatus:       get("host_vulnerability_status"),
			DiscoveryCompleteness:         get("discovery_completeness"),
			LimitationsSummary:            get("limitations_summary"),
			ConfigDiscoveryStatus:         get("config_discovery_status"),
			ConfigCandidateCount:          get("config_candidate_count"),
			ConfigSettingObservationCount: get("config_setting_observation_count"),
			ConfigCorrelatedToInstall:     get("config_correlated_to_install"),
			ConfigPrimaryIniPath:          get("config_primary_ini_path"),
			ConfigIniClasses:              get("config_ini_classes"),
			ExploitationAttemptStatus:     get("exploitation_attempt_status"),
			PossibleCompromiseStatus:      get("possible_compromise_status"),
			InvestigationCoverage:         get("investigation_coverage"),
			InvestigationWindowFrom:       get("investigation_window_from_utc"),
			InvestigationWindowTo:         get("investigation_window_to_utc"),
		})
	}
	return rows, nil
}

func requiredFleetColumns() []string {
	return []string{
		"schema_version", "scan_id", "hostname", "os", "architecture",
		"scan_timestamp_utc", "scanner_version", "install_id",
		"php_version", "version_confidence", "version_evidence",
		"patch_status", "active_http_runtime_status", "compromise_status",
		"host_vulnerability_status", "discovery_completeness",
	}
}
