package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// FleetCSVSchema identifies the consultant-facing per-installation CSV format.
const FleetCSVSchema = "php2shell-fleet-csv/v1"

// FleetCSVColumns is the stable header for scan CSV output and fleet rollup.
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
	base := FleetRow{
		SchemaVersion:           FleetCSVSchema,
		ScanID:                  scanID,
		Hostname:                r.Hostname,
		OS:                      r.OS,
		Architecture:            r.Architecture,
		ScanTimestampUTC:        ts,
		ScannerVersion:          r.ToolVersion,
		CustomerLabel:           r.CustomerLabel,
		ActiveHTTPRuntimeStatus: runtimeStatus,
		CompromiseStatus:        r.CompromiseStatus,
		HostVulnerabilityStatus: r.VulnerabilityStatus,
		DiscoveryCompleteness:   discovery,
		LimitationsSummary:      limits,
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
		out = append(out, row)
	}
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
		case "binary_path", "binary_static_version", "binary_path_inferred_version", "installed_package", "iis_php_handler_config", "apache_php_handler_config", "apache_php_module_config", "operator_reported_web_runtime", "running_process":
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
	}
	if r.CompromiseStatus == "NOT_ASSESSED" {
		parts = append(parts, "Compromise not assessed (no trusted IOC pack)")
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

// ParseFleetCSV reads a v2.4.0 fleet CSV produced by EncodeFleetCSV.
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
			return nil, fmt.Errorf("CSV missing required column %q (schema %s)", col, FleetCSVSchema)
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
		if schema != "" && schema != FleetCSVSchema {
			return nil, fmt.Errorf("row %d: unsupported schema_version %q (want %s)", line+2, schema, FleetCSVSchema)
		}
		if schema == "" {
			return nil, fmt.Errorf("row %d: empty schema_version", line+2)
		}
		rows = append(rows, FleetRow{
			SchemaVersion:           schema,
			ScanID:                  get("scan_id"),
			Hostname:                get("hostname"),
			OS:                      get("os"),
			Architecture:            get("architecture"),
			ScanTimestampUTC:        get("scan_timestamp_utc"),
			ScannerVersion:          get("scanner_version"),
			CustomerLabel:           get("customer_label"),
			InstallID:               get("install_id"),
			PHPVersion:              get("php_version"),
			VersionConfidence:       get("version_confidence"),
			VersionEvidence:         get("version_evidence"),
			InstallPath:             get("install_path"),
			ComponentName:           get("component_name"),
			UpstreamMinimumFixed:    get("upstream_minimum_fixed"),
			PatchStatus:             get("patch_status"),
			RemediationPriority:     get("remediation_priority"),
			RecommendedAction:       get("recommended_action"),
			Qualification:           get("qualification"),
			ActiveHTTPRuntimeStatus: get("active_http_runtime_status"),
			CompromiseStatus:        get("compromise_status"),
			HostVulnerabilityStatus: get("host_vulnerability_status"),
			DiscoveryCompleteness:   get("discovery_completeness"),
			LimitationsSummary:      get("limitations_summary"),
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
