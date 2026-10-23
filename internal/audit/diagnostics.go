package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Stable diagnostic identifiers for operators and deployment wrappers.
const (
	DiagOK                  = "OK"
	DiagUnsupportedOS       = "UNSUPPORTED_OS"
	DiagInvalidArgument     = "INVALID_ARGUMENT"
	DiagAccessDenied        = "ACCESS_DENIED"
	DiagEvidenceUnavailable = "EVIDENCE_UNAVAILABLE"
	DiagScanIncomplete      = "SCAN_INCOMPLETE"
	DiagOutputWriteFailed   = "OUTPUT_WRITE_FAILED"
	DiagOutputExists        = "OUTPUT_EXISTS"
	DiagInternalError       = "INTERNAL_ERROR"
	DiagTimedOut            = "TIMEOUT"
)

// ExecutionStatus is a machine-readable end-of-run diagnostic (no secrets, no request bodies).
type ExecutionStatus struct {
	SchemaVersion      string   `json:"schema_version"`
	ToolVersion        string   `json:"tool_version"`
	BuildFlavor        string   `json:"build_flavor"`
	ExecutionID        string   `json:"execution_id"`
	StartedUTC         string   `json:"started_utc"`
	EndedUTC           string   `json:"ended_utc"`
	DurationMS         int64    `json:"duration_ms"`
	GOOS               string   `json:"goos"`
	GOARCH             string   `json:"goarch"`
	Hostname           string   `json:"hostname,omitempty"`
	Command            string   `json:"command"`
	ExecutionStatus    string   `json:"execution_status"` // COMPLETED | COMPLETED_INCOMPLETE | FAILED
	ExitCode           int      `json:"exit_code"`
	FailurePhase       string   `json:"failure_phase,omitempty"`
	ErrorIDs           []string `json:"error_ids,omitempty"`
	ErrorDetail        string   `json:"error_detail,omitempty"`
	Remediation        string   `json:"remediation,omitempty"`
	ReportsWritten     bool     `json:"reports_written"`
	HTMLReportPath     string   `json:"html_report_path,omitempty"`
	CSVReportPath      string   `json:"csv_report_path,omitempty"`
	StatusJSONPath     string   `json:"status_json_path,omitempty"`
	StatusJSONWritten  bool     `json:"status_json_written"`
	ScanIncomplete     bool     `json:"scan_incomplete"`
	AcceptIncomplete   bool     `json:"accept_incomplete,omitempty"`
	EvidenceNotes      []string `json:"evidence_notes,omitempty"`
	CoverageIncomplete []string `json:"coverage_incomplete,omitempty"`
}

// NewExecutionID returns a random 128-bit hex id for correlating status JSON with reports.
func NewExecutionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// MatchingStatusJSONPath returns the .status.json sibling for an HTML report path.
func MatchingStatusJSONPath(htmlPath string) string {
	htmlPath = strings.TrimSpace(htmlPath)
	lower := strings.ToLower(htmlPath)
	switch {
	case strings.HasSuffix(lower, ".html"):
		return htmlPath[:len(htmlPath)-len(".html")] + ".status.json"
	case strings.HasSuffix(lower, ".htm"):
		return htmlPath[:len(htmlPath)-len(".htm")] + ".status.json"
	default:
		return htmlPath + ".status.json"
	}
}

// FailedStatusJSONPath returns an execution-scoped status path when the primary sibling exists
// (e.g. overwrite refusal on a second --out to the same HTML name).
func FailedStatusJSONPath(primary, executionID string) string {
	primary = strings.TrimSpace(primary)
	executionID = strings.TrimSpace(executionID)
	if primary == "" {
		return ""
	}
	if executionID == "" {
		executionID = "unknown"
	}
	lower := strings.ToLower(primary)
	if strings.HasSuffix(lower, ".status.json") {
		base := primary[:len(primary)-len(".status.json")]
		return base + ".failed-" + executionID + ".status.json"
	}
	return primary + ".failed-" + executionID + ".status.json"
}

// CollectIncompleteCoverageNames lists coverage checks that contribute to ScanIncomplete.
func CollectIncompleteCoverageNames(r *Report) []string {
	if r == nil {
		return nil
	}
	var out []string
	add := func(name, status string) {
		switch strings.ToUpper(status) {
		case "INCOMPLETE", "UNAVAILABLE", "TRUNCATED", "TIMEOUT", "ACCESS_DENIED", "UNSUPPORTED_FORMAT":
			out = append(out, name+"="+status)
		}
	}
	for _, c := range r.Coverage {
		add(c.Name, c.Status)
	}
	for _, repo := range r.Repositories {
		add("repository:"+repo.Root, repo.Status)
	}
	for _, log := range r.Logs {
		add("access_log:"+log.File, log.Status)
	}
	for _, log := range r.ErrorLogs {
		add("error_log:"+log.File, log.Status)
	}
	for _, pt := range r.ProcessTelemetry {
		add("process_telemetry:"+pt.File, pt.Status)
	}
	for _, w := range r.WebrootInvestigation {
		add("webroot:"+w.Root, w.Status)
	}
	for _, w := range r.WAFLogs {
		add("waf_log:"+w.File, w.Status)
	}
	if strings.EqualFold(r.InvestigationCoverage, "INCOMPLETE") {
		out = append(out, "investigation_coverage=INCOMPLETE")
	}
	return out
}

// BuildExecutionStatus assembles a diagnostic snapshot after a scan attempt.
func BuildExecutionStatus(opts ExecutionStatusOptions) *ExecutionStatus {
	st := &ExecutionStatus{
		SchemaVersion:    "php2shell-execution-status/v1",
		ToolVersion:      Version,
		BuildFlavor:      BuildFlavorLabel(),
		ExecutionID:      opts.ExecutionID,
		StartedUTC:       opts.Started.UTC().Format(time.RFC3339),
		EndedUTC:         opts.Ended.UTC().Format(time.RFC3339),
		DurationMS:       opts.Ended.Sub(opts.Started).Milliseconds(),
		GOOS:             opts.GOOS,
		GOARCH:           opts.GOARCH,
		Hostname:         opts.Hostname,
		Command:          "scan",
		ExitCode:         opts.ExitCode,
		FailurePhase:     opts.FailurePhase,
		ErrorIDs:         append([]string(nil), opts.ErrorIDs...),
		ErrorDetail:      opts.ErrorDetail,
		Remediation:      opts.Remediation,
		ReportsWritten:   opts.ReportsWritten,
		HTMLReportPath:   opts.HTMLPath,
		CSVReportPath:    opts.CSVPath,
		StatusJSONPath:   opts.StatusJSONPath,
		ScanIncomplete:   opts.Incomplete,
		AcceptIncomplete: opts.AcceptIncomplete,
	}
	switch {
	case opts.ExitCode == ExitFatal || !opts.ReportsWritten && opts.ExitCode != ExitOK:
		st.ExecutionStatus = "FAILED"
	case opts.Incomplete:
		st.ExecutionStatus = "COMPLETED_INCOMPLETE"
	default:
		st.ExecutionStatus = "COMPLETED"
	}
	if opts.Report != nil {
		st.CoverageIncomplete = CollectIncompleteCoverageNames(opts.Report)
		if opts.Report.InvestigationCoverage != "" {
			st.EvidenceNotes = append(st.EvidenceNotes, "investigation_coverage="+opts.Report.InvestigationCoverage)
		}
		if opts.Report.ExploitationAttemptStatus != "" {
			st.EvidenceNotes = append(st.EvidenceNotes, "exploitation_attempt="+opts.Report.ExploitationAttemptStatus)
		}
		if opts.Report.PossibleCompromiseStatus != "" {
			st.EvidenceNotes = append(st.EvidenceNotes, "possible_compromise="+opts.Report.PossibleCompromiseStatus)
		}
	}
	if st.Remediation == "" {
		st.Remediation = defaultRemediation(st)
	}
	return st
}

// ExecutionStatusOptions carries inputs for BuildExecutionStatus.
type ExecutionStatusOptions struct {
	ExecutionID      string
	Started, Ended   time.Time
	GOOS, GOARCH     string
	Hostname         string
	ExitCode         int
	FailurePhase     string
	ErrorIDs         []string
	ErrorDetail      string
	Remediation      string
	ReportsWritten   bool
	HTMLPath         string
	CSVPath          string
	StatusJSONPath   string
	Incomplete       bool
	AcceptIncomplete bool
	Report           *Report
}

func defaultRemediation(st *ExecutionStatus) string {
	switch st.ExecutionStatus {
	case "FAILED":
		if containsID(st.ErrorIDs, DiagUnsupportedOS) {
			return "On Windows Server 2012 R2 use php2shell-windows-legacy-amd64.exe; see docs/WINDOWS-LEGACY-2012R2.md."
		}
		if containsID(st.ErrorIDs, DiagOutputWriteFailed) || containsID(st.ErrorIDs, DiagOutputExists) {
			return "Fix output path permissions or choose a new --out/--output-dir; existing files are never overwritten."
		}
		if containsID(st.ErrorIDs, DiagInvalidArgument) {
			return "Correct CLI flags; see php2shell help. --out expects an HTML path or prefix (.csv is remapped to .html+.csv)."
		}
		return "Inspect error_detail and stderr; re-run after resolving the fatal condition. Do not treat missing reports as a clean host."
	case "COMPLETED_INCOMPLETE":
		return "HTML+CSV were written. Review coverage_incomplete in this status file and the HTML coverage section. For PSAppDeployToolkit, treat exit 0 and 2 as eligible for report upload, or pass --accept-incomplete. Exit 2 is not a security clearance."
	default:
		return "Open the HTML report for findings; use CSV for fleet rollup. Process success is not a vulnerability or compromise clearance."
	}
}

func containsID(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// WriteExecutionStatusJSON writes status JSON exclusively (refuses overwrite).
func WriteExecutionStatusJSON(path string, st *ExecutionStatus) error {
	path = strings.TrimSpace(path)
	if path == "" || st == nil {
		return fmt.Errorf("status JSON path and payload required")
	}
	st.StatusJSONPath = path
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := MakeReportDirectory(path); err != nil {
		return err
	}
	return writeExclusiveFile(path, data)
}

// PersistExecutionStatusJSON tries primary, then execution-scoped alternate names,
// then (when HTML was written) siblings next to the HTML report so Intune/PSADT
// can always read a machine-readable status when reports exist.
// If the primary path fails and a fallback succeeds, st includes OUTPUT_WRITE_FAILED
// before the successful write so automation can detect the degraded path on disk.
// On success sets st.StatusJSONWritten and st.StatusJSONPath to the path used.
// Returns the path written, whether a fallback was used, and any final error.
func PersistExecutionStatusJSON(st *ExecutionStatus, primary, htmlPath, executionID string) (written string, usedFallback bool, err error) {
	if st == nil {
		return "", false, fmt.Errorf("execution status required")
	}
	candidates := statusJSONWriteCandidates(primary, htmlPath, executionID)
	if len(candidates) == 0 {
		st.StatusJSONWritten = false
		return "", false, fmt.Errorf("no status JSON path available")
	}
	primaryClean := ""
	if len(candidates) > 0 {
		primaryClean = candidates[0]
	}
	var lastErr error
	for i, path := range candidates {
		if path == "" {
			continue
		}
		// Set before marshal so on-disk JSON reports status_json_written=true for automation.
		st.StatusJSONWritten = true
		st.StatusJSONPath = path
		if e := WriteExecutionStatusJSON(path, st); e != nil {
			st.StatusJSONWritten = false
			lastErr = e
			// After primary failure, mark diagnostic before attempting fallbacks so
			// the on-disk JSON carries OUTPUT_WRITE_FAILED for deployment automation.
			if i == 0 && path == primaryClean {
				if !containsID(st.ErrorIDs, DiagOutputWriteFailed) {
					st.ErrorIDs = append(st.ErrorIDs, DiagOutputWriteFailed)
				}
				if st.ErrorDetail == "" {
					st.ErrorDetail = e.Error()
				}
				st.Remediation = "Primary status JSON path was unavailable; wrote execution-scoped or HTML-sibling fallback when possible. Collect HTML/CSV and status_json_path. Prefer unique --out names."
			}
			continue
		}
		return path, i > 0, nil
	}
	st.StatusJSONWritten = false
	if lastErr == nil {
		lastErr = fmt.Errorf("no status JSON path available")
	}
	return "", false, lastErr
}

func statusJSONWriteCandidates(primary, htmlPath, executionID string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		key := strings.ToLower(p)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, p)
	}
	add(primary)
	add(FailedStatusJSONPath(primary, executionID))
	if html := strings.TrimSpace(htmlPath); html != "" {
		sib := MatchingStatusJSONPath(html)
		add(sib)
		add(FailedStatusJSONPath(sib, executionID))
	}
	return out
}

// FormatQuietStatusLine is a single stderr line for --quiet end-of-scan visibility.
func FormatQuietStatusLine(st *ExecutionStatus) string {
	if st == nil {
		return "PHP2Shell status=FAILED exit=1 error=INTERNAL_ERROR"
	}
	ids := strings.Join(st.ErrorIDs, ",")
	if ids == "" {
		ids = DiagOK
	}
	return fmt.Sprintf(
		"PHP2Shell status=%s exit=%d errors=%s reports_written=%t status_json_written=%t incomplete=%t html=%s csv=%s status_json=%s remediation=%s",
		st.ExecutionStatus, st.ExitCode, ids, st.ReportsWritten, st.StatusJSONWritten, st.ScanIncomplete,
		st.HTMLReportPath, st.CSVReportPath, st.StatusJSONPath, compactRemediation(st.Remediation),
	)
}

func compactRemediation(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 160 {
		return s[:157] + "..."
	}
	return s
}

// ClassifySaveError maps SaveReportPair failures to diagnostic IDs.
func ClassifySaveError(err error) (id, detail string) {
	if err == nil {
		return "", ""
	}
	detail = err.Error()
	low := strings.ToLower(detail)
	switch {
	case strings.Contains(low, "refusing overwrite") || strings.Contains(low, "output exists"):
		return DiagOutputExists, detail
	case strings.Contains(low, "permission denied") || strings.Contains(low, "access is denied"):
		return DiagAccessDenied, detail
	case strings.Contains(low, "invalid output directory"):
		return DiagOutputWriteFailed, detail
	default:
		return DiagOutputWriteFailed, detail
	}
}

// ResolveStatusJSONPath chooses where to write execution status.
// Explicit --status-json wins; otherwise sibling of HTML when reports resolve.
func ResolveStatusJSONPath(explicit, htmlPath string) string {
	if s := strings.TrimSpace(explicit); s != "" {
		return filepath.Clean(s)
	}
	if strings.TrimSpace(htmlPath) == "" {
		return ""
	}
	return MatchingStatusJSONPath(htmlPath)
}

// EnsureParentDirExists is a thin helper for tests/docs.
func EnsureParentDirExists(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0700)
}
