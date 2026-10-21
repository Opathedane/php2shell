package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
)

func SpreadsheetSafe(s string) string {
	v := strings.TrimLeft(s, " \t\r\n\uFEFF")
	if len(s) > 0 && (s[0] == '\t' || s[0] == '\r' || s[0] == '\n') {
		return "'" + s
	}
	if len(v) > 0 && (v[0] == '=' || v[0] == '+' || v[0] == '-' || v[0] == '@') {
		return "'" + s
	}
	return s
}

func EncodeCSV(r *Report) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"type", "name", "version", "source", "location", "detail", "interpretation"})
	for _, e := range r.Evidence {
		vals := []string{e.Type, e.Name, e.Version, e.Source, e.Location, e.Detail, e.Interpretation}
		for i := range vals {
			vals[i] = SpreadsheetSafe(vals[i])
		}
		if err := w.Write(vals); err != nil {
			return nil, err
		}
	}
	for _, item := range []struct{ name, value string }{{"php_discovery", r.Summary.PHPDiscovery}, {"patch_review", r.Summary.PatchReview}, {"compromise_review", r.Summary.CompromiseReview}} {
		if item.value != "" {
			_ = w.Write([]string{"assessment_summary", item.name, "", "scanner summary", "", SpreadsheetSafe(item.value), "NOT_A_CLEARANCE"})
		}
	}
	for i, step := range r.Summary.NextSteps {
		_ = w.Write([]string{"next_step", fmt.Sprint(i + 1), "", "scanner guidance", "", SpreadsheetSafe(step), "ACTION_REQUIRES_VALIDATION"})
	}
	for _, a := range r.PatchAssessments {
		qual := a.Status + " | min_fixed=" + a.MinimumFixed + " | priority=" + a.Priority + " | " + a.Qualification
		if a.InstallKey != "" {
			qual += " | install_key=" + a.InstallKey
		}
		if a.RuntimeKey != "" {
			qual += " | runtime_key=" + a.RuntimeKey
		}
		values := []string{"patch_assessment", a.Component, a.ObservedVersion, a.Source, a.Location, a.RequiredAction, qual}
		for i := range values {
			values[i] = SpreadsheetSafe(values[i])
		}
		if err := w.Write(values); err != nil {
			return nil, err
		}
	}
	for i, action := range r.RecommendedActions {
		values := []string{"recommended_action", fmt.Sprint(i + 1), "", "2026-10-21 PHP security advisory", "", action, "ACTION_REQUIRES_ANALYST_REVIEW"}
		for j := range values {
			values[j] = SpreadsheetSafe(values[j])
		}
		if err := w.Write(values); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return b.Bytes(), w.Error()
}

func EncodeHTML(r *Report) []byte {
	var b strings.Builder
	h := func(s string) string { return html.EscapeString(s) }
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline'"><title>PHP2Shell Assessment</title><style>body{font:15px/1.5 system-ui,Arial,sans-serif;max-width:1050px;margin:35px auto;padding:0 20px;color:#21262c}h1,h2{color:#152437}.notice{background:#fff7ed;border-left:4px solid #ad5e0d;padding:16px}table{border-collapse:collapse;width:100%;margin:15px 0 30px}td,th{border:1px solid #dce1e8;padding:9px;vertical-align:top;text-align:left;overflow-wrap:anywhere}th{background:#eef1f4}code{overflow-wrap:anywhere}p{max-width:75em}@media print{body{max-width:none;margin:0}}</style></head><body>`)
	b.WriteString("<h1>PHP2Shell – evidence assessment</h1><p><strong>Host: </strong>" + h(r.Hostname) + " &nbsp; <strong>UTC:</strong> " + h(r.GeneratedUTC.Format("2006-01-02 15:04:05")) + " &nbsp; <strong>Version:</strong> " + h(r.ToolVersion) + "</p>")
	b.WriteString("<div class=notice><strong>Results are NOT a vulnerability clearance or compromise clearance.</strong><p>Vulnerability: " + h(r.VulnerabilityStatus) + ". Compromise: " + h(r.CompromiseStatus) + ". Serving PHP runtime: " + h(r.EffectiveWebRuntime) + ". Lack of findings is not proof of safety.</p></div>")
	b.WriteString("<h2>At a glance</h2><table><tr><th>PHP discovery</th><th>Patch assessment</th><th>Compromise indicators</th></tr><tr><td>" + h(r.Summary.PHPDiscovery) + "</td><td>" + h(r.Summary.PatchReview) + "</td><td>" + h(r.Summary.CompromiseReview) + "</td></tr></table>")
	b.WriteString("<h2>What to do next</h2><ol>")
	for _, step := range r.Summary.NextSteps {
		b.WriteString("<li>" + h(step) + "</li>")
	}
	b.WriteString("</ol><p><strong>Important:</strong> This summary is evidence-qualified, not confirmation of a patched HTTP runtime or absence of compromise.</p>")
	b.WriteString("<h2>Official PHP2Shell patch assessment</h2><p>Official PHP fixes (21 October 2026): 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. These comparisons are based on observed package, repository or operator-reported versions. Vendor backports and serving web runtimes must be verified separately. Neither patching nor a negative IOC scan proves no prior compromise.</p>")
	b.WriteString("<table><tr><th>Component / evidence</th><th>Observed PHP version</th><th>Minimum fixed</th><th>Assessment / priority</th><th>Required action and limitations</th></tr>")
	if len(r.PatchAssessments) == 0 {
		b.WriteString("<tr><td colspan=5>No comparable PHP patch versions found. Web runtime and patch status remain unverified.</td></tr>")
	}
	for _, a := range r.PatchAssessments {
		b.WriteString("<tr><td>" + h(a.Component) + "<br>" + h(a.EvidenceType) + "<br>" + h(a.Location) + "</td><td>" + h(a.ObservedVersion) + "</td><td>" + h(a.MinimumFixed) + "</td><td>" + h(a.Status) + "<br>" + h(a.Priority) + "</td><td>" + h(a.RequiredAction) + "<br><small>" + h(a.Qualification) + "</small></td></tr>")
	}
	b.WriteString("</table>")
	b.WriteString(`<h2>Where to get security updates</h2><p><strong>Linux:</strong> install the approved security package from your OS/LTS vendor's official repository and verify the vendor advisory and installed build. <strong>Windows:</strong> use the <a href="https://windows.php.net/download/">official PHP for Windows downloads</a>. <strong>Source builds:</strong> use <a href="https://www.php.net/downloads.php">PHP's official source downloads</a>. <strong>Containers:</strong> redeploy an officially patched image and verify the deployed digest/runtime. Use the correct supported branch; do not replace distribution-managed PHP with an unrelated binary without change review.</p>`)
	b.WriteString("<h2>Coverage</h2><table><thead><tr><th>Check</th><th>Status</th><th>Notes</th></tr></thead><tbody>")
	for _, c := range r.Coverage {
		b.WriteString("<tr><td>" + h(c.Name) + "</td><td>" + h(c.Status) + "</td><td>" + h(c.Detail) + "</td></tr>")
	}
	b.WriteString("</tbody></table>")
	b.WriteString("<h2>Evidence (" + fmt.Sprint(len(r.Evidence)) + ")</h2><table><thead><tr><th>Type</th><th>Name</th><th>Version</th><th>Source / path</th><th>Meaning</th></tr></thead><tbody>")
	for _, e := range r.Evidence {
		b.WriteString("<tr><td>" + h(e.Type) + "</td><td>" + h(e.Name) + "</td><td>" + h(e.Version) + "</td><td>" + h(e.Source) + "<br>" + h(e.Location) + "<br>" + h(e.Detail) + "</td><td>" + h(e.Interpretation) + "</td></tr>")
	}
	b.WriteString("</tbody></table>")
	if r.RuleSequence > 0 {
		b.WriteString("<h2>Signed indicator bundle</h2><p>Sequence: " + fmt.Sprint(r.RuleSequence) + "; approved indicators loaded: " + fmt.Sprint(r.RuleCount) + ". A match requires manual analyst review. No matches cannot prove absence of compromise.</p>")
	}
	if len(r.Findings) > 0 {
		b.WriteString("<h2>Indicator matches (" + fmt.Sprint(len(r.Findings)) + ")</h2><table><tr><th>Rule</th><th>Severity</th><th>Confidence</th><th>Evidence</th><th>Source</th></tr>")
		for _, f := range r.Findings {
			b.WriteString("<tr><td>" + h(f.RuleID) + "</td><td>" + h(f.Severity) + "</td><td>" + h(f.Confidence) + "</td><td>" + h(f.Location) + ": " + h(f.Detail) + "</td><td>" + h(f.Source) + "</td></tr>")
		}
		b.WriteString("</table>")
	}
	if len(r.Logs) > 0 {
		b.WriteString("<h2>HTTP access log coverage (indicators where available)</h2><table><tr><th>File</th><th>Status</th><th>Lines</th><th>Parsed requests</th><th>First / Last</th></tr>")
		for _, c := range r.Logs {
			b.WriteString("<tr><td>" + h(c.File) + "</td><td>" + h(c.Status) + "</td><td>" + fmt.Sprint(c.Lines) + "</td><td>" + fmt.Sprint(c.ParsedRequests) + "</td><td>" + h(c.FirstTimestamp) + " / " + h(c.LastTimestamp) + "</td></tr>")
		}
		b.WriteString("</table>")
	}
	if len(r.Repositories) > 0 {
		b.WriteString("<h2>Repository audit coverage</h2><table><tr><th>Repository</th><th>Status</th><th>Inspected files</th><th>Skipped</th></tr>")
		for _, c := range r.Repositories {
			b.WriteString("<tr><td>" + h(c.Root) + "</td><td>" + h(c.Status) + "</td><td>" + fmt.Sprint(c.InspectedFiles) + "</td><td>" + fmt.Sprint(c.SkippedFiles) + "</td></tr>")
		}
		b.WriteString("</table>")
	}
	if len(r.Warnings) > 0 {
		b.WriteString("<h2>Warnings</h2><ul>")
		for _, w := range r.Warnings {
			b.WriteString("<li>" + h(w) + "</li>")
		}
		b.WriteString("</ul>")
	}
	b.WriteString("<h2>Recommended follow-up</h2><ol>")
	for _, a := range r.RecommendedActions {
		b.WriteString("<li>" + h(a) + "</li>")
	}
	b.WriteString("</ol><p><small>Local-only report. May contain sensitive internal details. Reports have no cryptographic attestation and require analyst review.</small></p></body></html>")
	return []byte(b.String())
}

// Save writes a single self-contained HTML report as owner-readable only and refuses overwrite.
// JSON and CSV are not written during normal scanning; EncodeCSV and json.Marshal remain for tests and legacy rollup.
func Save(r *Report, htmlPath string) error {
	htmlPath = strings.TrimSpace(htmlPath)
	if htmlPath == "" {
		return fmt.Errorf("empty HTML report path")
	}
	if !strings.HasSuffix(strings.ToLower(htmlPath), ".html") {
		htmlPath = htmlPath + ".html"
	}
	if err := MakeReportDirectory(htmlPath); err != nil {
		return err
	}
	if _, err := os.Lstat(htmlPath); err == nil {
		return fmt.Errorf("output exists, refusing overwrite: %s", htmlPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	// Excl prevents following an existing destination symlink.
	fp, err := os.OpenFile(htmlPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	data := EncodeHTML(r)
	_, werr := fp.Write(data)
	serr := fp.Sync()
	cerr := fp.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(htmlPath)
		return fmt.Errorf("cannot complete report output: %v %v %v", werr, serr, cerr)
	}
	return nil
}

// Exit codes for php2shell scan (operational, not a security clearance).
const (
	ExitOK         = 0 // HTML written; findings may exist
	ExitFatal      = 1 // tool/config/I/O failure
	ExitIncomplete = 2 // HTML written but scan incomplete
)

// ScanExitCode returns the process exit code after a scan attempt.
func ScanExitCode(r *Report, saveErr error) int {
	if saveErr != nil || r == nil {
		return ExitFatal
	}
	if ScanIncomplete(r) {
		return ExitIncomplete
	}
	return ExitOK
}

// ScanIncomplete reports whether coverage indicates inaccessible resources or truncated checks.
// Exit code 2 uses this after a successful HTML write; it is not a security clearance signal.
func ScanIncomplete(r *Report) bool {
	if r == nil {
		return true
	}
	for _, c := range r.Coverage {
		switch strings.ToUpper(c.Status) {
		case "INCOMPLETE", "UNAVAILABLE", "TRUNCATED", "TIMEOUT":
			return true
		}
	}
	for _, repo := range r.Repositories {
		switch strings.ToUpper(repo.Status) {
		case "INCOMPLETE", "UNAVAILABLE", "TRUNCATED":
			return true
		}
	}
	for _, log := range r.Logs {
		switch strings.ToUpper(log.Status) {
		case "INCOMPLETE", "UNAVAILABLE", "TRUNCATED":
			return true
		}
	}
	return false
}

type RollupRow struct {
	ReportHash             string `json:"report_sha256"`
	TrustedTenant          string `json:"trusted_tenant"`
	Hostname               string `json:"hostname"`
	Timestamp              string `json:"timestamp"`
	VulnerabilityStatus    string `json:"vulnerability_status"`
	CompromiseStatus       string `json:"compromise_status"`
	EvidenceCount          int    `json:"evidence_count"`
	MissingOrPartialChecks int    `json:"missing_or_partial_checks"`
	PatchAssessments       int    `json:"patch_assessments"`
	CriticalPatchReviews   int    `json:"critical_patch_reviews"`
	ImmediateAction        string `json:"immediate_action"`
}

// Rollup never trusts report.CustomerLabel to assign a customer to a tenant.
// Explicit hash-to-tenant mapping is controlled by the SOC operator.
func Rollup(reportFiles []string, tenantMapFile string, output string) error {
	if len(reportFiles) == 0 {
		return fmt.Errorf("provide input JSON reports")
	}
	if len(reportFiles) > 1000 {
		return fmt.Errorf("maximum 1000 reports")
	}
	mapping := map[string]string{}
	if tenantMapFile != "" {
		b, err := ReadRegular(tenantMapFile, 2<<20)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &mapping); err != nil {
			return err
		}
	}
	rows := []RollupRow{}
	for _, path := range reportFiles {
		b, err := ReadRegular(path, 5<<20)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		r, err := ParseReport(b)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		sum := sha256.Sum256(b)
		digest := hex.EncodeToString(sum[:])
		tenant := mapping[digest]
		if tenant == "" {
			tenant = "UNMAPPED"
		}
		partial := 0
		for _, c := range r.Coverage {
			if c.Status != "COMPLETE" {
				partial++
			}
		}
		critical := 0
		for _, a := range r.PatchAssessments {
			if a.Priority == "CRITICAL" && a.EvidenceType != "repository_declaration" {
				critical++
			}
		}
		immediate := "Verify active web-serving PHP version and vendor patch evidence."
		if critical > 0 {
			immediate = "Urgent: review below-fix/legacy PHP, apply supported vendor fixes and restart web workers."
		}
		rows = append(rows, RollupRow{digest, tenant, r.Hostname, r.GeneratedUTC.Format("2006-01-02T15:04:05Z"), r.VulnerabilityStatus, r.CompromiseStatus, len(r.Evidence), partial, len(r.PatchAssessments), critical, immediate})
	}
	var buffer bytes.Buffer
	w := csv.NewWriter(&buffer)
	_ = w.Write([]string{"report_sha256", "trusted_tenant", "hostname", "timestamp", "vulnerability_status", "compromise_status", "evidence_count", "missing_or_partial_checks", "patch_assessments", "critical_patch_reviews", "immediate_action"})
	for _, row := range rows {
		fields := []string{row.ReportHash, row.TrustedTenant, row.Hostname, row.Timestamp, row.VulnerabilityStatus, row.CompromiseStatus, fmt.Sprint(row.EvidenceCount), fmt.Sprint(row.MissingOrPartialChecks), fmt.Sprint(row.PatchAssessments), fmt.Sprint(row.CriticalPatchReviews), row.ImmediateAction}
		for i := range fields {
			fields[i] = SpreadsheetSafe(fields[i])
		}
		if err := w.Write(fields); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	if err := MakeReportDirectory(strings.TrimSuffix(output, filepath.Ext(output))); err != nil {
		return err
	}
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(buffer.Bytes())
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(output)
		return fmt.Errorf("rollup output failed: %v %v", err, closeErr)
	}
	return nil
}
