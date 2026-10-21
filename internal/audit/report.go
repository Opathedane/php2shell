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
	phpLabel, versions := humanPHPDetected(r)
	vulnLabel := humanVulnerability(r.VulnerabilityStatus)
	rtLabel, rtDetail := humanRuntime(r)
	compLabel := humanCompromise(r.CompromiseStatus)
	groups := GroupInstallations(r)
	next := r.Summary.NextSteps
	if len(next) == 0 {
		next = BuildFocusedNextSteps(r)
	}

	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>PHP2Shell Security Assessment</title><style>
:root{--ink:#1a2332;--muted:#5b6573;--line:#d7dde6;--bg:#f7f8fa;--card:#fff;--accent:#1f4b7a;--warn:#8a4b12;--warnbg:#fff7ed;--ok:#1f5c3a}
*{box-sizing:border-box}body{font:16px/1.55 "Segoe UI",system-ui,sans-serif;margin:0;color:var(--ink);background:linear-gradient(180deg,#eef2f7, #f7f8fa 180px);padding:28px 18px 48px}
main{max-width:980px;margin:0 auto}.header{margin-bottom:22px}h1{font-size:1.75rem;margin:0 0 8px;color:var(--accent);letter-spacing:-.02em}
.meta{color:var(--muted);font-size:.95rem}.priority{display:inline-block;margin-top:12px;padding:8px 12px;border-radius:6px;background:var(--warnbg);color:var(--warn);font-weight:600}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:22px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;box-shadow:0 1px 0 rgba(16,24,40,.04)}.card h2{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:0 0 8px;font-weight:700}.card .value{font-size:1.05rem;font-weight:650;margin:0 0 6px}.card .detail{color:var(--muted);font-size:.9rem;margin:0}
.notice{background:var(--warnbg);border-left:4px solid #c2741a;padding:14px 16px;border-radius:0 8px 8px 0;margin:18px 0}
h2.section{font-size:1.2rem;margin:28px 0 10px;color:var(--accent)}
table{border-collapse:collapse;width:100%;margin:10px 0 18px;background:var(--card)}th,td{border:1px solid var(--line);padding:9px 10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eef2f6;font-size:.9rem}
ol.actions{padding-left:1.25rem}ol.actions li{margin:8px 0}
details{border:1px solid var(--line);border-radius:8px;background:var(--card);margin:10px 0;padding:0}details>summary{cursor:pointer;padding:12px 14px;font-weight:650;color:var(--accent)}details[open]>summary{border-bottom:1px solid var(--line)}details .body{padding:12px 14px}details table{margin:0}
.footer{margin-top:28px;color:var(--muted);font-size:.85rem}
@media print{body{background:#fff;padding:0}details{break-inside:avoid}details:not([open]){border-style:dashed}a{color:inherit}}
@media (max-width:600px){body{padding:16px 12px}h1{font-size:1.4rem}}
</style></head><body><main>`)

	b.WriteString(`<header class="header"><h1>PHP2Shell Security Assessment</h1>`)
	b.WriteString(`<p class="meta"><strong>Host:</strong> ` + h(r.Hostname) + ` &nbsp;·&nbsp; <strong>Assessed (UTC):</strong> ` + h(r.GeneratedUTC.Format("2006-01-02 15:04:05")) + ` &nbsp;·&nbsp; <strong>Scanner:</strong> ` + h(r.ToolVersion) + `</p>`)
	b.WriteString(`<p class="priority">Overall priority: ` + h(overallPriority(r)) + `</p></header>`)

	b.WriteString(`<div class="notice"><strong>This report is not a clearance.</strong> It does not prove that a host is fully patched, that the correct PHP runtime is serving HTTP, or that the server is uncompromised. Missing findings are not proof of safety.</div>`)

	b.WriteString(`<section class="cards" aria-label="Executive summary">`)
	b.WriteString(`<article class="card"><h2>PHP detected</h2><p class="value">` + h(phpLabel) + `</p><p class="detail">`)
	if len(versions) == 0 {
		b.WriteString("No comparable PHP release versions were extracted from this scan scope.")
	} else {
		b.WriteString("Observed versions: " + h(strings.Join(versions, ", ")))
	}
	b.WriteString(`</p></article>`)
	b.WriteString(`<article class="card"><h2>Vulnerability assessment</h2><p class="value">` + h(vulnLabel) + `</p><p class="detail">Upstream thresholds (21 Oct 2026): 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. Vendor backports require separate verification.</p></article>`)
	b.WriteString(`<article class="card"><h2>Active web runtime</h2><p class="value">` + h(rtLabel) + `</p><p class="detail">` + h(rtDetail) + `</p></article>`)
	b.WriteString(`<article class="card"><h2>Compromise assessment</h2><p class="value">` + h(compLabel) + `</p><p class="detail">IOC matches require analyst review; no matches within scope do not clear the host.</p></article>`)
	b.WriteString(`</section>`)

	b.WriteString(`<h2 class="section">Recommended next steps</h2><ol class="actions">`)
	for _, step := range next {
		b.WriteString(`<li>` + h(step) + `</li>`)
	}
	b.WriteString(`</ol>`)

	b.WriteString(`<h2 class="section">PHP installations (grouped)</h2>`)
	if len(groups) == 0 {
		b.WriteString(`<p>No comparable PHP installation versions were assessed. Inventory may be incomplete.</p>`)
	} else {
		b.WriteString(`<table><thead><tr><th>PHP version</th><th>Minimum fixed</th><th>Assessment</th></tr></thead><tbody>`)
		for _, g := range groups {
			b.WriteString(`<tr><td>` + h(g.Label) + `</td><td>` + h(g.MinimumFixed) + `</td><td>` + h(g.StatusLabel) + `</td></tr>`)
		}
		b.WriteString(`</tbody></table>`)
		for _, g := range groups {
			b.WriteString(`<details><summary>` + h(g.Label) + ` — packages, binaries and evidence</summary><div class="body">`)
			b.WriteString(`<p><strong>Assessment:</strong> ` + h(g.StatusLabel) + ` &nbsp;·&nbsp; <strong>Priority:</strong> ` + h(g.Priority) + `</p>`)
			b.WriteString(`<table><thead><tr><th>Component</th><th>Type</th><th>Version</th><th>Action / limitations</th></tr></thead><tbody>`)
			for _, a := range g.Assessments {
				b.WriteString(`<tr><td>` + h(a.Component) + `</td><td>` + h(a.EvidenceType) + `</td><td>` + h(a.ObservedVersion) + `</td><td>` + h(a.RequiredAction) + `<br><small>` + h(a.Qualification) + `</small></td></tr>`)
			}
			b.WriteString(`</tbody></table>`)
			if len(g.RelatedEvidence) > 0 {
				b.WriteString(`<p><strong>Related evidence</strong> (includes extension packages kept for completeness):</p><table><thead><tr><th>Name</th><th>Version</th><th>Type</th><th>Source</th></tr></thead><tbody>`)
				for _, e := range g.RelatedEvidence {
					b.WriteString(`<tr><td>` + h(e.Name) + `</td><td>` + h(e.Version) + `</td><td>` + h(e.Type) + `</td><td>` + h(e.Source) + `</td></tr>`)
				}
				b.WriteString(`</tbody></table>`)
			}
			b.WriteString(`</div></details>`)
		}
	}

	b.WriteString(`<p>Update sources: OS/LTS vendor security packages; <a href="https://windows.php.net/download/">PHP for Windows</a>; <a href="https://www.php.net/downloads.php">official source downloads</a>. Advisory: <a href="` + h(AdvisoryURL) + `">` + h(AdvisoryURL) + `</a>.</p>`)

	// Collapsible technical sections
	writeDetails := func(title string, body func()) {
		b.WriteString(`<details><summary>` + h(title) + `</summary><div class="body">`)
		body()
		b.WriteString(`</div></details>`)
	}

	writeDetails("Runtime and process information", func() {
		count := 0
		b.WriteString(`<table><thead><tr><th>Name</th><th>Location</th><th>Meaning</th></tr></thead><tbody>`)
		for _, e := range r.Evidence {
			if e.Type != "running_process" && e.Type != "iis_php_handler_config" && e.Type != "binary_static_version" && e.Type != "binary_path" && e.Type != "operator_reported_web_runtime" {
				continue
			}
			count++
			b.WriteString(`<tr><td>` + h(e.Name) + `</td><td>` + h(e.Location) + `<br>` + h(e.Detail) + `</td><td>` + h(e.Interpretation) + `</td></tr>`)
		}
		if count == 0 {
			b.WriteString(`<tr><td colspan="3">No process, handler, or binary runtime evidence recorded.</td></tr>`)
		}
		b.WriteString(`</tbody></table>`)
	})

	writeDetails("PHP configuration findings", func() {
		count := 0
		b.WriteString(`<table><thead><tr><th>Setting / file</th><th>Detail</th><th>Meaning</th></tr></thead><tbody>`)
		for _, e := range r.Evidence {
			if e.Type != "configuration_observation" {
				continue
			}
			count++
			b.WriteString(`<tr><td>` + h(e.Name) + `<br>` + h(e.Location) + `</td><td>` + h(e.Detail) + `</td><td>` + h(e.Interpretation) + `</td></tr>`)
		}
		if count == 0 {
			b.WriteString(`<tr><td colspan="3">No PHP configuration observations in this scan.</td></tr>`)
		}
		b.WriteString(`</tbody></table>`)
	})

	writeDetails("Vulnerability and patch assessment details", func() {
		b.WriteString(`<table><thead><tr><th>Component</th><th>Version</th><th>Status</th><th>Minimum fixed</th><th>Action</th></tr></thead><tbody>`)
		if len(r.PatchAssessments) == 0 {
			b.WriteString(`<tr><td colspan="5">No patch assessments.</td></tr>`)
		}
		for _, a := range r.PatchAssessments {
			b.WriteString(`<tr><td>` + h(a.Component) + `<br><small>` + h(a.EvidenceType) + `</small></td><td>` + h(a.ObservedVersion) + `</td><td>` + h(humanPatchStatus(a.Status)) + `</td><td>` + h(a.MinimumFixed) + `</td><td>` + h(a.RequiredAction) + `</td></tr>`)
		}
		b.WriteString(`</tbody></table>`)
		if len(r.RecommendedActions) > 0 {
			b.WriteString(`<p><strong>Extended remediation notes</strong></p><ol>`)
			for _, a := range r.RecommendedActions {
				b.WriteString(`<li>` + h(a) + `</li>`)
			}
			b.WriteString(`</ol>`)
		}
	})

	writeDetails("Compromise indicators and investigation coverage", func() {
		if r.RuleSequence > 0 {
			b.WriteString(`<p>Signed indicator bundle sequence ` + fmt.Sprint(r.RuleSequence) + ` with ` + fmt.Sprint(r.RuleCount) + ` indicators loaded. Matches require manual review.</p>`)
		} else {
			b.WriteString(`<p>No trusted signed indicator bundle was loaded for this scan. Compromise status cannot be cleared by this tool alone.</p>`)
		}
		if len(r.Findings) == 0 {
			b.WriteString(`<p>No indicator matches were recorded in the assessed scope.</p>`)
		} else {
			b.WriteString(`<table><thead><tr><th>Rule</th><th>Severity</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>`)
			for _, f := range r.Findings {
				b.WriteString(`<tr><td>` + h(f.RuleID) + `</td><td>` + h(f.Severity) + `</td><td>` + h(f.Confidence) + `</td><td>` + h(f.Location) + `: ` + h(f.Detail) + `</td></tr>`)
			}
			b.WriteString(`</tbody></table>`)
		}
		if len(r.Logs) > 0 {
			b.WriteString(`<p><strong>Access log coverage</strong></p><table><thead><tr><th>File</th><th>Status</th><th>Lines</th><th>Parsed</th></tr></thead><tbody>`)
			for _, c := range r.Logs {
				b.WriteString(`<tr><td>` + h(c.File) + `</td><td>` + h(c.Status) + `</td><td>` + fmt.Sprint(c.Lines) + `</td><td>` + fmt.Sprint(c.ParsedRequests) + `</td></tr>`)
			}
			b.WriteString(`</tbody></table>`)
		}
	})

	writeDetails("Scan coverage and limitations", func() {
		b.WriteString(`<table><thead><tr><th>Check</th><th>Status</th><th>Notes</th></tr></thead><tbody>`)
		for _, c := range r.Coverage {
			b.WriteString(`<tr><td>` + h(c.Name) + `</td><td>` + h(c.Status) + `</td><td>` + h(c.Detail) + `</td></tr>`)
		}
		b.WriteString(`</tbody></table>`)
		if len(r.Warnings) > 0 {
			b.WriteString(`<p><strong>Warnings</strong></p><ul>`)
			for _, w := range r.Warnings {
				b.WriteString(`<li>` + h(w) + `</li>`)
			}
			b.WriteString(`</ul>`)
		}
		if len(r.Repositories) > 0 {
			b.WriteString(`<p><strong>Repositories</strong></p><table><thead><tr><th>Root</th><th>Status</th><th>Inspected</th><th>Skipped</th></tr></thead><tbody>`)
			for _, c := range r.Repositories {
				b.WriteString(`<tr><td>` + h(c.Root) + `</td><td>` + h(c.Status) + `</td><td>` + fmt.Sprint(c.InspectedFiles) + `</td><td>` + fmt.Sprint(c.SkippedFiles) + `</td></tr>`)
			}
			b.WriteString(`</tbody></table>`)
		}
	})

	writeDetails("Full technical evidence ("+fmt.Sprint(len(r.Evidence))+")", func() {
		b.WriteString(`<table><thead><tr><th>Type</th><th>Name</th><th>Version</th><th>Source / path</th><th>Meaning</th></tr></thead><tbody>`)
		for _, e := range r.Evidence {
			b.WriteString(`<tr><td>` + h(e.Type) + `</td><td>` + h(e.Name) + `</td><td>` + h(e.Version) + `</td><td>` + h(e.Source) + `<br>` + h(e.Location) + `<br>` + h(e.Detail) + `</td><td>` + h(e.Interpretation) + `</td></tr>`)
		}
		b.WriteString(`</tbody></table>`)
	})

	b.WriteString(`<p class="footer">Local-only HTML report. May contain sensitive hostnames and paths. No cryptographic attestation of findings. Generated by PHP2Shell ` + h(r.ToolVersion) + `.</p>`)
	b.WriteString(`</main></body></html>`)
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
