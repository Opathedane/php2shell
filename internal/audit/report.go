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
	w.Flush()
	return b.Bytes(), w.Error()
}

func EncodeHTML(r *Report) []byte {
	var b strings.Builder
	h := func(s string) string { return html.EscapeString(s) }
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline'"><title>PHP2Shell Assessment</title><style>body{font:15px/1.5 system-ui,Arial,sans-serif;max-width:1050px;margin:35px auto;padding:0 20px;color:#21262c}h1,h2{color:#152437}.notice{background:#fff7ed;border-left:4px solid #ad5e0d;padding:16px}table{border-collapse:collapse;width:100%;margin:15px 0 30px}td,th{border:1px solid #dce1e8;padding:9px;vertical-align:top;text-align:left;overflow-wrap:anywhere}th{background:#eef1f4}code{overflow-wrap:anywhere}p{max-width:75em}@media print{body{max-width:none;margin:0}}</style></head><body>`)
	b.WriteString("<h1>PHP2Shell – evidence assessment</h1><p><strong>Host: </strong>" + h(r.Hostname) + " &nbsp; <strong>UTC:</strong> " + h(r.GeneratedUTC.Format("2006-01-02 15:04:05")) + " &nbsp; <strong>Version:</strong> " + h(r.ToolVersion) + "</p>")
	b.WriteString("<div class=notice><strong>Results are NOT a vulnerability clearance or compromise clearance.</strong><p>Vulnerability: " + h(r.VulnerabilityStatus) + ". Compromise: " + h(r.CompromiseStatus) + ". Serving PHP runtime: " + h(r.EffectiveWebRuntime) + ". Lack of findings is not proof of safety.</p></div>")
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

// Save creates all files as owner-readable only and refuses to overwrite any existing target.
// If a later file fails, only newly created files from this invocation are removed.
func Save(r *Report, outPrefix string) error {
	if strings.TrimSpace(outPrefix) == "" {
		return fmt.Errorf("empty output prefix")
	}
	if err := MakeReportDirectory(outPrefix); err != nil {
		return err
	}
	js, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	csvB, err := EncodeCSV(r)
	if err != nil {
		return err
	}
	files := []struct {
		path string
		data []byte
	}{{outPrefix + ".json", append(js, '\n')}, {outPrefix + ".csv", csvB}, {outPrefix + ".html", EncodeHTML(r)}}
	for _, f := range files {
		if _, err := os.Lstat(f.path); err == nil {
			return fmt.Errorf("output exists, refusing overwrite: %s", f.path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	created := []string{}
	for _, target := range files {
		// Excl prevents following an existing destination symlink.
		fp, err := os.OpenFile(target.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			for _, c := range created {
				_ = os.Remove(c)
			}
			return err
		}
		created = append(created, target.path)
		_, werr := fp.Write(target.data)
		serr := fp.Sync()
		cerr := fp.Close()
		if werr != nil || serr != nil || cerr != nil {
			for _, c := range created {
				_ = os.Remove(c)
			}
			return fmt.Errorf("cannot complete report output: %v %v %v", werr, serr, cerr)
		}
	}
	return nil
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
		rows = append(rows, RollupRow{digest, tenant, r.Hostname, r.GeneratedUTC.Format("2006-01-02T15:04:05Z"), r.VulnerabilityStatus, r.CompromiseStatus, len(r.Evidence), partial})
	}
	var buffer bytes.Buffer
	w := csv.NewWriter(&buffer)
	_ = w.Write([]string{"report_sha256", "trusted_tenant", "hostname", "timestamp", "vulnerability_status", "compromise_status", "evidence_count", "missing_or_partial_checks"})
	for _, row := range rows {
		fields := []string{row.ReportHash, row.TrustedTenant, row.Hostname, row.Timestamp, row.VulnerabilityStatus, row.CompromiseStatus, fmt.Sprint(row.EvidenceCount), fmt.Sprint(row.MissingOrPartialChecks)}
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
