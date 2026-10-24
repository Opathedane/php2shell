package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Documented Cloudflare Managed Ruleset / Free Ruleset / Response Firewall rule IDs
// published for php2shell Anomalous Execution protections (Cloudflare Blog, 21 Oct 2026).
// Only these RuleID values receive high-confidence waf_php2shell_rule_match leads.
var cloudflarePHP2ShellRuleIDs = map[string]string{
	// Free Managed Free Ruleset — Generic Rules - Anomalous Execution 1–7
	"4e315666e8e344cdb64119a3b5ccf32f": "Generic Rules - Anomalous Execution - 1 (free)",
	"00c10e6cc4da4bd08722adeebcd95984": "Generic Rules - Anomalous Execution - 2 (free)",
	"48ddf592361e4fdb97a8a85982dab691": "Generic Rules - Anomalous Execution - 3 (free)",
	"3556683d512a47f2937899c524b1a4c6": "Generic Rules - Anomalous Execution - 4 (free)",
	"da07c85852e34625bb478496302ede46": "Generic Rules - Anomalous Execution - 5 (free)",
	"19373a83abb840e18ab3ce5a7975ce1b": "Generic Rules - Anomalous Execution - 6 (free)",
	"07f0b6ddaabf40b1b2042dade8d613fa": "Generic Rules - Anomalous Execution - 7 (free)",
	// Paid Managed Ruleset — Anomalous Execution 1–7
	"c1d409ad838f47f59446f21cc438d5dd": "Generic Rules - Anomalous Execution - 1 (paid)",
	"f9a45927414245e3a64bb12d0a0c2f64": "Generic Rules - Anomalous Execution - 2 (paid)",
	"771c654ae1154d4daa72f4e1545d163c": "Generic Rules - Anomalous Execution - 3 (paid)",
	"217005865f0145f392300bac212afcc9": "Generic Rules - Anomalous Execution - 4 (paid)",
	"38efdb17ea594501bb55a1d71867b12e": "Generic Rules - Anomalous Execution - 5 (paid)",
	"4148ae686fdb4d01be673fab9d9c073d": "Generic Rules - Anomalous Execution - 6 (paid)",
	"1389aa259617437392ce149c48143645": "Generic Rules - Anomalous Execution - 7 (paid)",
	// Managed Response Firewall Default — high confidence signatures
	"afffe22785674c80a31875c848d2242a": "Default block for High confidence Signatures (response)",
}

// cloudflareFirewallEvent is a subset of the documented Logpush firewall_events schema.
// Fields not present in the official dataset (e.g. Content-Length, multipart nesting)
// are intentionally omitted — never invented.
type cloudflareFirewallEvent struct {
	Action               string          `json:"Action"`
	Datetime             json.RawMessage `json:"Datetime"`
	Description          string          `json:"Description"`
	RuleID               string          `json:"RuleID"`
	Source               string          `json:"Source"`
	RayID                string          `json:"RayID"`
	ClientRequestMethod  string          `json:"ClientRequestMethod"`
	ClientRequestHost    string          `json:"ClientRequestHost"`
	ClientRequestPath    string          `json:"ClientRequestPath"`
	ClientRequestQuery   string          `json:"ClientRequestQuery"`
	EdgeResponseStatus   json.RawMessage `json:"EdgeResponseStatus"`
	OriginResponseStatus json.RawMessage `json:"OriginResponseStatus"`
	Kind                 string          `json:"Kind"`
	// ClientIP is parsed for in-memory correlation only and never retained in findings.
	ClientIP string `json:"ClientIP"`
}

// ScanWAFLog reviews one offline WAF export. Currently supports Cloudflare Logpush
// firewall_events JSON Lines when the documented field set is present.
func ScanWAFLog(r *Report, path string) []InvestigationEvent {
	item := WAFLogCoverage{File: path, Status: "NOT_ASSESSED"}
	b, err := ReadRegular(path, wafLogMaxBytes)
	if err != nil {
		item.Status = "UNAVAILABLE"
		item.Detail = "File inaccessible, nonregular, or over 32 MiB: " + err.Error()
		r.WAFLogs = append(r.WAFLogs, item)
		r.AddWarning("WAF log not reviewed: " + path)
		return nil
	}
	format := detectWAFFormat(b)
	item.Format = string(format)
	if format == WAFFormatUnsupported {
		item.Status = "UNSUPPORTED_FORMAT"
		item.Detail = "No verified WAF export schema matched. Supported: Cloudflare Logpush firewall_events JSONL " +
			"(Action, RuleID, Datetime, ClientRequest*). Multipart nesting / Content-Length are not in that schema and are not invented."
		r.WAFLogs = append(r.WAFLogs, item)
		r.AddWarning("Unsupported WAF log format: " + path)
		return nil
	}

	events, leads, first, last, parseNotes := parseCloudflareFirewallEventsJSONL(path, b)
	item.EventsParsed = events
	item.MatchedLeads = len(leads)
	if !first.IsZero() {
		item.FirstTimestamp = first.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		item.LastTimestamp = last.UTC().Format(time.RFC3339)
	}
	if events == 0 {
		item.Status = "INCOMPLETE"
		item.Detail = "Cloudflare firewall_events JSONL detected but no parseable events. " + parseNotes
	} else if strings.Contains(parseNotes, "Truncated at") {
		// Truncation/oversized event caps are incomplete coverage — not a completed limited parse.
		item.Status = "TRUNCATED"
		item.Detail = fmt.Sprintf(
			"Parsed %d Cloudflare firewall_events as %s before a safety cap (leads=%d). "+
				"Coverage is TRUNCATED — do not treat as complete WAF review. "+
				"Documented schema fields only; Content-Length/multipart nesting are NOT inferred. %s",
			events, format, len(leads), parseNotes,
		)
	} else {
		item.Status = "PARSED_COVERAGE_LIMITED"
		item.Detail = fmt.Sprintf(
			"Parsed %d Cloudflare firewall_events as %s. Leads=%d. "+
				"Documented schema fields only — Content-Length and multipart/form-field nesting are NOT present in firewall_events and were not inferred. "+
				"ClientIP/query/cookie values are not retained in findings (upload-progress presence flag only). "+
				"Blocked/challenged actions are not successful exploitation. %s",
			events, format, len(leads), parseNotes,
		)
	}
	r.WAFLogs = append(r.WAFLogs, item)
	return leads
}

func detectWAFFormat(b []byte) WAFFormat {
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var probe map[string]json.RawMessage
		if json.Unmarshal([]byte(line), &probe) != nil {
			return WAFFormatUnsupported
		}
		_, hasAction := probe["Action"]
		_, hasRule := probe["RuleID"]
		_, hasDT := probe["Datetime"]
		if hasAction && hasRule && hasDT {
			return WAFFormatCloudflareFirewallEventsJSONL
		}
		// Also accept lowercase keys from some JSON exporters.
		_, hasAction = probe["action"]
		_, hasRule = probe["ruleId"]
		if !hasRule {
			_, hasRule = probe["rule_id"]
		}
		_, hasDT = probe["datetime"]
		if hasAction && hasRule && hasDT {
			return WAFFormatCloudflareFirewallEventsJSONL
		}
		return WAFFormatUnsupported
	}
	return WAFFormatUnsupported
}

func parseCloudflareFirewallEventsJSONL(path string, b []byte) (parsed int, leads []InvestigationEvent, first, last time.Time, notes string) {
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	lineNo := 0
	truncated := false
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if parsed >= wafLogMaxEvents {
			truncated = true
			break
		}
		var ev cloudflareFirewallEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			// Completely non-JSON / wrong shape — try alternate casing as a full substitute.
			if !fillCloudflareEventAltCasing([]byte(line), &ev) {
				continue
			}
		} else if strings.TrimSpace(ev.RuleID) == "" || strings.TrimSpace(ev.Action) == "" {
			// Primary unmarshal often "succeeds" with empty RuleID when exporters use rule_id/ruleId.
			// Always merge alternate keys so allowlisted IDs are not silently dropped.
			_ = fillCloudflareEventAltCasing([]byte(line), &ev)
		}
		if strings.TrimSpace(ev.RuleID) == "" && strings.TrimSpace(ev.Action) == "" {
			continue
		}
		parsed++
		ts := parseCloudflareDatetime(ev.Datetime)
		if !ts.IsZero() {
			if first.IsZero() || ts.Before(first) {
				first = ts
			}
			if last.IsZero() || ts.After(last) {
				last = ts
			}
		}

		action := strings.ToLower(strings.TrimSpace(ev.Action))
		ruleLabel, ruleOK := cloudflarePHP2ShellRuleIDs[strings.TrimSpace(ev.RuleID)]
		uploadProgress := queryHasUploadProgressToken(ev.ClientRequestQuery)
		// Never retain raw query / IP / cookies in findings.
		ev.ClientRequestQuery = ""
		ev.ClientIP = ""

		if !ruleOK && !uploadProgress {
			continue
		}
		if len(leads) >= wafLogMaxLeads {
			truncated = true
			break
		}

		edgeStatus := rawJSONScalar(ev.EdgeResponseStatus)
		kind := "waf_php2shell_rule_match"
		conf := "suspected"
		class := "verified_public_pattern"
		detail := ""
		if ruleOK {
			detail = fmt.Sprintf(
				"Cloudflare firewall_events RuleID matched documented php2shell Anomalous Execution protection (%s). "+
					"Action=%s method=%s host=%s path=%s edge_status=%s ray_id=%s. "+
					"Provenance=Cloudflare Logpush firewall_events. "+
					"A block/challenge/log action is an exploitation-attempt assist only — not successful compromise. "+
					"Content-Length and multipart/form-field structure are not fields in this schema and were not inferred.",
				ruleLabel, nullDash(action), nullDash(ev.ClientRequestMethod),
				nullDash(truncateRunes(ev.ClientRequestHost, 80)), nullDash(truncateRunes(ev.ClientRequestPath, 120)),
				nullDash(edgeStatus), nullDash(truncateRunes(ev.RayID, 40)),
			)
		}
		if uploadProgress {
			if ruleOK {
				detail += " Query string contained PHP_SESSION_UPLOAD_PROGRESS token (presence only; value not retained)."
			} else {
				kind = "waf_upload_progress_query_token"
				conf = "unconfirmed"
				class = "heuristic"
				detail = fmt.Sprintf(
					"Cloudflare firewall_events query string contained PHP_SESSION_UPLOAD_PROGRESS token (presence flag only; token/value not retained). "+
						"Action=%s method=%s path=%s ray_id=%s. Weak heuristic aligned with AWS hunt guidance; not proof of exploitation. "+
						"Multipart body fields are not available in this schema.",
					nullDash(action), nullDash(ev.ClientRequestMethod),
					nullDash(truncateRunes(ev.ClientRequestPath, 120)), nullDash(truncateRunes(ev.RayID, 40)),
				)
			}
		}
		if action == "block" || action == "challenge" || strings.Contains(action, "challenge") {
			detail += " Action indicates edge mitigation; do not classify as successful exploitation."
		}
		leads = append(leads, InvestigationEvent{
			Kind:       kind,
			Class:      class,
			Confidence: conf,
			Source:     "Cloudflare Logpush firewall_events (documented fields only); https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/zone/firewall_events/",
			Location:   path,
			Time:       ts,
			Line:       lineNo,
			Detail:     detail,
		})
	}
	if err := scanner.Err(); err != nil {
		// bufio size limit / read error: remaining JSONL was not assessed — not a complete parse.
		truncated = true
		notes = "Overlong or unreadable JSONL line; remaining content not fully assessed."
	}
	if truncated {
		if notes != "" {
			notes += " "
		}
		notes += fmt.Sprintf("Truncated at %d events or %d leads.", wafLogMaxEvents, wafLogMaxLeads)
	}
	if notes == "" {
		notes = "First/last timestamps do not prove continuous WAF coverage."
	}
	return parsed, leads, first, last, notes
}

// fillCloudflareEventAltCasing merges camelCase / snake_case exporter fields into ev.
// Returns false only when the line cannot be decoded as JSON object with those keys.
func fillCloudflareEventAltCasing(line []byte, ev *cloudflareFirewallEvent) bool {
	var alt struct {
		Action              string          `json:"action"`
		Datetime            json.RawMessage `json:"datetime"`
		Description         string          `json:"description"`
		RuleID              string          `json:"ruleId"`
		RuleIDSnake         string          `json:"rule_id"`
		Source              string          `json:"source"`
		RayID               string          `json:"rayId"`
		RayIDSnake          string          `json:"ray_id"`
		ClientRequestMethod string          `json:"clientRequestMethod"`
		ClientRequestHost   string          `json:"clientRequestHost"`
		ClientRequestPath   string          `json:"clientRequestPath"`
		ClientRequestQuery  string          `json:"clientRequestQuery"`
		EdgeResponseStatus  json.RawMessage `json:"edgeResponseStatus"`
	}
	if json.Unmarshal(line, &alt) != nil {
		return false
	}
	if strings.TrimSpace(ev.Action) == "" {
		ev.Action = alt.Action
	}
	if len(ev.Datetime) == 0 {
		ev.Datetime = alt.Datetime
	}
	if strings.TrimSpace(ev.Description) == "" {
		ev.Description = alt.Description
	}
	if strings.TrimSpace(ev.RuleID) == "" {
		ev.RuleID = alt.RuleID
		if ev.RuleID == "" {
			ev.RuleID = alt.RuleIDSnake
		}
	}
	if strings.TrimSpace(ev.Source) == "" {
		ev.Source = alt.Source
	}
	if strings.TrimSpace(ev.RayID) == "" {
		ev.RayID = alt.RayID
		if ev.RayID == "" {
			ev.RayID = alt.RayIDSnake
		}
	}
	if strings.TrimSpace(ev.ClientRequestMethod) == "" {
		ev.ClientRequestMethod = alt.ClientRequestMethod
	}
	if strings.TrimSpace(ev.ClientRequestHost) == "" {
		ev.ClientRequestHost = alt.ClientRequestHost
	}
	if strings.TrimSpace(ev.ClientRequestPath) == "" {
		ev.ClientRequestPath = alt.ClientRequestPath
	}
	if strings.TrimSpace(ev.ClientRequestQuery) == "" {
		ev.ClientRequestQuery = alt.ClientRequestQuery
	}
	if len(ev.EdgeResponseStatus) == 0 {
		ev.EdgeResponseStatus = alt.EdgeResponseStatus
	}
	return true
}

func queryHasUploadProgressToken(q string) bool {
	if q == "" || q == "-" {
		return false
	}
	return strings.Contains(strings.ToUpper(q), "PHP_SESSION_UPLOAD_PROGRESS")
}

func parseCloudflareDatetime(raw json.RawMessage) time.Time {
	if len(raw) == 0 || string(raw) == "null" {
		return time.Time{}
	}
	// String RFC3339 or similar
	var s string
	if json.Unmarshal(raw, &s) == nil {
		s = strings.TrimSpace(s)
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02T15:04:05"} {
			if ts, err := time.Parse(layout, s); err == nil {
				return ts.UTC()
			}
		}
	}
	// Unix seconds or milliseconds (Logpush int form)
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		if i, err := n.Int64(); err == nil {
			if i > 1e12 { // ms
				return time.UnixMilli(i).UTC()
			}
			return time.Unix(i, 0).UTC()
		}
		if f, err := n.Float64(); err == nil {
			return time.Unix(int64(f), 0).UTC()
		}
	}
	return time.Time{}
}

func rawJSONScalar(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	var i int
	if json.Unmarshal(raw, &i) == nil {
		return strconv.Itoa(i)
	}
	return ""
}
