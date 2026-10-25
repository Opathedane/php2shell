package audit

import (
	"fmt"
	"strings"
	"time"
)

// Offline WAF export bounds (read-only).
const (
	wafLogMaxFiles  = 8
	wafLogMaxEvents = 50000
	wafLogMaxLeads  = 100
)

// wafLogMaxBytes caps a single --waf-log file read (32 MiB). Tests may lower this.
var wafLogMaxBytes int64 = 32 << 20

// WAFFormat identifies a verified offline export schema.
type WAFFormat string

const (
	WAFFormatCloudflareFirewallEventsJSONL WAFFormat = "cloudflare_firewall_events_jsonl"
	WAFFormatUnsupported                   WAFFormat = "unsupported"
)

// WAFLogCoverage summarizes one --waf-log file review.
type WAFLogCoverage struct {
	File           string `json:"file"`
	Status         string `json:"status"`
	Format         string `json:"format,omitempty"`
	EventsParsed   int    `json:"events_parsed"`
	EventsInWindow int    `json:"events_in_window,omitempty"`
	MatchedLeads   int    `json:"matched_leads,omitempty"`
	FirstTimestamp string `json:"first_timestamp,omitempty"`
	LastTimestamp  string `json:"last_timestamp,omitempty"`
	Detail         string `json:"detail,omitempty"`
}

func countWAFUsable(items []WAFLogCoverage) (usable, unusable int) {
	for _, it := range items {
		switch strings.ToUpper(it.Status) {
		case "UNAVAILABLE", "INCOMPLETE", "UNSUPPORTED_FORMAT":
			unusable++
		default:
			if it.EventsParsed > 0 {
				usable++
			} else {
				unusable++
			}
		}
	}
	return
}

// correlateWAF emits temporal proximity findings only (not same-worker identity).
// WAF block/challenge never implies successful compromise.
func correlateWAF(r *Report, waf, errors, access []InvestigationEvent, procs []ProcessLead) int {
	corr := 0
	for _, w := range waf {
		if w.Time.IsZero() {
			continue
		}
		for _, ev := range errors {
			if ev.Time.IsZero() || !isErrorResearchKind(ev.Kind) {
				continue
			}
			delta := w.Time.Sub(ev.Time)
			if delta < 0 {
				delta = -delta
			}
			if delta <= correlationWindow {
				corr++
				appendInvestigationFinding(r, InvestigationFinding{
					ID:           fmt.Sprintf("corr-waf-err-%d-%d", w.Line, ev.Line),
					Class:        "correlation",
					Kind:         "correlated_waf_and_error",
					Confidence:   "unconfirmed",
					Source:       "php2shell temporal proximity (±15m); not causality; not same-worker identity",
					Location:     w.Location + " + " + ev.Location,
					TimestampUTC: w.Time.UTC().Format(time.RFC3339),
					Detail: fmt.Sprintf(
						"Temporal proximity only (Δ=%s ≤ 15m), not causality and not proof two requests shared a PHP worker. "+
							"Contributing evidence: WAF %s and error-log %s. A blocked WAF action is not successful exploitation.",
						delta.Round(time.Second), w.Kind, ev.Kind,
					),
				})
				if corr >= 20 {
					return corr
				}
			}
		}
		for _, ev := range access {
			if ev.Time.IsZero() || !isAccessCorrelationKind(ev.Kind) {
				continue
			}
			delta := w.Time.Sub(ev.Time)
			if delta < 0 {
				delta = -delta
			}
			if delta <= correlationWindow {
				corr++
				appendInvestigationFinding(r, InvestigationFinding{
					ID:           fmt.Sprintf("corr-waf-acc-%d-%d", w.Line, ev.Line),
					Class:        "correlation",
					Kind:         "correlated_waf_and_access",
					Confidence:   "unconfirmed",
					Source:       "php2shell temporal proximity (±15m); not causality; not same-worker identity",
					Location:     w.Location + " + " + ev.Location,
					TimestampUTC: w.Time.UTC().Format(time.RFC3339),
					Detail: fmt.Sprintf(
						"Temporal proximity only (Δ=%s ≤ 15m). WAF lead beside access-log request-target heuristic (not body size). "+
							"Not same-worker identity; blocked WAF ≠ successful exploitation.",
						delta.Round(time.Second),
					),
				})
				if corr >= 20 {
					return corr
				}
			}
		}
		for _, p := range procs {
			if p.Event.TimeUTC.IsZero() {
				continue
			}
			delta := w.Time.Sub(p.Event.TimeUTC)
			if delta < 0 {
				delta = -delta
			}
			if delta <= correlationWindow {
				corr++
				appendInvestigationFinding(r, InvestigationFinding{
					ID:           fmt.Sprintf("corr-waf-proc-%d-%s", w.Line, p.DedupKey),
					Class:        "correlation",
					Kind:         "correlated_waf_and_process",
					Confidence:   "unconfirmed",
					Source:       "php2shell temporal proximity (±15m); not causality; not same-worker identity",
					Location:     w.Location + " + " + p.Event.SourceFile,
					TimestampUTC: w.Time.UTC().Format(time.RFC3339),
					Detail: fmt.Sprintf(
						"Temporal proximity only (Δ=%s ≤ 15m) between WAF lead and process lead %s. "+
							"Does not prove the WAF request caused the process event or shared a worker. "+
							"Possible-compromise still requires host-level process/webroot evidence independently.",
						delta.Round(time.Second), p.Kind,
					),
				})
				if corr >= 20 {
					return corr
				}
			}
		}
	}
	return corr
}
