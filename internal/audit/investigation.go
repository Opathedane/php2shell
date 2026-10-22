package audit

import (
	"fmt"
	"strings"
	"time"
)

// SuggestedInvestigateFromUTC is the PHP2Shell-recommended investigation floor
// (AWS MadPot observations from 2026-10-17). Analysts may choose an earlier From.
var SuggestedInvestigateFromUTC = time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)

// Access anomaly / correlation bounds (deterministic, conservative).
const (
	longPOSTTargetRunes      = 2048
	correlationWindow        = 15 * time.Minute
	maxInvestigationFindings = 200
)

// InvestigationEvent is a timed signal used while finalizing a scan (not serialized raw).
type InvestigationEvent struct {
	Kind       string
	Class      string
	Confidence string
	Source     string
	Location   string
	Time       time.Time // zero if unknown
	Line       int
	Detail     string
}

// InvestigationOptions configures offline investigation (logs + process telemetry).
type InvestigationOptions struct {
	// From/To are UTC bounds. Zero From defaults to SuggestedInvestigateFromUTC when assessing.
	// Zero To defaults to report GeneratedUTC.
	From time.Time
	To   time.Time
	// Assessing is true when the operator supplied any investigation input
	// (--access-log, --error-log, --process-telemetry, --webroot, and/or --waf-log).
	Assessing bool
	// HasProcessTelemetry is true when at least one --process-telemetry file was requested.
	HasProcessTelemetry bool
	// HasWebrootInvestigation is true when --webroot was supplied for FS investigation.
	HasWebrootInvestigation bool
	// HasWAFLogs is true when at least one --waf-log file was requested.
	HasWAFLogs bool
}

// ResolveInvestigationWindow returns the effective UTC window and a human note.
func ResolveInvestigationWindow(opts InvestigationOptions, generatedUTC time.Time) (from, to time.Time, win InvestigationWindow) {
	from = opts.From
	if from.IsZero() {
		from = SuggestedInvestigateFromUTC
	}
	to = opts.To
	if to.IsZero() {
		if generatedUTC.IsZero() {
			to = time.Now().UTC()
		} else {
			to = generatedUTC.UTC()
		}
	}
	from = from.UTC()
	to = to.UTC()
	win = InvestigationWindow{
		FromUTC:          from.Format(time.RFC3339),
		ToUTC:            to.Format(time.RFC3339),
		SuggestedFromUTC: SuggestedInvestigateFromUTC.Format(time.RFC3339),
		Note: "Earliest/latest timestamps in supplied logs/telemetry do not prove continuous coverage. " +
			"Rotation gaps, missing intervals, parser failures, timezone ambiguity, PID reuse, and inaccessible sources may hide activity. " +
			"Analysts may set --investigate-from earlier than 2026-10-17 when retained records exist.",
	}
	return from, to, win
}

func inInvestigationWindow(t, from, to time.Time) bool {
	if t.IsZero() {
		return true
	}
	tu := t.UTC()
	return !tu.Before(from) && !tu.After(to)
}

func appendInvestigationFinding(r *Report, f InvestigationFinding) {
	if r == nil {
		return
	}
	if len(r.InvestigationFindings) >= maxInvestigationFindings {
		if len(r.InvestigationFindings) == maxInvestigationFindings {
			r.AddWarning("Investigation findings limited to 200 matches; additional matches omitted")
		}
		return
	}
	r.InvestigationFindings = append(r.InvestigationFindings, f)
}

// FinalizeInvestigation sets independent exploitation-attempt, possible-compromise,
// and investigation-coverage statuses. Possible compromise stays NOT_ASSESSED unless
// offline process telemetry and/or webroot investigation inputs were usable.
// WAF leads contribute to exploitation-attempt review only (never alone to possible compromise).
// Never emits CONFIRMED_COMPROMISE or CLEAN.
func FinalizeInvestigation(r *Report, opts InvestigationOptions, accessEvents, errorEvents []InvestigationEvent, processLeads []ProcessLead, webrootLeads []WebrootLead, wafEvents ...[]InvestigationEvent) {
	if r == nil {
		return
	}
	var wafEv []InvestigationEvent
	if len(wafEvents) > 0 {
		wafEv = wafEvents[0]
	}
	if !opts.Assessing {
		r.ExploitationAttemptStatus = "NOT_ASSESSED"
		r.PossibleCompromiseStatus = "NOT_ASSESSED"
		r.InvestigationCoverage = "NOT_REQUESTED"
		r.InvestigationWindow = nil
		r.AddCheck("compromise_investigation", "NOT_REQUESTED",
			"No --access-log, --error-log, --process-telemetry, --webroot, or --waf-log investigation inputs supplied; exploitation-attempt and possible-compromise statuses remain NOT_ASSESSED (not a negative finding)")
		r.AddCheck("process_telemetry_investigation", "NOT_REQUESTED",
			"No offline process/EDR telemetry supplied")
		r.AddCheck("webroot_investigation", "NOT_REQUESTED",
			"No --webroot filesystem investigation requested; possible-compromise stays NOT_ASSESSED without process or webroot evidence")
		r.AddCheck("waf_log_investigation", "NOT_REQUESTED",
			"No offline WAF event export supplied")
		return
	}

	from, to, win := ResolveInvestigationWindow(opts, r.GeneratedUTC)
	r.InvestigationWindow = &win

	usableAccess, unusableAccess := countLogUsable(r.Logs)
	usableError, unusableError := countErrorLogUsable(r.ErrorLogs)
	usableProc, unusableProc := countProcessTelemetryUsable(r.ProcessTelemetry)
	usableWeb, unusableWeb := countWebrootUsable(r.WebrootInvestigation)
	usableWAF, unusableWAF := countWAFUsable(r.WAFLogs)

	hasLogInputs := usableAccess+unusableAccess+usableError+unusableError > 0
	hasProcInputs := opts.HasProcessTelemetry
	hasWebrootInputs := opts.HasWebrootInvestigation
	hasWAFInputs := opts.HasWAFLogs

	// P0: SAPI-aware narrative + HTTP body/form metadata limitations (always when assessing).
	emitInvestigationP0Context(r)

	coverage := "ASSESSED_SCOPE_LIMITED"
	coverageDetail := "Usable investigation inputs were reviewed inside the selected UTC window (completed assessment of available evidence — not the same as unavailable sources). " +
		"First/last timestamps do not prove continuous coverage; rotation gaps and missing sources cannot be ruled out. " +
		"Filesystem modification times are not file creation evidence. " +
		"Ordinary access logs do not expose HTTP request bodies, form-field names, or multipart nesting."

	// If every requested input class failed entirely, mark incomplete.
	logsAllFailed := hasLogInputs && usableAccess+usableError == 0
	procAllFailed := hasProcInputs && usableProc == 0 && unusableProc > 0
	webAllFailed := hasWebrootInputs && usableWeb == 0 && unusableWeb > 0
	if hasLogInputs && usableAccess+usableError == 0 && !hasProcInputs && !hasWebrootInputs && !hasWAFInputs {
		r.InvestigationCoverage = "INCOMPLETE"
		r.ExploitationAttemptStatus = "NOT_ASSESSED"
		r.PossibleCompromiseStatus = "NOT_ASSESSED"
		r.AddCheck("compromise_investigation", "INCOMPLETE",
			"Investigation was requested but no usable access/error log could be parsed; statuses remain NOT_ASSESSED (unavailable/incomplete evidence, not absence of matches)")
		r.AddCheck("process_telemetry_investigation", "NOT_REQUESTED",
			"No offline process/EDR telemetry supplied")
		r.AddCheck("webroot_investigation", "NOT_REQUESTED",
			"No --webroot filesystem investigation requested")
		r.AddCheck("waf_log_investigation", "NOT_REQUESTED",
			"No offline WAF event export supplied")
		r.AddWarning("Investigation coverage incomplete: supplied logs were inaccessible, oversized, or unreadable (unavailable ≠ no matches)")
		return
	}
	_ = logsAllFailed
	_ = procAllFailed
	_ = webAllFailed
	if unusableAccess+unusableError+unusableProc+unusableWeb+unusableWAF > 0 {
		coverage = "INCOMPLETE"
		coverageDetail = "At least one requested evidence source was UNAVAILABLE, unsupported, truncated, or incompletely parsed. " +
			"Unavailable evidence is not the same as a completed assessment with no matches. " +
			"Do not treat missing matches as proof of safety; gaps cannot be ruled out from first/last timestamps alone."
	}
	r.AddCheck("investigation_evidence_sources", coverage, formatEvidenceSourceAvailability(
		usableAccess+unusableAccess > 0, usableAccess, unusableAccess,
		usableError+unusableError > 0, usableError, unusableError,
		hasProcInputs, usableProc, unusableProc,
		hasWebrootInputs, usableWeb, unusableWeb,
		hasWAFInputs, usableWAF, unusableWAF,
	))

	var timedUnknown bool
	var inScopeAccess, inScopeError, inScopeWAF []InvestigationEvent
	for _, ev := range accessEvents {
		if ev.Time.IsZero() {
			timedUnknown = true
			inScopeAccess = append(inScopeAccess, ev)
			continue
		}
		if inInvestigationWindow(ev.Time, from, to) {
			inScopeAccess = append(inScopeAccess, ev)
		}
	}
	for _, ev := range errorEvents {
		if ev.Time.IsZero() {
			timedUnknown = true
			inScopeError = append(inScopeError, ev)
			continue
		}
		if inInvestigationWindow(ev.Time, from, to) {
			inScopeError = append(inScopeError, ev)
		}
	}
	for _, ev := range wafEv {
		if ev.Time.IsZero() {
			timedUnknown = true
			inScopeWAF = append(inScopeWAF, ev)
			continue
		}
		if inInvestigationWindow(ev.Time, from, to) {
			inScopeWAF = append(inScopeWAF, ev)
		}
	}

	var inScopeProc []ProcessLead
	procInWindow := 0
	for _, lead := range processLeads {
		ev := lead.Event
		if ev.TimeUTC.IsZero() {
			timedUnknown = true
			inScopeProc = append(inScopeProc, lead)
			continue
		}
		if inInvestigationWindow(ev.TimeUTC, from, to) {
			procInWindow++
			inScopeProc = append(inScopeProc, lead)
		}
	}
	for i := range r.ProcessTelemetry {
		// Annotate window counts approximately from leads (coverage detail).
		if r.ProcessTelemetry[i].EventsParsed > 0 {
			r.ProcessTelemetry[i].EventsInWindow = r.ProcessTelemetry[i].EventsParsed // upper bound note in detail
		}
	}
	_ = procInWindow

	if timedUnknown {
		if coverage != "INCOMPLETE" {
			coverage = "PARTIAL_TIMESTAMP_UNCERTAIN"
		}
		coverageDetail += " Some matched lines/events lacked reliable timestamps (timezone/format uncertainty)."
	}

	// --- Exploitation-attempt leads (access/error/WAF) ---
	attemptHits := 0
	if usableAccess+usableError > 0 {
		for _, ev := range inScopeError {
			attemptHits++
			appendInvestigationFinding(r, findingFromLogEvent("err", ev))
		}
		for _, ev := range inScopeAccess {
			attemptHits++
			appendInvestigationFinding(r, findingFromLogEvent("acc", ev))
		}
	}
	if usableWAF > 0 {
		for _, ev := range inScopeWAF {
			attemptHits++
			appendInvestigationFinding(r, findingFromLogEvent("waf", ev))
		}
	}

	corr := correlateAccessError(r, inScopeError, inScopeAccess)
	wafCorr := correlateWAF(r, inScopeWAF, inScopeError, inScopeAccess, inScopeProc)
	_ = wafCorr

	// Process ↔ attempt temporal proximity (not causality).
	procCorr := 0
	for _, lead := range inScopeProc {
		if lead.Event.TimeUTC.IsZero() {
			continue
		}
		for _, ev := range inScopeError {
			if ev.Time.IsZero() {
				continue
			}
			if ev.Kind != "php_oom_unknown_line0" && ev.Kind != "apache_child_segfault" {
				continue
			}
			delta := lead.Event.TimeUTC.Sub(ev.Time)
			if delta < 0 {
				delta = -delta
			}
			if delta <= correlationWindow {
				procCorr++
				appendInvestigationFinding(r, InvestigationFinding{
					ID:           fmt.Sprintf("corr-proc-err-%s-%d", lead.DedupKey, ev.Line),
					Class:        "correlation",
					Kind:         "correlated_process_and_error",
					Confidence:   "unconfirmed",
					Source:       "php2shell temporal proximity (±15m); not causality",
					Location:     lead.Event.SourceFile + " + " + ev.Location,
					TimestampUTC: lead.Event.TimeUTC.UTC().Format(time.RFC3339),
					Detail: fmt.Sprintf(
						"Temporal proximity only (Δ=%s ≤ 15m), not causality. Contributing evidence: process lead %s (entity=%s) and error-log %s line %d. "+
							"Does not confirm successful exploitation or compromise.",
						delta.Round(time.Second), lead.Kind, nullDash(lead.Event.ProcessEntityID), ev.Kind, ev.Line,
					),
				})
				if procCorr >= 20 {
					break
				}
			}
		}
		if procCorr >= 20 {
			break
		}
		for _, ev := range inScopeAccess {
			if ev.Time.IsZero() || ev.Kind != "access_long_post_target" {
				continue
			}
			delta := lead.Event.TimeUTC.Sub(ev.Time)
			if delta < 0 {
				delta = -delta
			}
			if delta <= correlationWindow {
				procCorr++
				appendInvestigationFinding(r, InvestigationFinding{
					ID:           fmt.Sprintf("corr-proc-acc-%s-%d", lead.DedupKey, ev.Line),
					Class:        "correlation",
					Kind:         "correlated_process_and_access",
					Confidence:   "unconfirmed",
					Source:       "php2shell temporal proximity (±15m); not causality",
					Location:     lead.Event.SourceFile + " + " + ev.Location,
					TimestampUTC: lead.Event.TimeUTC.UTC().Format(time.RFC3339),
					Detail: fmt.Sprintf(
						"Temporal proximity only (Δ=%s ≤ 15m), not causality. Contributing evidence: process lead %s (entity=%s) and access-log %s line %d (request-target length heuristic, not body size). "+
							"Does not confirm successful exploitation or compromise.",
						delta.Round(time.Second), lead.Kind, nullDash(lead.Event.ProcessEntityID), ev.Kind, ev.Line,
					),
				})
				if procCorr >= 20 {
					break
				}
			}
		}
		if procCorr >= 20 {
			break
		}
	}

	// Emit process leads (possible-compromise axis).
	for _, lead := range inScopeProc {
		ts := ""
		if !lead.Event.TimeUTC.IsZero() {
			ts = lead.Event.TimeUTC.UTC().Format(time.RFC3339)
		}
		appendInvestigationFinding(r, InvestigationFinding{
			ID:           "proc-" + lead.DedupKey,
			Class:        "behavioral_convergent",
			Kind:         lead.Kind,
			Confidence:   lead.Confidence,
			Source:       string(lead.Event.SourceFormat) + " offline export",
			Location:     lead.Event.SourceFile,
			TimestampUTC: ts,
			Detail:       lead.Detail,
		})
	}

	// Webroot filesystem leads (metadata-only; never content/webshell scanning).
	// Leads are window-gated at detection; all confidence=unconfirmed.
	var inScopeWeb []WebrootLead
	for _, lead := range webrootLeads {
		inScopeWeb = append(inScopeWeb, lead)
		ts := preferTS(lead.BirthUTC, lead.BirthAvailable, lead.MtimeUTC)
		tsStr := ""
		if !ts.IsZero() {
			tsStr = ts.UTC().Format(time.RFC3339)
		}
		conf := lead.Confidence
		if conf == "" || conf == "suspected" {
			conf = "unconfirmed" // never present metadata-only as EDR-strength
		}
		appendInvestigationFinding(r, InvestigationFinding{
			ID:           "fs-" + lead.DedupKey,
			Class:        "heuristic",
			Kind:         lead.Kind,
			Confidence:   conf,
			Source:       "authorized --webroot filesystem metadata (contents not read; weaker than EDR)",
			Location:     lead.Path,
			TimestampUTC: tsStr,
			Detail:       lead.Detail,
		})
	}

	webCorr := correlateWebroot(r, inScopeWeb, inScopeError, inScopeAccess, inScopeProc)

	r.InvestigationCoverage = coverage

	// Exploitation attempts: access/error logs and/or offline WAF events.
	hasAttemptInputs := hasLogInputs || hasWAFInputs
	usableAttempt := usableAccess + usableError + usableWAF
	if hasAttemptInputs {
		if usableAttempt == 0 {
			r.ExploitationAttemptStatus = "NOT_ASSESSED"
			r.AddWarning("Exploitation-attempt inputs were requested but not usable; status remains NOT_ASSESSED (unavailable/incomplete evidence — not the same as no matches)")
		} else if attemptHits > 0 || corr > 0 {
			r.ExploitationAttemptStatus = "SUSPECTED_ATTEMPTS_REVIEW"
			r.AddWarning("Suspected exploitation-attempt leads require analyst validation; they are not proof of successful exploitation or host compromise")
			r.AddWarning("Successful in-process exploitation may produce neither a worker crash nor a suspicious child process; absence of those signals is not a negative finding")
			r.AddAction("Preserve original access/error/WAF logs covering the investigation window (from at least 2026-10-17 when possible) and escalate suspected attempt leads for human review")
		} else {
			r.ExploitationAttemptStatus = "NO_MATCHES_IN_SCOPE"
			r.AddAction("Usable exploitation-attempt evidence was assessed and no patterns matched in scope — this is a completed no-match result for those sources, not unavailable evidence, and not a host clearance. Expand retention, offline EDR/process review, and WAF exports when missing.")
			r.AddWarning("Successful in-process exploitation may produce neither a worker crash nor a suspicious child process; no-match on current heuristics is not proof of safety")
		}
	} else {
		r.ExploitationAttemptStatus = "NOT_ASSESSED"
	}

	// Process telemetry coverage check (independent of webroot).
	if !hasProcInputs {
		r.AddCheck("process_telemetry_investigation", "NOT_REQUESTED",
			"No offline process/EDR telemetry supplied")
	} else if usableProc == 0 {
		r.AddCheck("process_telemetry_investigation", "INCOMPLETE",
			"Process telemetry was requested but no usable events were parsed (incomplete evidence, not absence of matches)")
		r.AddWarning("Process telemetry incomplete or unsupported; do not treat as a negative compromise finding")
	} else if len(inScopeProc) > 0 {
		r.AddCheck("process_telemetry_investigation", coverage,
			fmt.Sprintf("Parsed process telemetry with %d suspicious parent→child lead(s) in window (behavioral convergent; not confirmed compromise). Command lines redacted to classification tokens.", len(inScopeProc)))
		r.AddWarning("Possible compromise process leads require analyst validation against host baselines; normal apps may launch shells/interpreters")
		r.AddAction("Validate suspicious web/PHP worker child processes with original EDR/Sysmon/audit records; do not treat POSSIBLE_COMPROMISE_REVIEW as confirmed compromise")
	} else {
		r.AddCheck("process_telemetry_investigation", coverage,
			"Process telemetry reviewed in scope with no web/PHP→suspicious-child leads; not a host clearance (coverage limited; missed parents/PID reuse possible)")
	}

	// Webroot investigation coverage check.
	if !hasWebrootInputs {
		r.AddCheck("webroot_investigation", "NOT_REQUESTED",
			"No --webroot filesystem investigation requested")
	} else if usableWeb == 0 {
		r.AddCheck("webroot_investigation", "INCOMPLETE",
			"Webroot investigation was requested but the directory was unavailable or unusable; incomplete evidence, not absence of matches")
		r.AddWarning("Webroot investigation incomplete; do not treat as a negative compromise finding")
	} else if len(inScopeWeb) > 0 {
		r.AddCheck("webroot_investigation", coverage,
			fmt.Sprintf("Authorized webroot metadata review found %d unconfirmed filesystem lead(s). "+
				"WEAK METADATA-ONLY evidence (weaker than EDR process leads). Not a webshell scanner; mtime is not creation or execution; file contents were not read.",
				len(inScopeWeb)))
		r.AddWarning("Webroot filesystem leads are low-confidence investigative heuristics; ordinary CMS uploads and deployments can match")
		r.AddAction("Validate webroot filesystem leads against deployment baselines; do not treat as confirmed webshell or successful exploitation")
	} else {
		r.AddCheck("webroot_investigation", coverage,
			"Authorized webroot metadata reviewed with no upload/unusual-extension leads in scope; not a host clearance (mtime≠creation; truncated walks possible)")
	}

	// Possible compromise: process telemetry and/or webroot timestamp evidence.
	// Path-context webroot leads alone must not flip POSSIBLE_COMPROMISE_REVIEW.
	hasCompromiseInputs := hasProcInputs || hasWebrootInputs
	usableCompromise := usableProc + usableWeb
	webrootTemporal := 0
	for _, lead := range inScopeWeb {
		if webrootLeadIsTimestampEvidence(lead.Kind) {
			webrootTemporal++
		}
	}
	compromiseLeads := len(inScopeProc) + webrootTemporal
	if !hasCompromiseInputs {
		r.PossibleCompromiseStatus = "NOT_ASSESSED"
	} else if usableCompromise == 0 {
		r.PossibleCompromiseStatus = "NOT_ASSESSED"
		r.AddWarning("Possible-compromise inputs were requested but none were usable; status remains NOT_ASSESSED (incomplete, not negative)")
	} else if compromiseLeads > 0 {
		r.PossibleCompromiseStatus = "POSSIBLE_COMPROMISE_REVIEW"
		if len(inScopeProc) == 0 && webrootTemporal > 0 {
			r.AddWarning("POSSIBLE_COMPROMISE_REVIEW rests on low-confidence webroot metadata only (not EDR-strength evidence). " +
				"This is an investigative lead, not confirmed webshell activity or successful exploitation. " +
				"Path location context alone is not treated as recent compromise evidence.")
			r.AddAction("Treat webroot-only POSSIBLE_COMPROMISE_REVIEW as a weak investigative lead; validate against deployment baselines before escalating as compromise")
		}
	} else {
		r.PossibleCompromiseStatus = "NO_MATCHES_IN_SCOPE"
		r.AddAction("Usable process/webroot evidence was assessed with no compromise patterns in scope — completed no-match for those sources (not unavailable evidence) and not a host clearance. Expand retention and correlate WAF/log/EDR sources.")
		r.AddWarning("Possible-compromise no-match does not rule out in-process code execution without a suspicious child process")
	}

	// WAF coverage check (attempt axis only — never flips possible-compromise alone).
	if !hasWAFInputs {
		r.AddCheck("waf_log_investigation", "NOT_REQUESTED",
			"No offline WAF event export supplied")
	} else if usableWAF == 0 {
		r.AddCheck("waf_log_investigation", "INCOMPLETE",
			"WAF logs were requested but no usable events were parsed (unavailable/incomplete — not absence of matches)")
		r.AddWarning("WAF log review incomplete; do not treat as a negative exploitation-attempt finding")
	} else if len(inScopeWAF) > 0 {
		r.AddCheck("waf_log_investigation", coverage,
			fmt.Sprintf("Parsed offline WAF events with %d research-backed lead(s) in window. "+
				"Blocked/challenged actions are NOT successful exploitation. WAF alone does not set possible-compromise.",
				len(inScopeWAF)))
	} else {
		r.AddCheck("waf_log_investigation", coverage,
			"Offline WAF events reviewed in scope with no allowlisted PHP2Shell rule or upload-progress indicators; not a clearance")
	}

	if procCorr > 0 || webCorr > 0 || wafCorr > 0 {
		r.AddAction("Review temporally proximate WAF, process, webroot, and log leads together; proximity is not causation and is not same-worker identity")
	}

	r.AddCheck("compromise_investigation", coverage, fmt.Sprintf(
		"%s Findings: %d investigation lead(s). ExploitationAttempt=%s PossibleCompromise=%s (independent). "+
			"Long request-target length ≠ large HTTP body ≠ unusual form-field names ≠ multipart nesting. "+
			"A single memory error, crash, long request-target, child process, or PHP-like file never implies confirmed compromise. "+
			"Successful exploitation may leave no crash and no suspicious child. "+
			"Correlation is temporal proximity only (not same-worker identity). Filesystem mtime is not creation evidence.",
		coverageDetail, len(r.InvestigationFindings),
		r.ExploitationAttemptStatus, r.PossibleCompromiseStatus,
	))
}

// emitInvestigationP0Context records SAPI-aware narrative and HTTP body/form metadata limits.
func emitInvestigationP0Context(r *Report) {
	sapi := ClassifyConfiguredSAPIContext(r)
	r.AddCheck("sapi_investigation_context", "HINTS_ONLY_ACTIVE_RUNTIME_UNVERIFIED", sapi.Detail)
	r.AddCheck("http_request_body_form_metadata", "UNAVAILABLE",
		"HTTP request-body bytes, form-field names/lengths, multipart nesting depth, empty filename=\"\" parts, and Content-Length vs consumed-body mismatches are NOT available from ordinary Combined/IIS access logs. "+
			"The access-log long-POST heuristic measures request-target (URI path/query) length only. "+
			"Do not treat a long or short request-target as evidence of large bodies, unusual field names, or multipart structure. "+
			"Prefer offline WAF/proxy exports that document those fields when investigating Calif-style producers.")
	r.AddWarning("Configured PHP SAPI hints are not proof of the active HTTP-serving runtime; do not infer safety from PHP-FPM vs mod_php inventory differences alone")
}

func formatEvidenceSourceAvailability(
	hasAccess bool, usableAccess, unusableAccess int,
	hasError bool, usableError, unusableError int,
	hasProc bool, usableProc, unusableProc int,
	hasWeb bool, usableWeb, unusableWeb int,
	hasWAF bool, usableWAF, unusableWAF int,
) string {
	describe := func(label string, requested bool, usable, unusable int) string {
		if !requested {
			return label + "=NOT_REQUESTED"
		}
		if usable == 0 && unusable > 0 {
			return fmt.Sprintf("%s=REQUESTED_UNAVAILABLE (usable=0 unusable=%d)", label, unusable)
		}
		if usable == 0 && unusable == 0 {
			return label + "=REQUESTED_EMPTY"
		}
		if unusable > 0 {
			return fmt.Sprintf("%s=REQUESTED_PARTIAL (usable=%d unusable=%d)", label, usable, unusable)
		}
		return fmt.Sprintf("%s=REQUESTED_USABLE (usable=%d)", label, usable)
	}
	return strings.Join([]string{
		describe("access_logs", hasAccess, usableAccess, unusableAccess),
		describe("error_logs", hasError, usableError, unusableError),
		describe("process_telemetry", hasProc, usableProc, unusableProc),
		describe("webroot", hasWeb, usableWeb, unusableWeb),
		describe("waf_logs", hasWAF, usableWAF, unusableWAF),
		"Distinguish REQUESTED_UNAVAILABLE from completed assessments with NO_MATCHES_IN_SCOPE on usable sources.",
	}, "; ")
}

// correlateWebroot emits unconfirmed temporal links only when an OS birth/creation
// timestamp is available. mtime proximity alone never creates correlation and never
// elevates confidence — mtime is not creation or execution time.
func correlateWebroot(r *Report, webs []WebrootLead, errors, access []InvestigationEvent, procs []ProcessLead) int {
	corr := 0
	for _, w := range webs {
		if !w.BirthAvailable || w.BirthUTC.IsZero() {
			continue // refuse mtime-only temporal correlation
		}
		wt := w.BirthUTC.UTC()
		for _, ev := range errors {
			if ev.Time.IsZero() || (ev.Kind != "php_oom_unknown_line0" && ev.Kind != "apache_child_segfault") {
				continue
			}
			delta := wt.Sub(ev.Time)
			if delta < 0 {
				delta = -delta
			}
			if delta <= correlationWindow {
				corr++
				appendInvestigationFinding(r, InvestigationFinding{
					ID:           fmt.Sprintf("corr-fs-err-%s-%d", w.DedupKey, ev.Line),
					Class:        "correlation",
					Kind:         "correlated_webroot_and_error",
					Confidence:   "unconfirmed",
					Source:       "php2shell birth-timestamp proximity (±15m); not causality; mtime unused",
					Location:     w.Path + " + " + ev.Location,
					TimestampUTC: wt.Format(time.RFC3339),
					Detail: fmt.Sprintf(
						"Birth-timestamp proximity only (Δ=%s ≤ 15m), not causality. mtime was not used for correlation. "+
							"Contributing evidence: webroot lead %s (birth=%s) and error-log %s line %d. "+
							"Does not confirm successful exploitation or webshell; confidence remains unconfirmed.",
						delta.Round(time.Second), w.Kind, wt.Format(time.RFC3339), ev.Kind, ev.Line,
					),
				})
				if corr >= 20 {
					return corr
				}
			}
		}
		for _, ev := range access {
			if ev.Time.IsZero() || ev.Kind != "access_long_post_target" {
				continue
			}
			delta := wt.Sub(ev.Time)
			if delta < 0 {
				delta = -delta
			}
			if delta <= correlationWindow {
				corr++
				appendInvestigationFinding(r, InvestigationFinding{
					ID:           fmt.Sprintf("corr-fs-acc-%s-%d", w.DedupKey, ev.Line),
					Class:        "correlation",
					Kind:         "correlated_webroot_and_access",
					Confidence:   "unconfirmed",
					Source:       "php2shell birth-timestamp proximity (±15m); not causality; mtime unused",
					Location:     w.Path + " + " + ev.Location,
					TimestampUTC: wt.Format(time.RFC3339),
					Detail: fmt.Sprintf(
						"Birth-timestamp proximity only (Δ=%s ≤ 15m), not causality. mtime was not used for correlation. "+
							"Contributing evidence: webroot lead %s and access-log %s line %d. "+
							"Does not confirm successful exploitation or webshell; confidence remains unconfirmed.",
						delta.Round(time.Second), w.Kind, ev.Kind, ev.Line,
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
			delta := wt.Sub(p.Event.TimeUTC)
			if delta < 0 {
				delta = -delta
			}
			if delta <= correlationWindow {
				corr++
				appendInvestigationFinding(r, InvestigationFinding{
					ID:           fmt.Sprintf("corr-fs-proc-%s-%s", w.DedupKey, p.DedupKey),
					Class:        "correlation",
					Kind:         "correlated_webroot_and_process",
					Confidence:   "unconfirmed",
					Source:       "php2shell birth-timestamp proximity (±15m); not causality; mtime unused",
					Location:     w.Path + " + " + p.Event.SourceFile,
					TimestampUTC: wt.Format(time.RFC3339),
					Detail: fmt.Sprintf(
						"Birth-timestamp proximity only (Δ=%s ≤ 15m), not causality. mtime was not used for correlation. "+
							"Contributing evidence: webroot lead %s and process lead %s (entity=%s). "+
							"Does not confirm successful exploitation or webshell; confidence remains unconfirmed.",
						delta.Round(time.Second), w.Kind, p.Kind, nullDash(p.Event.ProcessEntityID),
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

func findingFromLogEvent(prefix string, ev InvestigationEvent) InvestigationFinding {
	ts := ""
	if !ev.Time.IsZero() {
		ts = ev.Time.UTC().Format(time.RFC3339)
	}
	return InvestigationFinding{
		ID:           fmt.Sprintf("%s-%s-%d", prefix, ev.Kind, ev.Line),
		Class:        ev.Class,
		Kind:         ev.Kind,
		Confidence:   ev.Confidence,
		Source:       ev.Source,
		Location:     ev.Location,
		TimestampUTC: ts,
		Detail:       ev.Detail,
	}
}

func correlateAccessError(r *Report, inScopeError, inScopeAccess []InvestigationEvent) int {
	corr := 0
	for _, errEv := range inScopeError {
		if errEv.Kind != "php_oom_unknown_line0" && errEv.Kind != "apache_child_segfault" {
			continue
		}
		if errEv.Time.IsZero() {
			continue
		}
		for _, accEv := range inScopeAccess {
			if accEv.Kind != "access_long_post_target" || accEv.Time.IsZero() {
				continue
			}
			delta := errEv.Time.Sub(accEv.Time)
			if delta < 0 {
				delta = -delta
			}
			if delta <= correlationWindow {
				corr++
				appendInvestigationFinding(r, InvestigationFinding{
					ID:           fmt.Sprintf("corr-%d-%d", errEv.Line, accEv.Line),
					Class:        "correlation",
					Kind:         "correlated_attempt_signals",
					Confidence:   "unconfirmed",
					Source:       "php2shell temporal proximity (±15m); not causality; not a confirmed PHP2Shell attribution",
					Location:     errEv.Location + " + " + accEv.Location,
					TimestampUTC: errEv.Time.UTC().Format(time.RFC3339),
					Detail: fmt.Sprintf(
						"Temporal proximity only (Δ=%s ≤ 15m), not causality. Contributing evidence: "+
							"error-log %s at line %d (%s) and access-log %s at line %d (%s; request-target length heuristic, not body size). "+
							"Independent sources; two generic errors alone are not correlated. "+
							"Does not mean confirmed exploitation or host compromise — analyst review required.",
						delta.Round(time.Second),
						errEv.Kind, errEv.Line, errEv.Time.UTC().Format(time.RFC3339),
						accEv.Kind, accEv.Line, accEv.Time.UTC().Format(time.RFC3339),
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

func countLogUsable(logs []LogCoverage) (usable, unusable int) {
	for _, lg := range logs {
		switch strings.ToUpper(lg.Status) {
		case "UNAVAILABLE", "INCOMPLETE":
			unusable++
		default:
			usable++
		}
	}
	return
}

func countErrorLogUsable(logs []ErrorLogCoverage) (usable, unusable int) {
	for _, lg := range logs {
		switch strings.ToUpper(lg.Status) {
		case "UNAVAILABLE", "INCOMPLETE":
			unusable++
		default:
			usable++
		}
	}
	return
}

func countProcessTelemetryUsable(items []ProcessTelemetryCoverage) (usable, unusable int) {
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

func humanExploitationAttempt(status string) string {
	switch status {
	case "SUSPECTED_ATTEMPTS_REVIEW":
		return "Suspected exploitation attempts — review required"
	case "NO_MATCHES_IN_SCOPE":
		return "No attempt patterns in assessed scope (not a clearance)"
	case "NOT_ASSESSED":
		return "Not assessed"
	default:
		if status == "" {
			return "Not assessed"
		}
		return status
	}
}

func humanPossibleCompromise(status string) string {
	switch status {
	case "POSSIBLE_COMPROMISE_REVIEW":
		return "Possible compromise indicators — review required"
	case "NO_MATCHES_IN_SCOPE":
		return "No compromise patterns in assessed scope (not a clearance)"
	case "NOT_ASSESSED":
		return "Not assessed"
	default:
		if status == "" {
			return "Not assessed"
		}
		return status
	}
}

// humanPossibleCompromiseDetail clarifies evidence strength for the HTML card.
func humanPossibleCompromiseDetail(r *Report) string {
	if possibleCompromiseIsWebrootMetadataOnly(r) {
		return "LOW-CONFIDENCE investigative lead from webroot metadata only (not EDR-strength evidence). " +
			"Not confirmed webshell activity or successful exploitation — analyst validation required. " +
			"mtime is never treated as creation or execution time."
	}
	return "Independent of attempt status. Assessed from offline process/EDR telemetry and/or authorized webroot metadata; never auto-confirmed."
}

func humanInvestigationCoverage(status string) string {
	switch status {
	case "NOT_REQUESTED":
		return "Not requested"
	case "ASSESSED_SCOPE_LIMITED":
		return "Assessed usable sources (scope limited; continuity not proven)"
	case "PARTIAL_TIMESTAMP_UNCERTAIN":
		return "Partial (timestamp uncertainty on usable sources)"
	case "INCOMPLETE":
		return "Incomplete — one or more requested sources unavailable"
	default:
		if status == "" {
			return "Not requested"
		}
		return status
	}
}

func humanExploitationAttemptDetail(r *Report) string {
	base := "Suspected attempt leads need analyst review. " +
		"Long request-target ≠ large body ≠ unusual form-field names ≠ multipart nesting. " +
		"A single memory error, crash, or WAF block is not successful exploitation. " +
		"Successful in-process exploitation may leave no crash and no suspicious child process."
	switch r.ExploitationAttemptStatus {
	case "NO_MATCHES_IN_SCOPE":
		return "Completed assessment of usable attempt evidence found no matches in scope — not the same as unavailable evidence, and not a clearance. " + base
	case "NOT_ASSESSED":
		return "Attempt status not assessed (inputs absent or unavailable). Unavailable evidence is not a no-match result. " + base
	default:
		return base
	}
}
