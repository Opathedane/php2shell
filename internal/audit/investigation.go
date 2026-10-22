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
	// (--access-log, --error-log, and/or --process-telemetry).
	Assessing bool
	// HasProcessTelemetry is true when at least one --process-telemetry file was requested.
	HasProcessTelemetry bool
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
// offline process telemetry was supplied. Never emits CONFIRMED_COMPROMISE or CLEAN.
func FinalizeInvestigation(r *Report, opts InvestigationOptions, accessEvents, errorEvents []InvestigationEvent, processLeads []ProcessLead) {
	if r == nil {
		return
	}
	if !opts.Assessing {
		r.ExploitationAttemptStatus = "NOT_ASSESSED"
		r.PossibleCompromiseStatus = "NOT_ASSESSED"
		r.InvestigationCoverage = "NOT_REQUESTED"
		r.InvestigationWindow = nil
		r.AddCheck("compromise_investigation", "NOT_REQUESTED",
			"No --access-log, --error-log, or --process-telemetry supplied; exploitation-attempt and possible-compromise statuses remain NOT_ASSESSED (not a negative finding)")
		r.AddCheck("process_telemetry_investigation", "NOT_REQUESTED",
			"No offline process/EDR telemetry supplied; possible-compromise stays NOT_ASSESSED")
		return
	}

	from, to, win := ResolveInvestigationWindow(opts, r.GeneratedUTC)
	r.InvestigationWindow = &win

	usableAccess, unusableAccess := countLogUsable(r.Logs)
	usableError, unusableError := countErrorLogUsable(r.ErrorLogs)
	usableProc, unusableProc := countProcessTelemetryUsable(r.ProcessTelemetry)

	hasLogInputs := usableAccess+unusableAccess+usableError+unusableError > 0
	hasProcInputs := opts.HasProcessTelemetry

	coverage := "ASSESSED_SCOPE_LIMITED"
	coverageDetail := "Investigation inputs were reviewed inside the selected UTC window. " +
		"First/last timestamps do not prove continuous coverage; rotation gaps and missing sources cannot be ruled out."

	// If every requested input class failed entirely, mark incomplete.
	logsAllFailed := hasLogInputs && usableAccess+usableError == 0
	procAllFailed := hasProcInputs && usableProc == 0 && unusableProc > 0
	if (hasLogInputs || hasProcInputs) && logsAllFailed && (procAllFailed || !hasProcInputs) && !(hasProcInputs && usableProc > 0) {
		if hasLogInputs && usableAccess+usableError == 0 && !hasProcInputs {
			r.InvestigationCoverage = "INCOMPLETE"
			r.ExploitationAttemptStatus = "NOT_ASSESSED"
			r.PossibleCompromiseStatus = "NOT_ASSESSED"
			r.AddCheck("compromise_investigation", "INCOMPLETE",
				"Investigation was requested but no usable access/error log could be parsed; statuses remain NOT_ASSESSED (incomplete evidence, not absence of matches)")
			r.AddCheck("process_telemetry_investigation", "NOT_REQUESTED",
				"No offline process/EDR telemetry supplied; possible-compromise stays NOT_ASSESSED")
			r.AddWarning("Investigation coverage incomplete: supplied logs were inaccessible, oversized, or unreadable")
			return
		}
	}
	if unusableAccess+unusableError+unusableProc > 0 {
		coverage = "INCOMPLETE"
		coverageDetail = "At least one requested log or telemetry file was unavailable, unsupported, or incompletely parsed. " +
			"Do not treat missing matches as proof of safety; gaps cannot be ruled out from first/last timestamps alone."
	}

	var timedUnknown bool
	var inScopeAccess, inScopeError []InvestigationEvent
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

	// --- Exploitation-attempt leads (access/error) ---
	attemptHits := 0
	if usableAccess+usableError > 0 || (hasLogInputs && usableAccess+usableError > 0) {
		for _, ev := range inScopeError {
			attemptHits++
			appendInvestigationFinding(r, findingFromLogEvent("err", ev))
		}
		for _, ev := range inScopeAccess {
			attemptHits++
			appendInvestigationFinding(r, findingFromLogEvent("acc", ev))
		}
	}

	corr := correlateAccessError(r, inScopeError, inScopeAccess)

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

	r.InvestigationCoverage = coverage

	// Exploitation attempts: only when access/error logs were part of the assessment.
	if hasLogInputs {
		if usableAccess+usableError == 0 {
			r.ExploitationAttemptStatus = "NOT_ASSESSED"
			r.AddWarning("Access/error logs were requested but not usable; exploitation-attempt status remains NOT_ASSESSED (incomplete, not negative)")
		} else if attemptHits > 0 || corr > 0 {
			r.ExploitationAttemptStatus = "SUSPECTED_ATTEMPTS_REVIEW"
			r.AddWarning("Suspected exploitation-attempt leads require analyst validation; they are not proof of successful exploitation or host compromise")
			r.AddAction("Preserve original access/error logs covering the investigation window (from at least 2026-10-17 when possible) and escalate suspected attempt leads for human review")
		} else {
			r.ExploitationAttemptStatus = "NO_MATCHES_IN_SCOPE"
			r.AddAction("No exploitation-attempt patterns matched in the assessed log scope; this is not a clearance — expand retention and offline EDR/process review")
		}
	} else {
		r.ExploitationAttemptStatus = "NOT_ASSESSED"
	}

	// Possible compromise: only when process telemetry was supplied.
	if !hasProcInputs {
		r.PossibleCompromiseStatus = "NOT_ASSESSED"
		r.AddCheck("process_telemetry_investigation", "NOT_REQUESTED",
			"No offline process/EDR telemetry supplied; possible-compromise stays NOT_ASSESSED (not cleared)")
	} else if usableProc == 0 {
		r.PossibleCompromiseStatus = "NOT_ASSESSED"
		r.AddCheck("process_telemetry_investigation", "INCOMPLETE",
			"Process telemetry was requested but no usable events were parsed; possible-compromise remains NOT_ASSESSED (incomplete evidence, not absence of matches)")
		r.AddWarning("Process telemetry incomplete or unsupported; do not treat as a negative compromise finding")
	} else if len(inScopeProc) > 0 {
		r.PossibleCompromiseStatus = "POSSIBLE_COMPROMISE_REVIEW"
		r.AddCheck("process_telemetry_investigation", coverage,
			fmt.Sprintf("Parsed process telemetry with %d suspicious parent→child lead(s) in window (behavioral convergent; not confirmed compromise). Command lines redacted to classification tokens.", len(inScopeProc)))
		r.AddWarning("Possible compromise leads require analyst validation against host baselines; normal apps may launch shells/interpreters")
		r.AddAction("Validate suspicious web/PHP worker child processes with original EDR/Sysmon/audit records; do not treat POSSIBLE_COMPROMISE_REVIEW as confirmed compromise")
	} else {
		r.PossibleCompromiseStatus = "NO_MATCHES_IN_SCOPE"
		r.AddCheck("process_telemetry_investigation", coverage,
			"Process telemetry reviewed in scope with no web/PHP→suspicious-child leads; not a host clearance (coverage limited; missed parents/PID reuse possible)")
		r.AddAction("No suspicious process relationships matched in assessed telemetry scope; this is not a clearance — expand retention and correlate with access/error evidence")
	}

	if procCorr > 0 {
		r.AddAction("Review temporally proximate process and log leads together; proximity is not causation")
	}

	r.AddCheck("compromise_investigation", coverage, fmt.Sprintf(
		"%s Findings: %d investigation lead(s). ExploitationAttempt=%s PossibleCompromise=%s (independent). "+
			"A single memory error, crash, long request-target, or child process never implies confirmed compromise. Correlation is temporal proximity only.",
		coverageDetail, len(r.InvestigationFindings),
		r.ExploitationAttemptStatus, r.PossibleCompromiseStatus,
	))
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

func humanInvestigationCoverage(status string) string {
	switch status {
	case "NOT_REQUESTED":
		return "Not requested"
	case "ASSESSED_SCOPE_LIMITED":
		return "Assessed (scope limited; continuity not proven)"
	case "PARTIAL_TIMESTAMP_UNCERTAIN":
		return "Partial (timestamp uncertainty)"
	case "INCOMPLETE":
		return "Incomplete"
	default:
		if status == "" {
			return "Not requested"
		}
		return status
	}
}
