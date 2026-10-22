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
	longPOSTTargetRunes     = 2048
	correlationWindow       = 15 * time.Minute
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

// InvestigationOptions configures Phase A/B offline investigation.
type InvestigationOptions struct {
	// From/To are UTC bounds. Zero From defaults to SuggestedInvestigateFromUTC when assessing.
	// Zero To defaults to report GeneratedUTC.
	From time.Time
	To   time.Time
	// Assessing is true when the operator supplied investigation inputs (--access-log and/or --error-log).
	Assessing bool
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
		Note: "Earliest/latest timestamps in supplied logs do not prove continuous coverage. " +
			"Rotation gaps, missing intervals, parser failures, timezone ambiguity, and inaccessible sources may hide activity. " +
			"Analysts may set --investigate-from earlier than 2026-10-17 when retained records exist.",
	}
	return from, to, win
}

func inInvestigationWindow(t, from, to time.Time) bool {
	if t.IsZero() {
		// Untimed events count as in-scope but mark coverage incomplete separately.
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
// and investigation-coverage statuses. Possible compromise stays NOT_ASSESSED in
// Phases A/B (no offline process/EDR telemetry yet).
func FinalizeInvestigation(r *Report, opts InvestigationOptions, accessEvents, errorEvents []InvestigationEvent) {
	if r == nil {
		return
	}
	if !opts.Assessing {
		r.ExploitationAttemptStatus = "NOT_ASSESSED"
		r.PossibleCompromiseStatus = "NOT_ASSESSED"
		r.InvestigationCoverage = "NOT_REQUESTED"
		r.InvestigationWindow = nil
		r.AddCheck("compromise_investigation", "NOT_REQUESTED",
			"No --access-log or --error-log supplied; exploitation-attempt and possible-compromise statuses remain NOT_ASSESSED (not a negative finding)")
		r.AddCheck("process_telemetry_investigation", "NOT_REQUESTED",
			"Offline EDR/process telemetry ingestion is not enabled in this phase; possible-compromise stays NOT_ASSESSED")
		return
	}

	from, to, win := ResolveInvestigationWindow(opts, r.GeneratedUTC)
	r.InvestigationWindow = &win

	// Possible compromise: not assessed until process/EDR telemetry (Phase D).
	r.PossibleCompromiseStatus = "NOT_ASSESSED"
	r.AddCheck("process_telemetry_investigation", "NOT_REQUESTED",
		"No offline process/EDR telemetry files supplied; possible host compromise is NOT_ASSESSED (not cleared)")

	usableAccess, unusableAccess := 0, 0
	for _, lg := range r.Logs {
		switch strings.ToUpper(lg.Status) {
		case "UNAVAILABLE", "INCOMPLETE":
			unusableAccess++
		default:
			usableAccess++
		}
	}
	usableError, unusableError := 0, 0
	for _, lg := range r.ErrorLogs {
		switch strings.ToUpper(lg.Status) {
		case "UNAVAILABLE", "INCOMPLETE":
			unusableError++
		default:
			usableError++
		}
	}

	coverage := "ASSESSED_SCOPE_LIMITED"
	coverageDetail := "Investigation inputs were reviewed inside the selected UTC window. " +
		"First/last log timestamps do not prove continuous coverage; rotation gaps and missing sources cannot be ruled out."
	if usableAccess+usableError == 0 {
		r.InvestigationCoverage = "INCOMPLETE"
		r.ExploitationAttemptStatus = "NOT_ASSESSED"
		r.AddCheck("compromise_investigation", "INCOMPLETE",
			"Investigation was requested but no usable access/error log could be parsed; exploitation attempts remain NOT_ASSESSED (incomplete evidence, not absence of matches)")
		r.AddWarning("Investigation coverage incomplete: supplied logs were inaccessible, oversized, or unreadable")
		return
	}
	if unusableAccess+unusableError > 0 {
		coverage = "INCOMPLETE"
		coverageDetail = "At least one requested log was unavailable or incompletely parsed. " +
			"Do not treat missing matches as proof of safety; gaps cannot be ruled out from first/last timestamps alone."
	}

	// Filter events to window; untimed events remain candidates but flag uncertainty.
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
	if timedUnknown {
		if coverage != "INCOMPLETE" {
			coverage = "PARTIAL_TIMESTAMP_UNCERTAIN"
		}
		coverageDetail += " Some matched lines lacked reliable timestamps (timezone/format uncertainty)."
	}

	// Emit findings for in-scope events (never escalate possible-compromise here).
	attemptHits := 0
	for _, ev := range inScopeError {
		attemptHits++
		ts := ""
		if !ev.Time.IsZero() {
			ts = ev.Time.UTC().Format(time.RFC3339)
		}
		appendInvestigationFinding(r, InvestigationFinding{
			ID:           fmt.Sprintf("err-%s-%d", ev.Kind, ev.Line),
			Class:        ev.Class,
			Kind:         ev.Kind,
			Confidence:   ev.Confidence,
			Source:       ev.Source,
			Location:     ev.Location,
			TimestampUTC: ts,
			Detail:       ev.Detail,
		})
	}
	for _, ev := range inScopeAccess {
		attemptHits++
		ts := ""
		if !ev.Time.IsZero() {
			ts = ev.Time.UTC().Format(time.RFC3339)
		}
		appendInvestigationFinding(r, InvestigationFinding{
			ID:           fmt.Sprintf("acc-%s-%d", ev.Kind, ev.Line),
			Class:        ev.Class,
			Kind:         ev.Kind,
			Confidence:   ev.Confidence,
			Source:       ev.Source,
			Location:     ev.Location,
			TimestampUTC: ts,
			Detail:       ev.Detail,
		})
	}

	// Bounded temporal proximity only (±15m). Requires reliable timestamps on both
	// sides; never implies causality, confirmed exploitation, or compromise.
	// Untimed / ambiguous-timestamp events are excluded from correlation.
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
					ID:         fmt.Sprintf("corr-%d-%d", errEv.Line, accEv.Line),
					Class:      "correlation",
					Kind:       "correlated_attempt_signals",
					Confidence: "unconfirmed", // temporal proximity of weak/heuristic leads — not corroborated attack proof
					Source:     "php2shell temporal proximity (±15m); not causality; not a confirmed PHP2Shell attribution",
					Location:   errEv.Location + " + " + accEv.Location,
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
					break
				}
			}
		}
		if corr >= 20 {
			break
		}
	}

	r.InvestigationCoverage = coverage
	if attemptHits > 0 || corr > 0 {
		r.ExploitationAttemptStatus = "SUSPECTED_ATTEMPTS_REVIEW"
		r.AddWarning("Suspected exploitation-attempt leads require analyst validation; they are not proof of successful exploitation or host compromise")
		r.AddAction("Preserve original access/error logs covering the investigation window (from at least 2026-10-17 when possible) and escalate suspected attempt leads for human review")
	} else {
		r.ExploitationAttemptStatus = "NO_MATCHES_IN_SCOPE"
		r.AddAction("No exploitation-attempt patterns matched in the assessed log scope; this is not a clearance — expand retention, error logs, and offline EDR/process review")
	}

	r.AddCheck("compromise_investigation", coverage, fmt.Sprintf(
		"%s Findings: %d investigation lead(s), %d correlation lead(s). ExploitationAttempt=%s PossibleCompromise=%s (independent). %s",
		coverageDetail, len(r.InvestigationFindings), corr,
		r.ExploitationAttemptStatus, r.PossibleCompromiseStatus,
		"A single memory error, worker crash, or long request-target never implies successful exploitation or compromise. Correlation is temporal proximity only.",
	))
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
