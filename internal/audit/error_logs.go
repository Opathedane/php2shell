package audit

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Research-backed pattern sources (citations appear on findings; no PoC payloads).
const (
	srcDatadogOOM = "Datadog Security Labs PHP2Shell analysis (2026-10-21): PHP Fatal memory exhausted in Unknown on line 0 — correlate; memory exhaustion alone is not proof of attack"
	srcDatadogSF  = "Datadog Security Labs PHP2Shell analysis (2026-10-21): Apache AH00052 child Segmentation fault may indicate failed exploit attempts; successful exploits may not crash"
	srcAWSReview  = "AWS Security Blog PHP2Shell MadPot (2026-10-21): review web server logs for suspicious activity; investigate from at least 2026-10-17"
)

var (
	// PHP bracketed log timestamp: [21-Oct-2026 14:05:01 UTC] or [21-Oct-2026 14:05:01 Europe/Berlin]
	phpErrorTime = regexp.MustCompile(`^\[([0-9]{2}-[A-Za-z]{3}-[0-9]{4}\s+[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\s+[^\]]+)?\]\s*(.*)$`)
	// Apache error log: [Wed Oct 21 14:05:01.123456 2026] ...
	apacheErrorTime = regexp.MustCompile(`^\[([A-Za-z]{3}\s+[A-Za-z]{3}\s+[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?\s+[0-9]{4})\]\s*(.*)$`)

	phpOOMUnknown = regexp.MustCompile(`(?i)Allowed memory size of [0-9]+ bytes exhausted.*in Unknown on line 0`)
	apacheSegfault = regexp.MustCompile(`(?i)AH00052:\s*child pid\s+[0-9]+\s+exit signal Segmentation fault`)
	apacheSegfaultLoose = regexp.MustCompile(`(?i)exit signal Segmentation fault\s*\(\s*11\s*\)`)
)

// ScanErrorLog reviews one PHP/Apache error log for research-backed patterns.
// Returns timed investigation events (may be empty). Never stores raw sensitive line text.
func ScanErrorLog(r *Report, path string) []InvestigationEvent {
	item := ErrorLogCoverage{File: path, Status: "NOT_ASSESSED"}
	b, err := ReadRegular(path, 32<<20)
	if err != nil {
		item.Status = "UNAVAILABLE"
		item.Detail = "File inaccessible, nonregular, or over 32 MiB: " + err.Error()
		r.ErrorLogs = append(r.ErrorLogs, item)
		r.AddWarning("Error log not reviewed: " + path)
		return nil
	}

	var events []InvestigationEvent
	var first, last time.Time
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	parseFailures := 0

	for scanner.Scan() {
		item.Lines++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		t, rest, ok := parseErrorLogLine(line)
		if !ok {
			// Still scan whole line for patterns when timestamp layout is unknown.
			rest = line
			parseFailures++
		} else {
			item.ParsedEvents++
			if !t.IsZero() {
				if first.IsZero() || t.Before(first) {
					first = t
				}
				if last.IsZero() || t.After(last) {
					last = t
				}
			}
		}

		if phpOOMUnknown.MatchString(rest) || phpOOMUnknown.MatchString(line) {
			item.MatchedPatterns++
			events = append(events, InvestigationEvent{
				Kind:       "php_oom_unknown_line0",
				Class:      "verified_public_pattern",
				Confidence: "suspected",
				Source:     srcDatadogOOM,
				Location:   path,
				Time:       t,
				Line:       item.Lines,
				Detail: fmt.Sprintf(
					"PHP memory-exhaustion fatal during request initialization (Unknown on line 0) at log line %d. "+
						"Legitimate workload can also exhaust memory; not proof of exploitation or compromise.",
					item.Lines,
				),
			})
		}
		if apacheSegfault.MatchString(rest) || apacheSegfault.MatchString(line) ||
			apacheSegfaultLoose.MatchString(rest) || apacheSegfaultLoose.MatchString(line) {
			item.MatchedPatterns++
			events = append(events, InvestigationEvent{
				Kind:       "apache_child_segfault",
				Class:      "verified_public_pattern",
				Confidence: "suspected",
				Source:     srcDatadogSF + "; " + srcAWSReview,
				Location:   path,
				Time:       t,
				Line:       item.Lines,
				Detail: fmt.Sprintf(
					"Apache child segmentation fault (AH00052 or equivalent) at log line %d. "+
						"May indicate a failed attempt; successful exploitation may leave no crash. Not proof of compromise.",
					item.Lines,
				),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		item.Status = "INCOMPLETE"
		item.Detail = "Overlong or unreadable error-log line; remaining content not fully assessed"
	} else {
		item.Status = "PATTERNS_REVIEWED_COVERAGE_LIMITED"
		item.Detail = "Research-backed PHP/Apache error patterns only. First/last timestamps do not prove continuous coverage. " +
			srcAWSReview
		if parseFailures > 0 && item.ParsedEvents == 0 {
			item.Detail += fmt.Sprintf(" Timestamp parse uncertain on many lines (%d); pattern scan still applied.", parseFailures)
		}
	}
	if !first.IsZero() {
		item.FirstTimestamp = first.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		item.LastTimestamp = last.UTC().Format(time.RFC3339)
	}
	r.ErrorLogs = append(r.ErrorLogs, item)
	return events
}

func parseErrorLogLine(line string) (t time.Time, rest string, ok bool) {
	if m := phpErrorTime.FindStringSubmatch(line); len(m) == 3 {
		// Treat clock as UTC when zone label is present but ambiguous (e.g. "UTC" or named zone).
		raw := strings.TrimSpace(m[1])
		if ts, err := time.Parse("02-Jan-2006 15:04:05", raw); err == nil {
			return ts.UTC(), m[2], true
		}
		return time.Time{}, m[2], true // body ok; time uncertain
	}
	if m := apacheErrorTime.FindStringSubmatch(line); len(m) == 3 {
		raw := strings.TrimSpace(m[1])
		layouts := []string{
			"Mon Jan 2 15:04:05.000000 2006",
			"Mon Jan 2 15:04:05 2006",
			"Mon Jan 02 15:04:05.000000 2006",
			"Mon Jan 02 15:04:05 2006",
		}
		for _, layout := range layouts {
			if ts, err := time.Parse(layout, raw); err == nil {
				return ts.UTC(), m[2], true
			}
		}
		return time.Time{}, m[2], true
	}
	return time.Time{}, "", false
}
