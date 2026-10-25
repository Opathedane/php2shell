package audit

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Opathedane/php2shell/internal/rules"
)

// Request-target capture stays bounded for normal parsing; long-POST heuristics use
// inspectLongPOSTTarget so oversized lines are still detected without retaining body text.
var accessLine = regexp.MustCompile(`"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+([^"\r\n]{0,1000})\s+HTTP/[0-9.]+"\s+([0-9]{3})`)
var accessTime = regexp.MustCompile(`\[([0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}\s+[+-][0-9]{4})\]`)

const srcAccessLongPOST = "Heuristic only: POST request-target (URI path/stem+query) length in the access-log line. " +
	"Distinct from: (1) large HTTP request-body size, (2) unusual form-field name length, (3) multipart nesting / empty filename parts. " +
	"Ordinary Combined/IIS W3C access logs do not expose body bytes or form-field metadata — those require WAF/proxy exports. " +
	"Weak alone — not proof of exploitation"

const srcAccessPOST5xx = "ReliaQuest Threat Spotlight PHP2Shell (2026-10-22): POST returning 5xx may accompany failed exploit attempts. " +
	"Correlation-only signal (not a standalone lead); ordinary application errors also return 5xx. No request body retained"

func ScanAccessLog(r *Report, path string) {
	ScanAccessLogWithIndicators(r, path, nil)
}

func ScanAccessLogWithIndicators(r *Report, path string, indicators []rules.Indicator) {
	_, _ = ScanAccessLogCollect(r, path, indicators)
}

// ScanAccessLogCollect summarizes an access log, applies signed IOC literals, and
// optionally returns heuristic investigation events (long POST targets). Request
// text and query strings are never retained in findings.
func ScanAccessLogCollect(r *Report, path string, indicators []rules.Indicator) (anomalies []InvestigationEvent, _ error) {
	item := LogCoverage{File: path, Status: "NOT_ASSESSED", Methods: map[string]int{}, StatusClasses: map[string]int{}}
	b, err := ReadRegular(path, 32<<20)
	if err != nil {
		item.Status = "UNAVAILABLE"
		item.Detail = "File inaccessible, nonregular, or over 32 MiB: " + err.Error()
		r.Logs = append(r.Logs, item)
		r.AddWarning("Access log not reviewed: " + path)
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	var first, last time.Time
	var iisFields map[string]int
	iisDetected := false
	post5xxKept := 0
	for scanner.Scan() {
		item.Lines++
		line := scanner.Text()
		if strings.HasPrefix(line, "#Fields:") {
			iisFields = map[string]int{}
			for i, n := range strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#Fields:"))) {
				iisFields[n] = i
			}
			if _, ok := iisFields["cs-method"]; ok {
				iisDetected = true
			}
			continue
		}
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		var target, method, status string
		var t time.Time
		if iisDetected && iisFields != nil {
			fields := strings.Fields(line)
			field := func(name string) string {
				i, ok := iisFields[name]
				if ok && i < len(fields) {
					return fields[i]
				}
				return ""
			}
			method, status = field("cs-method"), field("sc-status")
			stem := field("cs-uri-stem")
			query := field("cs-uri-query")
			target = stem
			if query != "" && query != "-" {
				target += "?" + query
			}
			dt := field("date") + " " + field("time")
			t, _ = time.Parse("2006-01-02 15:04:05", dt) // W3C timestamps are UTC
		} else if m := accessLine.FindStringSubmatch(line); len(m) == 4 {
			method, target, status = m[1], m[2], m[3]
			if m := accessTime.FindStringSubmatch(line); len(m) > 1 {
				t, _ = time.Parse("02/Jan/2006:15:04:05 -0700", strings.TrimSpace(m[1]))
			}
		}
		if method != "" && target != "" {
			item.ParsedRequests++
			item.Methods[method]++
			n, e := strconv.Atoi(status)
			if e == nil && n >= 100 && n <= 599 {
				item.StatusClasses[fmt.Sprintf("%dxx", n/100)]++
			}
			if len(indicators) > 0 && len(r.Findings) < 200 {
				low := strings.ToLower(target)
				for _, ind := range indicators {
					if ind.Type != "http_target_literal" {
						continue
					}
					if strings.Contains(low, strings.ToLower(ind.Value)) {
						r.Findings = append(r.Findings, IndicatorFinding{RuleID: ind.ID, Type: ind.Type, Severity: ind.Severity, Confidence: ind.Confidence, Source: ind.Source, Location: path, Detail: fmt.Sprintf("Matched HTTP request target at log line %d; request text deliberately not retained", item.Lines)})
						item.MatchedRules++
						if len(r.Findings) >= 200 {
							r.AddWarning("Indicator findings limited to 200 matches")
							break
						}
					}
				}
			}
		}
		// Long POST targets may exceed the normal request-target capture; probe raw line.
		if inspectLongPOSTTarget(line) {
			if t.IsZero() {
				if m := accessTime.FindStringSubmatch(line); len(m) > 1 {
					t, _ = time.Parse("02/Jan/2006:15:04:05 -0700", strings.TrimSpace(m[1]))
				}
			}
			item.AnomalyCount++
			anomalies = append(anomalies, InvestigationEvent{
				Kind:       "access_long_post_target",
				Class:      "heuristic",
				Confidence: "unconfirmed",
				Source:     srcAccessLongPOST,
				Location:   path,
				Time:       t,
				Line:       item.Lines,
				Detail: fmt.Sprintf(
					"POST request-target (URI path/query as logged) length ≥ %d characters at access-log line %d "+
						"(target text not retained). Measures request-target length ONLY — not HTTP body size, not form-field name length, "+
						"and not multipart nesting/empty-filename structure (Calif-style producers). "+
						"Ordinary access logs lack those fields; prefer offline WAF metadata when available. "+
						"Weak heuristic (confidence=unconfirmed); not proof of exploitation or compromise.",
					longPOSTTargetRunes, item.Lines,
				),
			})
		}
		// POST + 5xx: correlation-only (FinalizeInvestigation does not emit as standalone lead).
		// Cap retained events so large 5xx floods cannot exhaust memory before correlation.
		if strings.EqualFold(method, "POST") && len(status) == 3 && status[0] == '5' && post5xxKept < 200 {
			if t.IsZero() {
				if m := accessTime.FindStringSubmatch(line); len(m) > 1 {
					t, _ = time.Parse("02/Jan/2006:15:04:05 -0700", strings.TrimSpace(m[1]))
				}
			}
			post5xxKept++
			anomalies = append(anomalies, InvestigationEvent{
				Kind:       "access_post_server_error",
				Class:      "heuristic",
				Confidence: "unconfirmed",
				Source:     srcAccessPOST5xx,
				Location:   path,
				Time:       t,
				Line:       item.Lines,
				Detail: fmt.Sprintf(
					"POST with HTTP %s at access-log line %d (status only; request-target/body not retained). "+
						"Correlation-only assist for ReliaQuest-style sequences; ordinary application failures also return 5xx. "+
						"Not a standalone exploitation lead.",
					status, item.Lines,
				),
			})
		}
		if !t.IsZero() {
			if first.IsZero() || t.Before(first) {
				first = t
			}
			if last.IsZero() || t.After(last) {
				last = t
			}
		}
	}
	if err := scanner.Err(); err != nil {
		item.Status = "INCOMPLETE"
		item.Detail = "Overlong or unreadable log line"
	} else if len(indicators) == 0 {
		item.Status = "SUMMARIZED_NO_IOCS"
		item.Detail = "Request count/time coverage only; no approved indicators loaded. " +
			"First/last timestamps do not prove continuous coverage across rotations or gaps."
	} else {
		item.Status = "RULES_APPLIED_COVERAGE_LIMITED"
		item.Detail = "Matching rule literals only; no guarantee of detecting PHP2Shell activity. " +
			"First/last timestamps do not prove continuous coverage across rotations or gaps."
	}
	if item.AnomalyCount > 0 {
		item.Detail += fmt.Sprintf(" Heuristic long request-target anomalies: %d (URI length only; body size unknown; weak leads).", item.AnomalyCount)
	}
	if !first.IsZero() {
		item.FirstTimestamp = first.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		item.LastTimestamp = last.UTC().Format(time.RFC3339)
	}
	r.Logs = append(r.Logs, item)
	return anomalies, nil
}

func inspectLongPOSTTarget(line string) bool {
	const prefix = `"POST `
	i := strings.Index(line, prefix)
	if i < 0 {
		return false
	}
	rest := line[i+len(prefix):]
	end := strings.Index(rest, ` HTTP/`)
	if end < 0 {
		// Truncated or nonstandard line — count what is present without retaining it.
		return utf8.RuneCountInString(rest) >= longPOSTTargetRunes
	}
	return utf8.RuneCountInString(rest[:end]) >= longPOSTTargetRunes
}
