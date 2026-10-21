package audit

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Opathedane/php2shell/internal/rules"
)

var accessLine = regexp.MustCompile(`"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+([^"\r\n]{0,1000})\s+HTTP/[0-9.]+"\s+([0-9]{3})`)
var accessTime = regexp.MustCompile(`\[([0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}\s+[+-][0-9]{4})\]`)

func ScanAccessLog(r *Report, path string) { ScanAccessLogWithIndicators(r, path, nil) }
func ScanAccessLogWithIndicators(r *Report, path string, indicators []rules.Indicator) {
	item := LogCoverage{File: path, Status: "NOT_ASSESSED", Methods: map[string]int{}, StatusClasses: map[string]int{}}
	b, err := ReadRegular(path, 32<<20)
	if err != nil {
		item.Status = "UNAVAILABLE"
		item.Detail = "File inaccessible, nonregular, or over 32 MiB: " + err.Error()
		r.Logs = append(r.Logs, item)
		r.AddWarning("Access log not reviewed: " + path)
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	var first, last time.Time
	var iisFields map[string]int
	iisDetected := false
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
		item.Detail = "Request count/time coverage only; no approved indicators loaded"
	} else {
		item.Status = "RULES_APPLIED_COVERAGE_LIMITED"
		item.Detail = "Matching rule literals only; no guarantee of detecting PHP2Shell activity"
	}
	if !first.IsZero() {
		item.FirstTimestamp = first.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		item.LastTimestamp = last.UTC().Format(time.RFC3339)
	}
	r.Logs = append(r.Logs, item)
}
