package audit

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var accessLine = regexp.MustCompile(`"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+[^"\r\n]{0,1000}\s+HTTP/[0-9.]+"\s+([0-9]{3})`)
var accessTime = regexp.MustCompile(`\[([0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}\s+[+-][0-9]{4})\]`)

func ScanAccessLog(r *Report, path string) {
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
	for scanner.Scan() {
		item.Lines++
		line := scanner.Text()
		if m := accessLine.FindStringSubmatch(line); len(m) > 2 {
			item.ParsedRequests++
			item.Methods[m[1]]++
			n, _ := strconv.Atoi(m[2])
			item.StatusClasses[fmt.Sprintf("%dxx", n/100)]++
		}
		if m := accessTime.FindStringSubmatch(line); len(m) > 1 {
			t, err := time.Parse("02/Jan/2006:15:04:05 -0700", strings.TrimSpace(m[1]))
			if err == nil {
				if first.IsZero() || t.Before(first) {
					first = t
				}
				if last.IsZero() || t.After(last) {
					last = t
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		item.Status = "INCOMPLETE"
		item.Detail = "Encountered overlong or unreadable log line"
	} else {
		item.Status = "SUMMARIZED_NO_IOCS"
		item.Detail = "Request counts only; no PHP2Shell-specific indicators or compromise conclusion"
	}
	if !first.IsZero() {
		item.FirstTimestamp = first.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		item.LastTimestamp = last.UTC().Format(time.RFC3339)
	}
	r.Logs = append(r.Logs, item)
}
