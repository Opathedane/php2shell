package audit

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// ScanProcessTelemetry parses one offline EDR/process export into normalized events
// and coverage. Never executes content; never retains raw command lines in findings.
func ScanProcessTelemetry(r *Report, path string) (events []ProcessEvent, leads []ProcessLead) {
	item := ProcessTelemetryCoverage{File: path, Status: "NOT_ASSESSED"}
	b, err := ReadRegular(path, processTelemetryMaxBytes)
	if err != nil {
		item.Status = "UNAVAILABLE"
		item.Detail = "File inaccessible, nonregular, or over 32 MiB: " + err.Error()
		r.ProcessTelemetry = append(r.ProcessTelemetry, item)
		r.AddWarning("Process telemetry not reviewed: " + path)
		return nil, nil
	}

	format := detectProcessTelemetryFormat(b)
	item.Format = string(format)
	if format == FormatUnsupported {
		item.Status = "UNSUPPORTED_FORMAT"
		item.Detail = "Could not detect a documented schema (MDE DeviceProcessEvents CSV, Sysmon EventID 1 CSV, Linux auditd EXECVE text, or Elastic ECS process JSONL). No invented field mappings applied."
		r.ProcessTelemetry = append(r.ProcessTelemetry, item)
		r.AddWarning("Unsupported process telemetry format: " + path)
		return nil, nil
	}

	var parseErr string
	switch format {
	case FormatMDEDeviceProcessCSV:
		events, parseErr = parseMDEDeviceProcessCSV(b, path)
	case FormatSysmonProcessCSV:
		events, parseErr = parseSysmonEvent1CSV(b, path)
	case FormatAuditdText:
		events, parseErr = parseAuditdExecve(b, path)
	case FormatElasticECSJSONL:
		events, parseErr = parseElasticECSJSONL(b, path)
	}
	if len(events) > processTelemetryMaxEvents {
		events = events[:processTelemetryMaxEvents]
		parseErr = strings.TrimSpace(parseErr + " Event cap reached (50000); remaining rows omitted.")
	}

	var first, last time.Time
	for i := range events {
		events[i].SourceFormat = format
		events[i].SourceFile = path
		if !events[i].TimeUTC.IsZero() {
			if first.IsZero() || events[i].TimeUTC.Before(first) {
				first = events[i].TimeUTC
			}
			if last.IsZero() || events[i].TimeUTC.After(last) {
				last = events[i].TimeUTC
			}
		}
	}
	item.EventsParsed = len(events)
	if !first.IsZero() {
		item.FirstTimestamp = first.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		item.LastTimestamp = last.UTC().Format(time.RFC3339)
	}

	leads = detectSuspiciousProcessLeads(events)
	item.SuspiciousLeads = len(leads)

	if len(events) == 0 {
		item.Status = "INCOMPLETE"
		if parseErr != "" {
			item.Detail = parseErr
		} else {
			item.Detail = fmt.Sprintf("Detected %s but no process-creation events were parsed (empty or header-only export). Possible-compromise remains NOT_ASSESSED.", format)
		}
	} else if parseErr != "" {
		item.Status = "PARTIAL"
		item.Detail = fmt.Sprintf("Parsed %d process events as %s with limitations: %s. First/last timestamps do not prove continuous telemetry coverage. Command lines redacted to classification tokens.",
			len(events), format, parseErr)
	} else {
		item.Status = "PARSED_COVERAGE_LIMITED"
		item.Detail = fmt.Sprintf("Parsed %d process events as %s. First/last timestamps do not prove continuous coverage; PID reuse and missing parents may hide ancestry. Command lines redacted.",
			len(events), format)
	}
	r.ProcessTelemetry = append(r.ProcessTelemetry, item)
	return events, leads
}

func detectProcessTelemetryFormat(b []byte) SupportedFormat {
	trim := bytes.TrimSpace(b)
	if len(trim) == 0 {
		return FormatUnsupported
	}
	// JSONL / JSON object → ECS attempt
	if trim[0] == '{' {
		var probe map[string]json.RawMessage
		line := trim
		if i := bytes.IndexByte(trim, '\n'); i > 0 {
			line = bytes.TrimSpace(trim[:i])
		}
		if json.Unmarshal(line, &probe) == nil {
			if _, ok := probe["process"]; ok {
				return FormatElasticECSJSONL
			}
			if _, ok := probe["@timestamp"]; ok {
				return FormatElasticECSJSONL
			}
		}
	}
	// auditd text
	head := string(trim)
	if len(head) > 4000 {
		head = head[:4000]
	}
	if strings.Contains(head, "type=EXECVE") || strings.Contains(head, "type=SYSCALL") && strings.Contains(head, "audit(") {
		return FormatAuditdText
	}
	// CSV header detection
	scanner := bufio.NewScanner(bytes.NewReader(trim))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	if !scanner.Scan() {
		return FormatUnsupported
	}
	headerLine := scanner.Text()
	// strip BOM
	headerLine = strings.TrimPrefix(headerLine, "\ufeff")
	fields := splitCSVHeader(headerLine)
	lower := map[string]bool{}
	for _, f := range fields {
		lower[strings.ToLower(strings.TrimSpace(f))] = true
	}
	// MDE DeviceProcessEvents documented columns
	if lower["timestamp"] && lower["filename"] && lower["initiatingprocessfilename"] && (lower["processid"] || lower["reportid"]) {
		return FormatMDEDeviceProcessCSV
	}
	// Sysmon Event ID 1 common CSV export columns
	if (lower["image"] || lower["processimage"]) && (lower["parentimage"] || lower["parentprocessimage"]) &&
		(lower["utctime"] || lower["utc_time"] || lower["timegenerated"] || lower["timestamp"]) {
		return FormatSysmonProcessCSV
	}
	if lower["eventid"] && lower["image"] && lower["parentimage"] {
		return FormatSysmonProcessCSV
	}
	return FormatUnsupported
}

func splitCSVHeader(line string) []string {
	r := csv.NewReader(strings.NewReader(line))
	r.ReuseRecord = true
	rec, err := r.Read()
	if err != nil {
		return strings.Split(line, ",")
	}
	return rec
}

func parseTimeFlexible(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" || s == "-" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.9999999Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05.9999999",
		"2006-01-02 15:04:05",
		"01/02/2006 15:04:05",
		"1/2/2006 3:04:05 PM",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	// Sysmon UtcTime often: 2026-10-18 14:05:01.123
	if t, err := time.ParseInLocation("2006-01-02 15:04:05.000", s, time.UTC); err == nil {
		return t.UTC(), true
	}
	if t, err := time.ParseInLocation("2006-01-02 15:04:05.000000", s, time.UTC); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

func csvFieldMap(header []string) map[string]int {
	m := map[string]int{}
	for i, h := range header {
		m[strings.ToLower(strings.TrimSpace(h))] = i
	}
	return m
}

func csvGet(rec []string, idx map[string]int, names ...string) string {
	for _, n := range names {
		if i, ok := idx[strings.ToLower(n)]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
	}
	return ""
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}
