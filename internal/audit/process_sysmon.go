package audit

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// parseSysmonEvent1CSV parses Sysmon process-creation (Event ID 1) CSV exports.
// Expected documented fields (common exports): UtcTime/Timestamp, Image, ParentImage,
// ProcessId, ParentProcessId, ProcessGuid, ParentProcessGuid, CommandLine, EventID (optional).
func parseSysmonEvent1CSV(b []byte, path string) ([]ProcessEvent, string) {
	r := csv.NewReader(bytes.NewReader(b))
	r.ReuseRecord = true
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, "CSV header unreadable: " + err.Error()
	}
	if len(header) > 0 {
		header[0] = strings.TrimPrefix(header[0], "\ufeff")
	}
	idx := csvFieldMap(header)
	hasImage := false
	for _, k := range []string{"image", "processimage"} {
		if _, ok := idx[k]; ok {
			hasImage = true
			break
		}
	}
	if !hasImage {
		return nil, "Sysmon CSV missing Image column"
	}

	var out []ProcessEvent
	var notes []string
	row := 1
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		row++
		if err != nil {
			notes = append(notes, fmt.Sprintf("row %d parse error (skipped)", row))
			continue
		}
		if eid := csvGet(rec, idx, "EventID", "EventId"); eid != "" && eid != "1" {
			continue
		}
		ts, ok := parseTimeFlexible(csvGet(rec, idx, "UtcTime", "UTCTime", "Timestamp", "TimeGenerated", "utc_time"))
		image := csvGet(rec, idx, "Image", "ProcessImage")
		parent := csvGet(rec, idx, "ParentImage", "ParentProcessImage")
		cmdline := csvGet(rec, idx, "CommandLine", "ProcessCommandLine")
		ev := ProcessEvent{
			TimeUTC:           ts,
			ProcessName:       baseNameLower(image),
			ProcessPath:       image,
			ParentName:        baseNameLower(parent),
			ParentPath:        parent,
			PID:               csvGet(rec, idx, "ProcessId", "ProcessID"),
			PPID:              csvGet(rec, idx, "ParentProcessId", "ParentProcessID"),
			ProcessEntityID:   csvGet(rec, idx, "ProcessGuid", "ProcessGUID"),
			ParentEntityID:    csvGet(rec, idx, "ParentProcessGuid", "ParentProcessGUID"),
			SourceRecord:      row,
			CmdClass:          classifyCommandLine(cmdline),
			TimestampReliable: ok,
		}
		if !ok {
			ev.ParseNotes = "UtcTime missing or unparseable"
		}
		out = append(out, ev)
		if len(out) >= processTelemetryMaxEvents {
			notes = append(notes, "event cap reached")
			break
		}
	}
	return out, strings.Join(notes, "; ")
}
