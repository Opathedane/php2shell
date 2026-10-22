package audit

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// parseMDEDeviceProcessCSV parses Microsoft Defender for Endpoint DeviceProcessEvents CSV exports.
// Documented columns used: Timestamp, DeviceName, FileName, FolderPath, ProcessId,
// ProcessCommandLine, ProcessCreationTime, InitiatingProcessFileName, InitiatingProcessFolderPath,
// InitiatingProcessId, InitiatingProcessCommandLine, ReportId, ActionType (optional filter).
// Ref: Microsoft Learn — DeviceProcessEvents schema.
func parseMDEDeviceProcessCSV(b []byte, path string) ([]ProcessEvent, string) {
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
	if _, ok := idx["timestamp"]; !ok {
		return nil, "MDE CSV missing required Timestamp column"
	}
	if _, ok := idx["filename"]; !ok {
		return nil, "MDE CSV missing required FileName column"
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
		action := strings.ToLower(csvGet(rec, idx, "ActionType"))
		if action != "" && action != "processcreated" && !strings.Contains(action, "process") {
			continue
		}
		ts, ok := parseTimeFlexible(csvGet(rec, idx, "Timestamp"))
		name := csvGet(rec, idx, "FileName")
		folder := csvGet(rec, idx, "FolderPath")
		procPath := joinFolderFile(folder, name)
		parentName := csvGet(rec, idx, "InitiatingProcessFileName")
		parentFolder := csvGet(rec, idx, "InitiatingProcessFolderPath")
		parentPath := joinFolderFile(parentFolder, parentName)
		cmdline := csvGet(rec, idx, "ProcessCommandLine")
		start, _ := parseTimeFlexible(csvGet(rec, idx, "ProcessCreationTime"))
		ev := ProcessEvent{
			TimeUTC:           ts,
			Host:              csvGet(rec, idx, "DeviceName"),
			ProcessName:       name,
			ProcessPath:       procPath,
			ParentName:        parentName,
			ParentPath:        parentPath,
			PID:               csvGet(rec, idx, "ProcessId"),
			PPID:              csvGet(rec, idx, "InitiatingProcessId"),
			ProcessEntityID:   csvGet(rec, idx, "ReportId"),
			StartTimeUTC:      start,
			SourceRecord:      row,
			CmdClass:          classifyCommandLine(cmdline),
			TimestampReliable: ok,
		}
		if !ok {
			ev.ParseNotes = "Timestamp missing or unparseable"
		}
		out = append(out, ev)
		if len(out) >= processTelemetryMaxEvents {
			notes = append(notes, "event cap reached")
			break
		}
	}
	return out, strings.Join(notes, "; ")
}

func joinFolderFile(folder, file string) string {
	folder = strings.TrimSpace(folder)
	file = strings.TrimSpace(file)
	if folder == "" {
		return file
	}
	if file == "" {
		return folder
	}
	if strings.HasSuffix(folder, `\`) || strings.HasSuffix(folder, `/`) {
		return folder + file
	}
	if strings.Contains(folder, `\`) {
		return folder + `\` + file
	}
	return folder + `/` + file
}
