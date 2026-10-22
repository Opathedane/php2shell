package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// elasticProcessDoc is a minimal Elastic ECS process event shape.
// Fields follow Elastic Common Schema process.* / process.parent.* / @timestamp / host.name.
type elasticProcessDoc struct {
	Timestamp string `json:"@timestamp"`
	Host      *struct {
		Name string `json:"name"`
	} `json:"host"`
	Process *struct {
		Name       string `json:"name"`
		Executable string `json:"executable"`
		PID        any    `json:"pid"`
		CommandLine string `json:"command_line"`
		EntityID   string `json:"entity_id"`
		Parent     *struct {
			Name       string `json:"name"`
			Executable string `json:"executable"`
			PID        any    `json:"pid"`
			EntityID   string `json:"entity_id"`
		} `json:"parent"`
	} `json:"process"`
	Event *struct {
		Category any    `json:"category"`
		Type     any    `json:"type"`
		Action   string `json:"action"`
	} `json:"event"`
}

// parseElasticECSJSONL parses newline-delimited JSON using documented ECS process fields.
func parseElasticECSJSONL(b []byte, path string) ([]ProcessEvent, string) {
	_ = path
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 64*1024), 2<<20)
	var out []ProcessEvent
	var notes []string
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var doc elasticProcessDoc
		if err := json.Unmarshal(line, &doc); err != nil {
			notes = append(notes, fmt.Sprintf("line %d: invalid JSON (skipped)", lineNo))
			continue
		}
		if doc.Process == nil {
			continue
		}
		// Prefer process events; skip if event.category clearly unrelated when present.
		if doc.Event != nil && !ecsLooksLikeProcess(doc.Event.Category, doc.Event.Type, doc.Event.Action) {
			continue
		}
		ts, ok := parseTimeFlexible(doc.Timestamp)
		parentName, parentPath, ppid, parentEnt := "", "", "", ""
		if doc.Process.Parent != nil {
			parentName = doc.Process.Parent.Name
			parentPath = doc.Process.Parent.Executable
			ppid = anyToString(doc.Process.Parent.PID)
			parentEnt = doc.Process.Parent.EntityID
		}
		host := ""
		if doc.Host != nil {
			host = doc.Host.Name
		}
		ev := ProcessEvent{
			TimeUTC:           ts,
			Host:              host,
			ProcessName:       firstNonEmpty(doc.Process.Name, baseNameLower(doc.Process.Executable)),
			ProcessPath:       doc.Process.Executable,
			ParentName:        firstNonEmpty(parentName, baseNameLower(parentPath)),
			ParentPath:        parentPath,
			PID:               anyToString(doc.Process.PID),
			PPID:              ppid,
			ProcessEntityID:   doc.Process.EntityID,
			ParentEntityID:    parentEnt,
			SourceRecord:      lineNo,
			CmdClass:          classifyCommandLine(doc.Process.CommandLine),
			TimestampReliable: ok,
		}
		if !ok {
			ev.ParseNotes = "@timestamp missing or unparseable"
		}
		out = append(out, ev)
		if len(out) >= processTelemetryMaxEvents {
			notes = append(notes, "event cap reached")
			break
		}
	}
	if err := scanner.Err(); err != nil {
		notes = append(notes, "scanner error: "+err.Error())
	}
	return out, strings.Join(notes, "; ")
}

func ecsLooksLikeProcess(category, typ any, action string) bool {
	action = strings.ToLower(action)
	if action != "" && (strings.Contains(action, "process") || action == "start" || action == "exec" || action == "executed") {
		return true
	}
	check := func(v any) bool {
		switch t := v.(type) {
		case string:
			l := strings.ToLower(t)
			return l == "process" || strings.Contains(l, "process")
		case []any:
			for _, x := range t {
				if s, ok := x.(string); ok && strings.Contains(strings.ToLower(s), "process") {
					return true
				}
			}
		}
		return false
	}
	if category == nil && typ == nil && action == "" {
		return true // process object present; accept
	}
	return check(category) || check(typ) || action == ""
}

func anyToString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return fmt.Sprintf("%.0f", t)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}
