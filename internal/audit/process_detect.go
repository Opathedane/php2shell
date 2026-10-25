package audit

import (
	"fmt"
	"strings"
)

// detectSuspiciousProcessLeads finds web/PHP parent → suspicious child relationships.
// Ordinary admin activity can look similar — confidence stays suspected/unconfirmed;
// never CONFIRMED_COMPROMISE. Command lines are classification tokens only.
func detectSuspiciousProcessLeads(events []ProcessEvent) []ProcessLead {
	var leads []ProcessLead
	seen := map[string]bool{}
	for _, ev := range events {
		if !isWebOrPHPParentName(ev.ParentName, ev.ParentPath) {
			continue
		}
		kind, ok := childRiskClass(ev.ProcessName, ev.ProcessPath, ev.CmdClass)
		if !ok {
			continue
		}
		conf := "suspected"
		if !ev.TimestampReliable || ev.ParentPath == "" || ev.PPID == "" {
			conf = "unconfirmed"
		}
		dedup := ev.ProcessEntityID
		if dedup == "" {
			dedup = fmt.Sprintf("%s|%s|%s|%s|%d", ev.SourceFile, ev.PID, ev.PPID, kind, ev.SourceRecord)
		}
		dedup = kind + "|" + dedup
		if seen[dedup] {
			continue
		}
		seen[dedup] = true

		detail := fmt.Sprintf(
			"Web/PHP-related parent %q spawned child %q (class=%s, cmdline=%s). "+
				"Source=%s record=%d entity=%s. "+
				"Ordinary application or admin activity can look similar — analyst validation required. "+
				"PID/PPID alone are weak (reuse); prefer entity IDs when present. "+
				"Not confirmed compromise.",
			safeProcLabel(ev.ParentName, ev.ParentPath),
			safeProcLabel(ev.ProcessName, ev.ProcessPath),
			kind,
			ev.CmdClass,
			ev.SourceFormat,
			ev.SourceRecord,
			nullDash(ev.ProcessEntityID),
		)
		if kind == "agentic_section_delimiter" {
			detail = fmt.Sprintf(
				"Web/PHP-related parent %q spawned child %q with Unit 42-published agentic section-delimiter token in command line "+
					"(class=agentic_section_delimiter; raw command line not retained). "+
					"Source=%s record=%d entity=%s. "+
					"Campaign-aligned post-exploitation marker — still not confirmed compromise; credentials/tokens never echoed.",
				safeProcLabel(ev.ParentName, ev.ParentPath),
				safeProcLabel(ev.ProcessName, ev.ProcessPath),
				ev.SourceFormat,
				ev.SourceRecord,
				nullDash(ev.ProcessEntityID),
			)
		}
		if ev.ParseNotes != "" {
			detail += " Parse notes: " + ev.ParseNotes + "."
		}
		leads = append(leads, ProcessLead{
			Event:      ev,
			Kind:       kind,
			Confidence: conf,
			Detail:     detail,
			DedupKey:   dedup,
		})
		if len(leads) >= processTelemetryMaxLeads {
			break
		}
	}
	return leads
}

func safeProcLabel(name, path string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		n = baseNameLower(path)
	}
	if n == "" {
		return "(unknown)"
	}
	// Cap length; paths may be long but are not secrets-bearing by default.
	return truncateRunes(n, 80)
}

func nullDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
