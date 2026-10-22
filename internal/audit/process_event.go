package audit

import (
	"path/filepath"
	"strings"
	"time"
)

// Process telemetry resource bounds (offline, read-only).
const (
	processTelemetryMaxBytes   = 32 << 20 // 32 MiB per file
	processTelemetryMaxFiles   = 8
	processTelemetryMaxEvents  = 50000
	processTelemetryMaxLeads   = 100
	processCmdClassMaxRunes    = 48 // sanitized classification token only
)

// SupportedFormat identifies a documented export schema we parse.
type SupportedFormat string

const (
	FormatMDEDeviceProcessCSV SupportedFormat = "mde_device_process_events_csv"
	FormatSysmonProcessCSV    SupportedFormat = "sysmon_eventid1_csv"
	FormatAuditdText          SupportedFormat = "linux_auditd_execve_text"
	FormatElasticECSJSONL     SupportedFormat = "elastic_ecs_process_jsonl"
	FormatUnsupported         SupportedFormat = "unsupported"
)

// ProcessEvent is a normalized process-creation record from offline telemetry.
// Command lines are never retained verbatim — only a short safe classification.
type ProcessEvent struct {
	TimeUTC          time.Time
	Host             string
	ProcessName      string
	ProcessPath      string
	ParentName       string
	ParentPath       string
	PID              string
	PPID             string
	ProcessEntityID  string // e.g. Sysmon ProcessGuid, MDE ReportId fragment
	ParentEntityID   string
	StartTimeUTC     time.Time
	SourceFormat     SupportedFormat
	SourceFile       string
	SourceRecord     int // 1-based row/line when known
	CmdClass         string // safe token, e.g. shell_cmd, download_curl — never raw cmdline
	ParseNotes       string
	TimestampReliable bool
}

// ProcessTelemetryCoverage summarizes one --process-telemetry file review.
type ProcessTelemetryCoverage struct {
	File           string `json:"file"`
	Status         string `json:"status"`
	Format         string `json:"format,omitempty"`
	EventsParsed   int    `json:"events_parsed"`
	EventsInWindow int    `json:"events_in_window,omitempty"`
	SuspiciousLeads int   `json:"suspicious_leads,omitempty"`
	FirstTimestamp string `json:"first_timestamp,omitempty"`
	LastTimestamp  string `json:"last_timestamp,omitempty"`
	Detail         string `json:"detail,omitempty"`
}

// ProcessLead is a sanitized suspicious parent→child relationship for investigation.
type ProcessLead struct {
	Event            ProcessEvent
	Kind             string // web_parent_shell_child | web_parent_interpreter_child | web_parent_download_child | web_parent_temp_path_child
	Confidence       string // suspected | unconfirmed
	Detail           string
	DedupKey         string // avoid double-counting same underlying event
}

func baseNameLower(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, `\`, `/`)
	return strings.ToLower(filepath.Base(p))
}

func isWebOrPHPParentName(name, path string) bool {
	b := baseNameLower(name)
	if b == "" {
		b = baseNameLower(path)
	}
	switch b {
	case "php.exe", "php-cgi.exe", "php-win.exe", "php", "php-fpm", "php-cgi",
		"apache2", "httpd", "httpd.exe", "apache.exe",
		"w3wp.exe",
		"nginx", "nginx.exe",
		"lsphp":
		return true
	}
	if strings.HasPrefix(b, "php-fpm") || strings.HasPrefix(b, "lsphp") {
		return true
	}
	return false
}

func classifyCommandLine(cmdline string) string {
	c := strings.ToLower(strings.TrimSpace(cmdline))
	if c == "" {
		return "cmdline_absent"
	}
	switch {
	case strings.Contains(c, "curl") || strings.Contains(c, "wget") || strings.Contains(c, "certutil") || strings.Contains(c, "bitsadmin"):
		return "download_utility"
	case strings.Contains(c, "powershell") || strings.Contains(c, "pwsh"):
		return "shell_powershell"
	case strings.Contains(c, "cmd.exe") || strings.Contains(c, "/bin/sh") || strings.Contains(c, "/bin/bash") ||
		strings.Contains(c, " -c ") || strings.HasPrefix(c, "sh ") || strings.HasPrefix(c, "bash "):
		return "shell_invocation"
	case strings.Contains(c, "python") || strings.Contains(c, "perl") || strings.Contains(c, "ruby") || strings.Contains(c, "node"):
		return "script_interpreter"
	default:
		// Never echo the raw line — fixed token only.
		if len(c) > processCmdClassMaxRunes {
			return "cmdline_present_redacted"
		}
		return "cmdline_present_redacted"
	}
}

func childRiskClass(name, path, cmdClass string) (kind string, ok bool) {
	b := baseNameLower(name)
	if b == "" {
		b = baseNameLower(path)
	}
	switch b {
	case "cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "dash", "zsh", "ksh", "busybox":
		return "web_parent_shell_child", true
	case "python", "python3", "python.exe", "perl", "perl.exe", "ruby", "ruby.exe", "node", "node.exe":
		return "web_parent_interpreter_child", true
	case "curl", "curl.exe", "wget", "wget.exe", "certutil.exe", "bitsadmin.exe":
		return "web_parent_download_child", true
	}
	pl := strings.ToLower(path)
	if strings.Contains(pl, "/tmp/") || strings.Contains(pl, "/dev/shm/") || strings.Contains(pl, "/var/tmp/") ||
		strings.Contains(pl, `\temp\`) || strings.Contains(pl, `/temp/`) {
		if b != "" {
			return "web_parent_temp_path_child", true
		}
	}
	if cmdClass == "shell_invocation" || cmdClass == "download_utility" || cmdClass == "shell_powershell" {
		return "web_parent_shell_child", true
	}
	return "", false
}
