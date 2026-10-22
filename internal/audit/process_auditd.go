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

var (
	auditMsgRE = regexp.MustCompile(`audit\((\d+(?:\.\d+)?):(\d+)\)`)
	auditKeyRE = regexp.MustCompile(`(?:^|\s)([a-z0-9_]+)=([^\s]+|"[^"]*")`)
)

type auditPartial struct {
	sec     int64
	serial  string
	exe     string
	comm    string
	pid     string
	ppid    string
	args    []string
	hasExec bool
	hasSys  bool
}

// parseAuditdExecve parses Linux auditd text logs for process execution.
// Uses documented type=SYSCALL (exe=, comm=, pid=, ppid=) and type=EXECVE (a0=…)
// correlated by audit serial. Parent executable is resolved via a PID→exe map when
// available; PID reuse may make that mapping wrong (noted on the event).
func parseAuditdExecve(b []byte, path string) ([]ProcessEvent, string) {
	_ = path
	bySerial := map[string]*auditPartial{}
	pidExe := map[string]string{} // best-effort; subject to reuse

	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	var notes []string
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "type=") {
			continue
		}
		m := auditMsgRE.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		serial := m[2]
		secFloat, _ := strconv.ParseFloat(m[1], 64)
		p := bySerial[serial]
		if p == nil {
			p = &auditPartial{serial: serial, sec: int64(secFloat)}
			bySerial[serial] = p
		}
		kv := parseAuditKV(line)
		isSyscall := strings.Contains(line, "type=SYSCALL")
		isExecve := strings.Contains(line, "type=EXECVE")
		if isSyscall {
			p.hasSys = true
			if v := unquoteAudit(kv["exe"]); v != "" {
				p.exe = v
			}
			if v := unquoteAudit(kv["comm"]); v != "" {
				p.comm = v
			}
			if v := kv["pid"]; v != "" {
				p.pid = v
				if p.exe != "" {
					pidExe[v] = p.exe
				} else if p.comm != "" {
					pidExe[v] = p.comm
				}
			}
			if v := kv["ppid"]; v != "" {
				p.ppid = v
			}
		}
		if isExecve {
			p.hasExec = true
			argc, _ := strconv.Atoi(kv["argc"])
			limit := argc
			if limit <= 0 || limit > 32 {
				limit = 8
			}
			for i := 0; i < limit; i++ {
				a := unquoteAudit(kv[fmt.Sprintf("a%d", i)])
				if a != "" {
					p.args = append(p.args, a)
				}
			}
		}
		if len(bySerial) > processTelemetryMaxEvents*2 {
			notes = append(notes, "audit serial map capped")
			break
		}
	}
	if err := scanner.Err(); err != nil {
		notes = append(notes, "scanner error: "+err.Error())
	}

	var out []ProcessEvent
	for _, p := range bySerial {
		if !p.hasSys && !p.hasExec {
			continue
		}
		// Prefer EXECVE a0 as the new image; else SYSCALL exe.
		childPath := ""
		if len(p.args) > 0 {
			childPath = p.args[0]
		}
		if childPath == "" {
			childPath = p.exe
		}
		childName := baseNameLower(childPath)
		if childName == "" {
			childName = strings.ToLower(p.comm)
		}
		parentPath := ""
		if p.ppid != "" {
			parentPath = pidExe[p.ppid]
		}
		cmdline := strings.Join(p.args, " ")
		ev := ProcessEvent{
			TimeUTC:           time.Unix(p.sec, 0).UTC(),
			ProcessName:       childName,
			ProcessPath:       childPath,
			ParentName:        baseNameLower(parentPath),
			ParentPath:        parentPath,
			PID:               p.pid,
			PPID:              p.ppid,
			ProcessEntityID:   "audit:" + p.serial,
			CmdClass:          classifyCommandLine(cmdline),
			TimestampReliable: p.sec > 0,
			ParseNotes:        "auditd: parent resolved via PPID map when available; PID reuse may mis-attribute parent",
		}
		if parentPath == "" && p.ppid != "" {
			ev.ParseNotes += "; parent executable unknown for PPID " + p.ppid
		}
		out = append(out, ev)
		if len(out) >= processTelemetryMaxEvents {
			break
		}
	}
	return out, strings.Join(notes, "; ")
}

func parseAuditKV(line string) map[string]string {
	out := map[string]string{}
	for _, m := range auditKeyRE.FindAllStringSubmatch(line, -1) {
		if len(m) == 3 {
			out[m[1]] = m[2]
		}
	}
	return out
}

func unquoteAudit(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}
