package audit

// windowsProc is a portable snapshot of one Windows process entry for filtering tests.
type windowsProc struct {
	PID  uint32
	Name string
}

// selectWindowsPHPProcesses applies self-PID exclusion and PHP runtime name filtering.
func selectWindowsPHPProcesses(entries []windowsProc, selfPID int, maxRecord int) (recorded []windowsProc, matchCount int) {
	if maxRecord < 0 {
		maxRecord = 0
	}
	for _, e := range entries {
		if int(e.PID) == selfPID {
			continue
		}
		if !IsPHPRuntimeProcessName(e.Name) {
			continue
		}
		matchCount++
		if len(recorded) < maxRecord {
			recorded = append(recorded, e)
		}
	}
	return recorded, matchCount
}

// walkWindowsProcessList mirrors Toolhelp32 First/Next control flow:
// each entry is visited exactly once, then the enumerator advances.
// Filter decisions must not skip advancement (that caused the Windows CI hang).
func walkWindowsProcessList(entries []windowsProc, visit func(windowsProc)) (visited int) {
	if len(entries) == 0 {
		return 0
	}
	i := 0
	for {
		visit(entries[i])
		visited++
		// Process32Next equivalent — always reached after visit.
		i++
		if i >= len(entries) {
			break
		}
	}
	return visited
}
