package audit

import (
	"testing"
	"time"
)

func TestWalkWindowsProcessListAlwaysAdvances(t *testing.T) {
	const n = 5000
	entries := make([]windowsProc, n)
	for i := 0; i < n; i++ {
		entries[i] = windowsProc{PID: uint32(i + 1), Name: "svchost.exe"}
	}
	entries[0] = windowsProc{PID: 42, Name: "php2shell-windows-amd64.exe"} // self
	entries[10] = windowsProc{PID: 100, Name: "php-cgi.exe"}
	entries[11] = windowsProc{PID: 101, Name: "php.exe"}
	entries[12] = windowsProc{PID: 102, Name: "w3wp.exe"}
	entries[13] = windowsProc{PID: 103, Name: "phpunit"} // must not match

	done := make(chan struct{})
	var visited int
	var matched []windowsProc
	go func() {
		visited = walkWindowsProcessList(entries, func(p windowsProc) {
			if int(p.PID) == 42 {
				return
			}
			if !IsPHPRuntimeProcessName(p.Name) {
				return
			}
			matched = append(matched, p)
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("process walk hung — advancement likely skipped on continue paths")
	}
	if visited != n {
		t.Fatalf("visited %d want %d", visited, n)
	}
	if len(matched) != 3 {
		t.Fatalf("matched=%+v", matched)
	}
}

func TestSelectWindowsPHPProcessesExcludesSelfAndNonPHP(t *testing.T) {
	entries := []windowsProc{
		{PID: 1, Name: "php2shell.exe"},
		{PID: 2, Name: "chrome.exe"},
		{PID: 3, Name: "php-cgi.exe"},
		{PID: 4, Name: "php.exe"},
		{PID: 5, Name: "w3wp.exe"},
		{PID: 6, Name: "phpmyadmin"},
	}
	recorded, count := selectWindowsPHPProcesses(entries, 1, 256)
	if count != 3 {
		t.Fatalf("count=%d", count)
	}
	if len(recorded) != 3 {
		t.Fatalf("%+v", recorded)
	}
	for _, p := range recorded {
		if int(p.PID) == 1 || p.Name == "phpmyadmin" || p.Name == "chrome.exe" {
			t.Fatalf("unexpected %+v", p)
		}
	}
}

func TestSelectWindowsPHPProcessesRespectsMaxRecord(t *testing.T) {
	var entries []windowsProc
	for i := 0; i < 10; i++ {
		entries = append(entries, windowsProc{PID: uint32(100 + i), Name: "php.exe"})
	}
	recorded, count := selectWindowsPHPProcesses(entries, 0, 3)
	if count != 10 || len(recorded) != 3 {
		t.Fatalf("count=%d recorded=%d", count, len(recorded))
	}
}

func TestBuggyContinueBeforeAdvanceWouldHang(t *testing.T) {
	// Documents the CI failure mode: continue before Next never advances.
	entries := []windowsProc{
		{PID: 1, Name: "svchost.exe"},
		{PID: 2, Name: "php.exe"},
	}
	i := 0
	steps := 0
	for {
		steps++
		if steps > 100 {
			// Expected for the buggy pattern when the first entry is skipped.
			break
		}
		e := entries[i]
		if e.Name != "php.exe" {
			continue // BUG: skips i++
		}
		i++
		if i >= len(entries) {
			break
		}
	}
	if steps <= 100 {
		t.Fatal("expected buggy pattern to spin; rewrite failed to demonstrate the hazard")
	}

	// Fixed pattern finishes in len(entries) steps.
	steps = 0
	i = 0
	for {
		steps++
		_ = entries[i]
		i++ // always advance
		if i >= len(entries) {
			break
		}
	}
	if steps != len(entries) {
		t.Fatalf("fixed pattern steps=%d", steps)
	}
}
