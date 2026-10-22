package audit

import (
	"strings"
	"testing"
)

func TestEvaluateWindowsCompatibilityModern(t *testing.T) {
	ok, msg := EvaluateWindowsCompatibility("windows", "standard", &WindowsHostInfo{Major: 6, Minor: 3, Build: 9600}, nil)
	if ok || msg == "" {
		t.Fatalf("2012 R2 must reject standard build; ok=%v msg=%q", ok, msg)
	}
	if !containsAll(msg, "php2shell-windows-legacy-amd64.exe", "2012") {
		t.Fatalf("message should name legacy artifact: %s", msg)
	}

	ok, msg = EvaluateWindowsCompatibility("windows", "standard", &WindowsHostInfo{Major: 10, Minor: 0, Build: 17763}, nil)
	if !ok || msg != "" {
		t.Fatalf("Server 2019 must accept standard build; ok=%v msg=%q", ok, msg)
	}
}

func TestEvaluateWindowsCompatibilityLegacy(t *testing.T) {
	ok, msg := EvaluateWindowsCompatibility("windows", "legacy", &WindowsHostInfo{Major: 6, Minor: 3, Build: 9600}, nil)
	if !ok || msg != "" {
		t.Fatalf("2012 R2 must accept legacy build; ok=%v msg=%q", ok, msg)
	}

	ok, msg = EvaluateWindowsCompatibility("windows", "legacy", &WindowsHostInfo{Major: 6, Minor: 1, Build: 7601}, nil)
	if ok || msg == "" {
		t.Fatalf("Win7 must reject legacy product floor; ok=%v msg=%q", ok, msg)
	}

	note := WindowsCompatAdvisory("windows", "legacy", &WindowsHostInfo{Major: 10, Minor: 0, Build: 19045})
	if note == "" {
		t.Fatal("expected advisory when legacy runs on modern Windows")
	}
}

func TestEvaluateWindowsCompatibilityNonWindows(t *testing.T) {
	ok, msg := EvaluateWindowsCompatibility("linux", "standard", nil, nil)
	if !ok || msg != "" {
		t.Fatalf("non-windows must pass; ok=%v msg=%q", ok, msg)
	}
}

func TestEvaluateWindowsCompatibilityUnknownVersion(t *testing.T) {
	ok, msg := EvaluateWindowsCompatibility("windows", "standard", nil, errSample)
	if ok || msg == "" {
		t.Fatalf("standard build must fail closed when version unknown; ok=%v msg=%q", ok, msg)
	}
	ok, msg = EvaluateWindowsCompatibility("windows", "legacy", nil, errSample)
	if !ok {
		t.Fatalf("legacy may fail open when version unknown; msg=%q", msg)
	}
}

var errSample = errString("probe failed")

type errString string

func (e errString) Error() string { return string(e) }

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
