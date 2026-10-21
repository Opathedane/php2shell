//go:build windows

package audit

import (
	"os"
	"testing"
)

// TestPEVersionWithPHPResourceMetadata uses a fixture patterned after official PHP for Windows
// builds: PE version resource includes ProductName "PHP" and FileVersion aligned with 8.4.27.
func TestPEVersionWithPHPResourceMetadata(t *testing.T) {
	data, err := os.ReadFile(moduleTestdataPath(t, "windows", "php-pe-version-resource.bin"))
	if err != nil {
		t.Skip("fixture missing:", err)
	}
	ver, src, err := versionMarkersFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if ver != "8.4.27" {
		t.Fatalf("version %q sources %v", ver, src)
	}
	if !containsSource(src, "pe_fixed_file_info") && !containsSource(src, "embedded_build_string") {
		t.Fatalf("expected PE or embedded source: %v", src)
	}
}

func containsSource(src []string, want string) bool {
	for _, s := range src {
		if s == want {
			return true
		}
	}
	return false
}
