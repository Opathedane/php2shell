package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPHPPEFixtureEmbeddedVersionAllPlatforms(t *testing.T) {
	path := moduleTestdataPath(t, "windows", "php-pe-version-resource.bin")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skip(err)
	}
	ver, src, err := versionMarkersFromBytes(b)
	if err != nil || ver != "8.4.27" {
		t.Fatalf("ver=%q src=%v err=%v", ver, src, err)
	}
	if !strings.Contains(strings.Join(src, ","), "embedded_build_string") {
		t.Fatal(src)
	}
}
