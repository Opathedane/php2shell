package audit

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
)

func TestOfficialPHP2ShellFixThresholds(t *testing.T) {
	cases := []struct{ version, status, fix string }{
		{"8.2.34", "BELOW_UPSTREAM_FIX", "8.2.35"},
		{"8.2.35", "AT_OR_ABOVE_UPSTREAM_FIX", "8.2.35"},
		{"8.3.35", "BELOW_UPSTREAM_FIX", "8.3.36"},
		{"8.3.36", "AT_OR_ABOVE_UPSTREAM_FIX", "8.3.36"},
		{"8.4.26-fpm", "BELOW_UPSTREAM_FIX", "8.4.27"},
		{"8.4.27+deb12u1", "AT_OR_ABOVE_UPSTREAM_FIX", "8.4.27"},
		{"8.5.11", "BELOW_UPSTREAM_FIX", "8.5.12"},
		{"8.5.12", "AT_OR_ABOVE_UPSTREAM_FIX", "8.5.12"},
		{"8.5.13", "AT_OR_ABOVE_UPSTREAM_FIX", "8.5.12"},
		{"8.1.45", "LEGACY_VENDOR_VERIFICATION_REQUIRED", ""},
		{"7.4.33", "LEGACY_VENDOR_VERIFICATION_REQUIRED", ""},
		{"8.6.0RC3", "UNDETERMINED_VERSION", ""},
		{"8.6.0-RC3", "PRERELEASE_NOT_APPROVED", ""},
		{"8.4", "UNDETERMINED_VERSION", ""},
		{"^8.4", "UNDETERMINED_VERSION", ""},
		{">=8.3", "UNDETERMINED_VERSION", ""},
		{"latest", "UNDETERMINED_VERSION", ""},
		{"8.6.0", "BRANCH_NOT_COVERED", ""},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			got := CheckPHPVersion(tc.version)
			if got.Status != tc.status || got.MinimumFixed != tc.fix {
				t.Fatalf("%q: got %+v, want %q/%q", tc.version, got, tc.status, tc.fix)
			}
		})
	}
}
func TestPostureNeverClearsRuntimeWithOnlyPackageEvidence(t *testing.T) {
	r := NewReport("test-host", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.4-fpm", Version: "8.4.27", Source: "dpkg", Location: "/var/lib/dpkg/status"})
	EvaluatePatchPosture(r)
	if !strings.Contains(r.VulnerabilityStatus, "UNVERIFIED") {
		t.Fatalf("unexpected assurance: %s", r.VulnerabilityStatus)
	}
	if r.EffectiveWebRuntime != "NOT_VERIFIED" {
		t.Fatalf("unexpected runtime: %s", r.EffectiveWebRuntime)
	}
	if r.CompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("unexpected compromise: %s", r.CompromiseStatus)
	}
}
func TestRepositoryOnlyNotDeclaredDeployed(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "repository_declaration", Name: "Docker PHP image", Version: "8.5.11-fpm", Source: "manifest", Location: "Dockerfile"})
	EvaluatePatchPosture(r)
	if r.VulnerabilityStatus != "REPOSITORY_DECLARATION_BELOW_FIX_DEPLOYMENT_UNKNOWN" {
		t.Fatal(r.VulnerabilityStatus)
	}
}
func TestPatchActionsIncludedInAllReports(t *testing.T) {
	r := NewReport("test", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.2-fpm", Version: "8.2.34", Source: "dpkg", Location: "/var/lib/dpkg/status"})
	EvaluatePatchPosture(r)
	if len(r.PatchAssessments) != 1 || r.PatchAssessments[0].MinimumFixed != "8.2.35" {
		t.Fatal(r.PatchAssessments)
	}
	data, err := EncodeCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	ok := false
	for _, v := range rows {
		if v[0] == "patch_assessment" && strings.Contains(v[5], "8.2.35") {
			ok = true
		}
	}
	if !ok {
		t.Fatal("expected patch instructions in CSV")
	}
	h := string(EncodeHTML(r))
	if !strings.Contains(h, "8.2.35") || !strings.Contains(h, "Required action") {
		t.Fatal("patch actions not in HTML")
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("patch_assessments")) {
		t.Fatal("patch assessments missing JSON")
	}
}
func TestNoVersionNeverGreen(t *testing.T) {
	r := NewReport("test", "windows", "amd64")
	EvaluatePatchPosture(r)
	if r.VulnerabilityStatus != "NO_COMPARABLE_PHP_VERSION_FOUND_INVENTORY_INCOMPLETE" {
		t.Fatal(r.VulnerabilityStatus)
	}
}
