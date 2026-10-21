package audit

import "testing"

func TestCorrelatedPackageAndBinarySameInstall(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.4-fpm", Version: "8.4.27", Source: "dpkg", Location: "/var/lib/dpkg/status"})
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php-fpm8.4", Version: "8.4.27", Source: "test", Location: "/usr/sbin/php-fpm8.4"})
	EvaluatePatchPosture(r)
	if r.VulnerabilityStatus == "MULTIPLE_RUNTIMES_MIXED_PATCH_LEVELS_REVIEW_REQUIRED" {
		t.Fatal("correlated install should not appear as mixed runtimes")
	}
	if r.VulnerabilityStatus != "UPSTREAM_FIX_LEVEL_OBSERVED_ACTIVE_RUNTIME_UNVERIFIED" {
		t.Fatalf("unexpected status: %s", r.VulnerabilityStatus)
	}
	if len(r.PatchAssessments) != 2 {
		t.Fatalf("assessments: %+v", r.PatchAssessments)
	}
	if r.PatchAssessments[0].InstallKey == "" || r.PatchAssessments[0].InstallKey != r.PatchAssessments[1].InstallKey {
		t.Fatalf("install keys: %q vs %q", r.PatchAssessments[0].InstallKey, r.PatchAssessments[1].InstallKey)
	}
}

func TestConflictingVersionsSameInstall(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.4-fpm", Version: "8.4.26", Source: "dpkg", Location: "/var/lib/dpkg/status"})
	r.AddEvidence(Evidence{Type: "binary_static_version", Name: "php-fpm8.4", Version: "8.4.27", Source: "test", Location: "/usr/sbin/php-fpm8.4"})
	EvaluatePatchPosture(r)
	if r.VulnerabilityStatus != "INSTALL_EVIDENCE_VERSION_CONFLICT_REVIEW_REQUIRED" {
		t.Fatalf("expected conflict, got %s", r.VulnerabilityStatus)
	}
}

func TestMixedDistinctInstalls(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.4-fpm", Version: "8.4.27", Source: "dpkg", Location: "/var/lib/dpkg/status"})
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.2-fpm", Version: "8.2.34", Source: "dpkg", Location: "/var/lib/dpkg/status"})
	EvaluatePatchPosture(r)
	if r.VulnerabilityStatus != "MULTIPLE_RUNTIMES_MIXED_PATCH_LEVELS_REVIEW_REQUIRED" {
		t.Fatalf("expected mixed installs, got %s", r.VulnerabilityStatus)
	}
}

func TestDistinctInstallsAllBelowNotMixedLabel(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.4-fpm", Version: "8.4.26", Source: "dpkg", Location: "/var/lib/dpkg/status"})
	r.AddEvidence(Evidence{Type: "installed_package", Name: "php8.2-fpm", Version: "8.2.34", Source: "dpkg", Location: "/var/lib/dpkg/status"})
	EvaluatePatchPosture(r)
	if r.VulnerabilityStatus != "BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED" {
		t.Fatalf("expected below fix, got %s", r.VulnerabilityStatus)
	}
}
