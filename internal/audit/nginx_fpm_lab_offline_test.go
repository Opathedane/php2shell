package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Lab ground-truth contracts (CONFIG_TREE_OFFLINE). These use the same scenario
// config trees as testdata/nginx-fpm-labs but do not start nginx/php-fpm.
// LIVE_DOCKER execution is scripts/run-all.sh — skipped when Docker is absent.

type labGroundTruth struct {
	Scenario string `json:"scenario"`
	Kind     string `json:"kind"`
	Expect   struct {
		EffectiveWebRuntime              string   `json:"effective_web_runtime"`
		EffectiveWebRuntimeIn            []string `json:"effective_web_runtime_in"`
		MustNotClaimVerifiedRuntime      bool     `json:"must_not_claim_verified_runtime"`
		NginxCoverageStatusIn            []string `json:"nginx_coverage_status_in"`
		PHPFPMCoverageStatusIn           []string `json:"php_fpm_coverage_status_in"`
		EvidenceAny                      []labEvExpect `json:"evidence_any"`
		EvidenceNoneTypes                []string `json:"evidence_none_types"`
		HandlerAndPoolVersionsEmpty      bool     `json:"handler_and_pool_versions_empty"`
		ForbidSoftNoPHPWithinCoverage    bool     `json:"forbid_soft_no_php_within_coverage"`
		AllowSoftNoPHPOrArtifactsOnly    bool     `json:"allow_soft_no_php_or_artifacts_only"`
		ForbidVersionOnRemote            bool     `json:"forbid_version_on_remote"`
		CorrelationDetailOptional        string   `json:"correlation_detail_optional"`
	} `json:"expect"`
}

type labEvExpect struct {
	Type               string   `json:"type"`
	Name               string   `json:"name"`
	DetailContainsAll  []string `json:"detail_contains_all"`
}

func labScenariosRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "nginx-fpm-labs", "scenarios"))
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		t.Fatalf("lab scenarios root missing: %s", root)
	}
	return root
}

func TestNginxFPMLabConfigTreesMatchGroundTruth(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nginx/FPM labs are Unix-focused")
	}
	base := labScenariosRoot(t)
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	var ran int
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		id := ent.Name()
		gtPath := filepath.Join(base, id, "ground-truth.json")
		raw, err := os.ReadFile(gtPath)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		var gt labGroundTruth
		if err := json.Unmarshal(raw, &gt); err != nil {
			t.Fatalf("%s: invalid ground-truth: %v", id, err)
		}
		t.Run(id, func(t *testing.T) {
			r := buildLabReportFromScenarioTrees(t, filepath.Join(base, id), id)
			assertLabGroundTruth(t, r, gt)
		})
		ran++
	}
	if ran < 8 {
		t.Fatalf("expected at least 8 lab scenarios, got %d", ran)
	}
}

func buildLabReportFromScenarioTrees(t *testing.T, scenarioDir, id string) *Report {
	t.Helper()
	r := NewReport("lab-offline-"+id, "linux", "amd64")
	nginxDir := filepath.Join(scenarioDir, "nginx")
	if fi, err := os.Stat(nginxDir); err == nil && fi.IsDir() {
		ParseNginxConfigForTest(r, nginxDir)
	}
	// Pool dirs used across scenarios.
	for _, rel := range []string{"fpm", "fpm83", "fpm84"} {
		p := filepath.Join(scenarioDir, rel)
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			if id == "07-unreadable-config" && rel == "fpm" {
				secret := filepath.Join(p, "secret.conf")
				_ = os.Chmod(secret, 0000)
				t.Cleanup(func() { _ = os.Chmod(secret, 0644) })
				if _, err := os.ReadFile(secret); err == nil {
					t.Skip("environment can read mode-000 files; cannot assert unreadable skip offline")
				}
			}
			ParseFPMPoolsForTest(r, p)
		}
	}
	// 03-remote: do not mount/parse fpm-remote into the nginx-facing report.
	CorrelateNginxFPMBackends(r)
	EvaluatePatchPosture(r)
	FinalizeSummary(r)
	return r
}

func assertLabGroundTruth(t *testing.T, r *Report, gt labGroundTruth) {
	t.Helper()
	exp := gt.Expect
	if exp.MustNotClaimVerifiedRuntime {
		if r.EffectiveWebRuntime == "VERIFIED" {
			t.Fatalf("EffectiveWebRuntime unexpectedly VERIFIED")
		}
		rt, _ := humanRuntime(r)
		if rt == "Verified" {
			t.Fatalf("human runtime Verified")
		}
	}
	if exp.EffectiveWebRuntime != "" && r.EffectiveWebRuntime != exp.EffectiveWebRuntime {
		t.Fatalf("EffectiveWebRuntime=%s want %s", r.EffectiveWebRuntime, exp.EffectiveWebRuntime)
	}
	if len(exp.EffectiveWebRuntimeIn) > 0 {
		ok := false
		for _, v := range exp.EffectiveWebRuntimeIn {
			if r.EffectiveWebRuntime == v {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("EffectiveWebRuntime=%q not in %v", r.EffectiveWebRuntime, exp.EffectiveWebRuntimeIn)
		}
	}
	assertCoverageIn(t, r, "nginx_configuration", exp.NginxCoverageStatusIn)
	assertCoverageIn(t, r, "php_fpm_configuration", exp.PHPFPMCoverageStatusIn)

	for _, want := range exp.EvidenceAny {
		if !labEvidenceMatches(r, want) {
			t.Fatalf("missing evidence %+v; have=%s", want, labEvidenceSummary(r))
		}
	}
	for _, typ := range exp.EvidenceNoneTypes {
		for _, e := range r.Evidence {
			if e.Type == typ {
				t.Fatalf("forbidden evidence type %s: %+v", typ, e)
			}
		}
	}
	if exp.HandlerAndPoolVersionsEmpty {
		for _, e := range r.Evidence {
			if (e.Type == "nginx_php_handler_config" || e.Type == "php_fpm_pool_config" || e.Type == "nginx_remote_php_backend") && e.Version != "" {
				t.Fatalf("version must be empty on %s: %+v", e.Type, e)
			}
		}
	}
	if exp.ForbidVersionOnRemote {
		for _, e := range r.Evidence {
			if e.Type == "nginx_remote_php_backend" && e.Version != "" {
				t.Fatalf("remote version set: %+v", e)
			}
		}
	}
	if exp.ForbidSoftNoPHPWithinCoverage && NoPHPDetectedWithinScanCoverage(r) {
		t.Fatal("soft no-PHP-within-coverage forbidden for this scenario")
	}
	if exp.CorrelationDetailOptional != "" {
		found := false
		for _, e := range r.Evidence {
			if e.Type == "nginx_php_handler_config" && strings.Contains(e.Detail, exp.CorrelationDetailOptional) {
				found = true
			}
		}
		if !found {
			t.Logf("optional correlation detail %q not present (acceptable if listen paths differ after normalize)", exp.CorrelationDetailOptional)
		}
	}
}

func assertCoverageIn(t *testing.T, r *Report, name string, want []string) {
	t.Helper()
	if len(want) == 0 {
		return
	}
	for _, c := range r.Coverage {
		if c.Name != name {
			continue
		}
		for _, w := range want {
			if c.Status == w {
				return
			}
		}
		t.Fatalf("coverage %s=%s not in %v", name, c.Status, want)
	}
	t.Fatalf("coverage row %s missing; want one of %v", name, want)
}

func labEvidenceMatches(r *Report, want labEvExpect) bool {
	for _, e := range r.Evidence {
		if want.Type != "" && e.Type != want.Type {
			continue
		}
		if want.Name != "" && e.Name != want.Name {
			continue
		}
		ok := true
		for _, frag := range want.DetailContainsAll {
			if !strings.Contains(e.Detail, frag) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func labEvidenceSummary(r *Report) string {
	var b strings.Builder
	for _, e := range r.Evidence {
		b.WriteString(e.Type)
		b.WriteString("{")
		b.WriteString(e.Name)
		b.WriteString(":")
		b.WriteString(e.Detail)
		b.WriteString("}; ")
	}
	return b.String()
}
