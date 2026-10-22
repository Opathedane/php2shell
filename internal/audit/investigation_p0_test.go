package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestP0SAPIContextModPHPAndFPMHints(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	r.AddEvidence(Evidence{
		Type: "apache_php_module_config", Name: "php_module", Location: "/etc/apache2/mods-enabled/php8.3.load",
		Detail: "module=php_module; module_path=libphp8.3.so; sapi=mod_php; configured_not_verified_serving",
	})
	r.AddEvidence(Evidence{
		Type: "binary_static_version", Name: "php-fpm8.3", Version: "8.3.24",
		Location: "/usr/sbin/php-fpm8.3", Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
	})
	ctx := ClassifyConfiguredSAPIContext(r)
	if !ctx.ModPHPConfigured || !ctx.PHPFPMHints {
		t.Fatalf("expected mod_php and FPM hints, got %+v", ctx)
	}
	if !strings.Contains(ctx.Detail, "Do not infer that PHP-FPM cannot be exploited") {
		t.Fatalf("must not imply FPM is safe: %s", ctx.Detail)
	}
	if !strings.Contains(ctx.Detail, "do NOT prove") && !strings.Contains(ctx.Detail, "NOT prove") {
		t.Fatalf("must not claim active runtime from config: %s", ctx.Detail)
	}
}

func TestP0SAPIContextUnknown(t *testing.T) {
	r := NewReport("host", "linux", "amd64")
	ctx := ClassifyConfiguredSAPIContext(r)
	if ctx.Label != "Unknown / unverified" {
		t.Fatalf("label=%s", ctx.Label)
	}
	if !strings.Contains(ctx.Detail, "PHP-FPM") {
		t.Fatal("unknown narrative should still mention FPM vs mod_php differences")
	}
}

func TestP0HTTPBodyFormMetadataUnavailableCheck(t *testing.T) {
	dir := t.TempDir()
	access := writeTemp(t, dir, "access.log", `127.0.0.1 - - [18/Oct/2026:12:00:00 +0000] "GET /index.php HTTP/1.1" 200 1234`+"\n")
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	acc := mustCollectAccess(t, r, access)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, acc, nil, nil, nil)

	foundBody, foundSAPI, foundSources := false, false, false
	for _, c := range r.Coverage {
		switch c.Name {
		case "http_request_body_form_metadata":
			foundBody = true
			if c.Status != "UNAVAILABLE" {
				t.Fatalf("body metadata status=%s", c.Status)
			}
			low := strings.ToLower(c.Detail)
			for _, want := range []string{"request-target", "form-field", "multipart", "body"} {
				if !strings.Contains(low, want) {
					t.Fatalf("body/form limitation missing %q in %s", want, c.Detail)
				}
			}
		case "sapi_investigation_context":
			foundSAPI = true
			if c.Status != "HINTS_ONLY_ACTIVE_RUNTIME_UNVERIFIED" {
				t.Fatalf("sapi status=%s", c.Status)
			}
		case "investigation_evidence_sources":
			foundSources = true
			if !strings.Contains(c.Detail, "REQUESTED_USABLE") && !strings.Contains(c.Detail, "NOT_REQUESTED") {
				t.Fatalf("evidence sources detail: %s", c.Detail)
			}
			if !strings.Contains(c.Detail, "NO_MATCHES_IN_SCOPE") {
				t.Fatalf("must distinguish unavailable vs no-matches: %s", c.Detail)
			}
		}
	}
	if !foundBody || !foundSAPI || !foundSources {
		t.Fatalf("missing P0 checks body=%v sapi=%v sources=%v", foundBody, foundSAPI, foundSources)
	}
}

func TestP0NoMatchesVsUnavailableMessaging(t *testing.T) {
	dir := t.TempDir()
	access := writeTemp(t, dir, "access.log", `127.0.0.1 - - [18/Oct/2026:12:00:00 +0000] "GET /index.php HTTP/1.1" 200 1234`+"\n")
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	acc := mustCollectAccess(t, r, access)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, acc, nil, nil, nil)
	if r.ExploitationAttemptStatus != "NO_MATCHES_IN_SCOPE" {
		t.Fatalf("attempt=%s", r.ExploitationAttemptStatus)
	}
	joined := strings.Join(r.RecommendedActions, "\n") + "\n" + strings.Join(r.Warnings, "\n")
	if !strings.Contains(joined, "completed no-match") && !strings.Contains(joined, "not unavailable evidence") {
		t.Fatalf("no-match must distinguish from unavailable: %s", joined)
	}
	if !strings.Contains(joined, "in-process") && !strings.Contains(strings.ToLower(joined), "suspicious child") {
		t.Fatalf("must warn about in-process exploitation without child: %s", joined)
	}

	// Unavailable path: requested log that cannot be read.
	r2 := NewReport("host", "linux", "amd64")
	r2.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	missing := filepath.Join(dir, "missing-access.log")
	_, _ = ScanAccessLogCollect(r2, missing, nil)
	FinalizeInvestigation(r2, InvestigationOptions{Assessing: true}, nil, nil, nil, nil)
	if r2.ExploitationAttemptStatus != "NOT_ASSESSED" {
		t.Fatalf("unavailable logs should leave attempts NOT_ASSESSED, got %s", r2.ExploitationAttemptStatus)
	}
	if r2.InvestigationCoverage != "INCOMPLETE" {
		t.Fatalf("coverage want INCOMPLETE, got %s", r2.InvestigationCoverage)
	}
	html := string(EncodeHTML(r2))
	if !strings.Contains(html, "unavailable") && !strings.Contains(html, "Incomplete") {
		t.Fatal("HTML should surface incomplete/unavailable coverage")
	}
}

func TestP0HTMLDistinguishesRequestTargetBodyFormMultipart(t *testing.T) {
	dir := t.TempDir()
	access := writeTemp(t, dir, "access.log", `127.0.0.1 - - [18/Oct/2026:12:00:00 +0000] "GET /index.php HTTP/1.1" 200 1`+"\n")
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	r.AddEvidence(Evidence{Type: "apache_php_module_config", Name: "php_module", Location: "/etc/apache2/mods-enabled/php.load", Detail: "sapi=mod_php"})
	acc := mustCollectAccess(t, r, access)
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true}, acc, nil, nil, nil)
	html := string(EncodeHTML(r))
	for _, want := range []string{
		"Configured SAPI hints",
		"request-target",
		"multipart",
		"form-field",
		"in-process",
		"OBSERVED",
		"not successful exploitation",
	} {
		if !strings.Contains(html, want) && !strings.Contains(strings.ToLower(html), strings.ToLower(want)) {
			// OBSERVED may appear as OBSERVED≠EFFECTIVE in config section only when ini present;
			// still require the body/form/SAPI/in-process language.
			if want == "OBSERVED" {
				continue
			}
			t.Fatalf("HTML missing %q", want)
		}
	}
	if !strings.Contains(html, "mod_php") || !strings.Contains(html, "PHP-FPM") {
		t.Fatal("HTML SAPI narrative should mention mod_php and PHP-FPM")
	}
}

func TestP0ConfigurationObservationNotEffective(t *testing.T) {
	dir := t.TempDir()
	ini := filepath.Join(dir, "php.ini")
	body := "memory_limit = 128M\nsession.upload_progress.enabled = On\npost_max_size = 8M\n"
	if err := os.WriteFile(ini, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewReport("host", "linux", "amd64")
	ObservePHPIniFile(r, ini, "test")
	found := 0
	for _, e := range r.Evidence {
		if e.Type != "configuration_observation" {
			continue
		}
		found++
		if e.Interpretation != "OBSERVED_NOT_EFFECTIVE_SETTING_NOT_VERIFIED_MITIGATION" {
			t.Fatalf("interp=%s", e.Interpretation)
		}
		if !strings.Contains(e.Detail, "observed_text_only=not_effective_runtime_setting") {
			t.Fatalf("detail missing observed_text_only: %s", e.Detail)
		}
		if e.Name == "memory_limit" || e.Name == "session.upload_progress.enabled" || e.Name == "post_max_size" {
			if !strings.Contains(e.Detail, "temporary_mitigation_unverified") {
				t.Fatalf("mitigation settings need unverified marker: %s %s", e.Name, e.Detail)
			}
		}
	}
	if found < 3 {
		t.Fatalf("expected configuration observations, got %d", found)
	}
}
