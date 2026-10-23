package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWAFCloudflarePHP2ShellRuleBlock(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "demos", "waf", "cloudflare-firewall-php2shell-block.jsonl")
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	leads := ScanWAFLog(r, path)
	if len(leads) != 1 {
		t.Fatalf("want 1 php2shell rule lead (benign rule ignored), got %d %+v", len(leads), leads)
	}
	if leads[0].Kind != "waf_php2shell_rule_match" {
		t.Fatalf("kind=%s", leads[0].Kind)
	}
	if strings.Contains(leads[0].Detail, "203.0.113") {
		t.Fatal("must not retain ClientIP in findings")
	}
	if !strings.Contains(leads[0].Detail, "not successful") && !strings.Contains(leads[0].Detail, "not successful exploitation") {
		t.Fatalf("block must not imply success: %s", leads[0].Detail)
	}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true, HasWAFLogs: true}, nil, nil, nil, nil, leads)
	if r.ExploitationAttemptStatus != "SUSPECTED_ATTEMPTS_REVIEW" {
		t.Fatalf("attempt=%s", r.ExploitationAttemptStatus)
	}
	if r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("WAF alone must not set possible-compromise, got %s", r.PossibleCompromiseStatus)
	}
	html := string(EncodeHTML(r))
	if !strings.Contains(html, "Offline WAF") && !strings.Contains(html, "waf_php2shell_rule_match") {
		t.Fatal("HTML should surface WAF coverage/leads")
	}
	if strings.Contains(html, "203.0.113.10") {
		t.Fatal("HTML must not echo ClientIP")
	}
}

func TestWAFCloudflareUploadProgressToken(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "demos", "waf", "cloudflare-firewall-upload-progress.jsonl")
	r := NewReport("host", "linux", "amd64")
	leads := ScanWAFLog(r, path)
	if len(leads) != 1 || leads[0].Kind != "waf_upload_progress_query_token" {
		t.Fatalf("leads=%+v", leads)
	}
	if strings.Contains(leads[0].Detail, "token-not-for-retention") {
		t.Fatal("must not retain upload-progress query value")
	}
}

func TestWAFCloudflareBenignNoLead(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "demos", "waf", "cloudflare-firewall-benign.jsonl")
	r := NewReport("host", "linux", "amd64")
	r.GeneratedUTC = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	leads := ScanWAFLog(r, path)
	if len(leads) != 0 {
		t.Fatalf("benign unrelated rule must not create php2shell lead: %+v", leads)
	}
	FinalizeInvestigation(r, InvestigationOptions{Assessing: true, HasWAFLogs: true}, nil, nil, nil, nil, leads)
	if r.ExploitationAttemptStatus != "NO_MATCHES_IN_SCOPE" {
		t.Fatalf("attempt=%s", r.ExploitationAttemptStatus)
	}
	if r.PossibleCompromiseStatus != "NOT_ASSESSED" {
		t.Fatalf("possible=%s", r.PossibleCompromiseStatus)
	}
}

func TestWAFUnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	p := writeTemp(t, dir, "not-waf.txt", "this is not json\n")
	r := NewReport("host", "linux", "amd64")
	leads := ScanWAFLog(r, p)
	if len(leads) != 0 {
		t.Fatal("unsupported should yield no leads")
	}
	if len(r.WAFLogs) != 1 || r.WAFLogs[0].Status != "UNSUPPORTED_FORMAT" {
		t.Fatalf("coverage=%+v", r.WAFLogs)
	}
}

func TestWAFRuleIDSnakeCaseAllowlistedFinding(t *testing.T) {
	// Reproduces: exporters that use rule_id (not RuleID). Primary json.Unmarshal succeeds
	// with an empty RuleID field — must still match allowlisted IDs.
	dir := t.TempDir()
	rule := "4e315666e8e344cdb64119a3b5ccf32f" // free Anomalous Execution 1
	line := `{"action":"block","datetime":"2026-10-21T12:00:00Z","rule_id":"` + rule + `","clientRequestMethod":"POST","clientRequestPath":"/index.php","ray_id":"abcd"}` + "\n"
	p := writeTemp(t, dir, "snake.jsonl", line)
	r := NewReport("host", "linux", "amd64")
	leads := ScanWAFLog(r, p)
	if len(leads) != 1 || leads[0].Kind != "waf_php2shell_rule_match" {
		t.Fatalf("allowlisted rule_id must produce finding, got leads=%+v coverage=%+v", leads, r.WAFLogs)
	}
}

func TestWAFTruncationReportsTruncatedNotComplete(t *testing.T) {
	dir := t.TempDir()
	// Exceed lead cap with allowlisted RuleID lines so parsing hits Truncated notes.
	var b strings.Builder
	rule := "4e315666e8e344cdb64119a3b5ccf32f"
	for i := 0; i < wafLogMaxLeads+5; i++ {
		b.WriteString(`{"Action":"block","Datetime":"2026-10-21T12:00:00Z","RuleID":"` + rule + `","ClientRequestMethod":"GET","ClientRequestPath":"/x","RayID":"r` + string(rune('a'+(i%26))) + `"}` + "\n")
	}
	p := writeTemp(t, dir, "trunc.jsonl", b.String())
	r := NewReport("host", "linux", "amd64")
	_ = ScanWAFLog(r, p)
	if len(r.WAFLogs) != 1 {
		t.Fatal(r.WAFLogs)
	}
	if r.WAFLogs[0].Status != "TRUNCATED" {
		t.Fatalf("truncated WAF parse must be TRUNCATED, not %s (%s)", r.WAFLogs[0].Status, r.WAFLogs[0].Detail)
	}
	if !ScanIncomplete(r) {
		t.Fatal("TRUNCATED WAF coverage must mark ScanIncomplete")
	}
}

func TestWAFDoesNotInventContentLengthOrMultipart(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "demos", "waf", "cloudflare-firewall-php2shell-block.jsonl")
	r := NewReport("host", "linux", "amd64")
	_ = ScanWAFLog(r, path)
	detail := r.WAFLogs[0].Detail
	if !strings.Contains(detail, "Content-Length") || !strings.Contains(strings.ToLower(detail), "multipart") {
		t.Fatalf("coverage must state Content-Length/multipart are not in schema: %s", detail)
	}
	if strings.Contains(strings.ToLower(detail), "nested field") && strings.Contains(strings.ToLower(detail), "detected") {
		t.Fatal("must not claim nested field detection")
	}
}
