package audit

import (
	"encoding/json"
	"time"
)

const Schema = "php2shell-assessment/v1"
const Version = "2.4.0"

type Evidence struct {
	Type           string `json:"type"`
	Name           string `json:"name,omitempty"`
	Version        string `json:"version,omitempty"`
	Source         string `json:"source"`
	Location       string `json:"location,omitempty"`
	Detail         string `json:"detail,omitempty"`
	Interpretation string `json:"interpretation"`
}

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type LogCoverage struct {
	File           string         `json:"file"`
	Status         string         `json:"status"`
	Lines          int            `json:"lines"`
	ParsedRequests int            `json:"parsed_requests"`
	FirstTimestamp string         `json:"first_timestamp,omitempty"`
	LastTimestamp  string         `json:"last_timestamp,omitempty"`
	Methods        map[string]int `json:"methods,omitempty"`
	StatusClasses  map[string]int `json:"http_status_classes,omitempty"`
	Detail         string         `json:"detail,omitempty"`
	MatchedRules   int            `json:"matched_rules,omitempty"`
}

type RepoCoverage struct {
	Root           string `json:"root"`
	Status         string `json:"status"`
	InspectedFiles int    `json:"inspected_files"`
	SkippedFiles   int    `json:"skipped_files"`
	Detail         string `json:"detail,omitempty"`
}

type IndicatorFinding struct {
	RuleID     string `json:"rule_id"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
	Location   string `json:"location"`
	Detail     string `json:"detail"`
}

type Report struct {
	Schema              string             `json:"schema"`
	ToolVersion         string             `json:"tool_version"`
	GeneratedUTC        time.Time          `json:"generated_utc"`
	Hostname            string             `json:"hostname"`
	OS                  string             `json:"os"`
	Architecture        string             `json:"architecture"`
	CVEs                []string           `json:"cves"`
	CustomerLabel       string             `json:"customer_label,omitempty"`
	VulnerabilityStatus string             `json:"vulnerability_status"`
	CompromiseStatus    string             `json:"compromise_status"`
	EffectiveWebRuntime string             `json:"effective_web_runtime"`
	Evidence            []Evidence         `json:"evidence"`
	Summary             ReviewSummary      `json:"summary"`
	PatchAssessments    []PatchAssessment  `json:"patch_assessments"`
	Coverage            []Check            `json:"coverage"`
	Repositories        []RepoCoverage     `json:"repositories,omitempty"`
	Logs                []LogCoverage      `json:"logs,omitempty"`
	RuleSequence        uint64             `json:"rule_sequence,omitempty"`
	RuleCount           int                `json:"rule_count,omitempty"`
	Findings            []IndicatorFinding `json:"indicator_findings,omitempty"`
	Warnings            []string           `json:"warnings"`
	RecommendedActions  []string           `json:"recommended_actions"`

	// aliasDirs maps a corroborated alias install directory (e.g. ...\PHP\current)
	// to a canonical versioned directory. Not serialized; used only while building
	// patch assessments after ReconcileBinaryInstallAliases.
	aliasDirs map[string]string
}

func NewReport(host, osname, arch string) *Report {
	return &Report{
		Schema: Schema, ToolVersion: Version, GeneratedUTC: time.Now().UTC(),
		Hostname: host, OS: osname, Architecture: arch,
		CVEs:                []string{"CVE-2026-109618", "CVE-2026-109619"},
		VulnerabilityStatus: "NOT_VERIFIED", CompromiseStatus: "NOT_ASSESSED",
		EffectiveWebRuntime: "NOT_VERIFIED",
		Evidence:            []Evidence{}, Coverage: []Check{}, Warnings: []string{},
		RecommendedActions: []string{
			"Identify and patch the actively serving PHP SAPI using official vendor advisories; check vendor backports.",
			"Validate deployment/restart and investigate other containers, vhosts and PHP runtimes.",
			"Treat WAF, origin access controls, and disabled upload progress as risk-reduction only, not proof of patching.",
			"Review retained access/error logs and EDR/SIEM evidence with validated rules; this tool cannot exclude past compromise.",
			"Verify that edge/WAF controls cannot be bypassed by reaching the origin directly.",
		},
	}
}

func (r *Report) AddCheck(name, status, detail string) {
	r.Coverage = append(r.Coverage, Check{name, status, detail})
}
func (r *Report) AddEvidence(e Evidence) { r.Evidence = append(r.Evidence, e) }
func (r *Report) AddWarning(w string)    { r.Warnings = append(r.Warnings, w) }
func (r *Report) AddAction(action string) {
	for _, previous := range r.RecommendedActions {
		if previous == action {
			return
		}
	}
	r.RecommendedActions = append(r.RecommendedActions, action)
}

func ParseReport(b []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if !validReportSchema(r.Schema) || r.ToolVersion == "" || r.VulnerabilityStatus == "" || r.CompromiseStatus == "" || r.GeneratedUTC.IsZero() {
		return nil, ErrInvalidReport
	}
	return &r, nil
}

func validReportSchema(schema string) bool {
	switch schema {
	case Schema, "php2shell-assessment/standalone-preview-v1":
		return true
	default:
		return false
	}
}
