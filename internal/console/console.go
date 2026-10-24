package console

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Opathedane/php2shell/internal/audit"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	cyan   = "\033[36m"
	yellow = "\033[33m"
	red    = "\033[31m"
)

// Options control console rendering for interactive vs unattended runs.
type Options struct {
	Quiet    bool
	ForceTTY bool // tests only: pretend stdout is a TTY
	NoColor  bool // force plain text
	Stdout   io.Writer
	Stderr   io.Writer
}

// Printer writes professional scan status without implying security clearance.
type Printer struct {
	opts   Options
	color  bool
	out    io.Writer
	errOut io.Writer
}

func New(opts Options) *Printer {
	out := opts.Stdout
	if out == nil {
		out = os.Stdout
	}
	errOut := opts.Stderr
	if errOut == nil {
		errOut = os.Stderr
	}
	p := &Printer{opts: opts, out: out, errOut: errOut}
	p.color = p.shouldColor()
	return p
}

func (p *Printer) shouldColor() bool {
	if p.opts.Quiet || p.opts.NoColor {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	if os.Getenv("CI") != "" && !p.opts.ForceTTY {
		return false
	}
	if p.opts.ForceTTY {
		return true
	}
	return isTerminal(p.out)
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func (p *Printer) paint(code, s string) string {
	if !p.color {
		return s
	}
	return code + s + reset
}

// Banner prints tool identity. Safe for interactive use; suppressed when quiet.
func (p *Printer) Banner(version, goos, goarch, hostname string) {
	if p.opts.Quiet {
		return
	}
	fmt.Fprintln(p.out, p.paint(bold, "PHP2Shell Assessment")+" "+p.paint(dim, version))
	fmt.Fprintf(p.out, "Host: %s  OS: %s/%s\n", hostname, goos, goarch)
	fmt.Fprintln(p.out, p.paint(dim, "Read-only local scan. No PHP execution. No automatic remediation or data upload."))
	fmt.Fprintf(p.out, "%s Upstream fix thresholds: %s\n", p.paint(dim, "·"), audit.OfficialFixThresholdsSummary())
	fmt.Fprintf(p.out, "%s Advisory rules reviewed: %s (offline; not a live vulnerability feed)\n", p.paint(dim, "·"), audit.AdvisoryRulesReviewedUTC)
	fmt.Fprintln(p.out)
}

// Phase announces the current scan phase (only call for work that is actually running).
func (p *Printer) Phase(name string) {
	if p.opts.Quiet {
		return
	}
	fmt.Fprintf(p.out, "%s %s\n", p.paint(cyan, "==>"), name)
}

// Warn prints a significant warning to stderr (still shown when quiet).
func (p *Printer) Warn(msg string) {
	fmt.Fprintf(p.errOut, "%s %s\n", p.paint(yellow, "WARN:"), msg)
}

// Error prints a fatal error to stderr.
func (p *Printer) Error(msg string) {
	fmt.Fprintf(p.errOut, "%s %s\n", p.paint(red, "ERROR:"), msg)
}

// Summary prints end-of-scan operational status. Never claims a successful security clearance.
func (p *Printer) Summary(r *audit.Report, htmlPath, csvPath string, elapsed time.Duration, incomplete bool) {
	if p.opts.Quiet {
		return
	}
	fmt.Fprintln(p.out)
	fmt.Fprintln(p.out, p.paint(bold, "Scan summary"))

	phpLabel, versions := audit.HumanPHPDetected(r)
	fmt.Fprintf(p.out, "  PHP discovery:     %s\n", phpLabel)
	fmt.Fprintf(p.out, "  Patch assessment:  %s\n", audit.HumanVulnerabilityLabel(r.VulnerabilityStatus))
	rtLabel, rtDetail := audit.HumanRuntime(r)
	fmt.Fprintf(p.out, "  Serving runtime:   %s — %s\n", rtLabel, truncateConsole(rtDetail, 120))

	if len(versions) > 0 {
		fmt.Fprintf(p.out, "  Observed versions: %s\n", strings.Join(versions, ", "))
		fmt.Fprintf(p.out, "  Upstream fixes:    %s\n", audit.OfficialFixThresholdsSummary())
		shownLife := map[string]bool{}
		for _, ver := range versions {
			note := audit.PHPLifecycleNote(ver)
			if note == "" || shownLife[note] {
				continue
			}
			shownLife[note] = true
			fmt.Fprintf(p.out, "  Lifecycle:         %s\n", note)
			if len(shownLife) >= 3 {
				break
			}
		}
	} else {
		fmt.Fprintln(p.out, "  Observed versions: none in this scan scope (absence is not proof PHP is missing)")
	}

	// Group patch assessments by install/version for readability.
	type grp struct {
		ver, status, action string
		priority            string
	}
	byKey := map[string]*grp{}
	var order []string
	for _, a := range r.PatchAssessments {
		key := a.InstallKey
		if key == "" {
			key = a.ObservedVersion + "|" + a.Status
		}
		if _, ok := byKey[key]; !ok {
			byKey[key] = &grp{ver: a.ObservedVersion, status: a.Status, action: a.RequiredAction, priority: a.Priority}
			order = append(order, key)
		}
	}
	if len(order) > 0 {
		fmt.Fprintln(p.out, "  Installation review:")
		for i, key := range order {
			if i >= 6 {
				fmt.Fprintln(p.out, "    ... see HTML report for additional installations")
				break
			}
			g := byKey[key]
			label := g.ver
			if label == "" {
				label = "(version unknown)"
			}
			fmt.Fprintf(p.out, "    - PHP %s: %s\n", label, audit.HumanPatchStatusLabel(g.status))
			if g.priority == "CRITICAL" || g.status == "BELOW_UPSTREAM_FIX" || g.status == "LEGACY_VENDOR_VERIFICATION_REQUIRED" {
				fmt.Fprintf(p.out, "      Action: %s\n", truncateConsole(g.action, 140))
			}
		}
	}

	if len(r.AdditionalAdvisories) > 0 {
		fmt.Fprintln(p.out, "  Additional advisories:")
		for _, a := range r.AdditionalAdvisories {
			fmt.Fprintf(p.out, "    - %s: %s\n", a.CVE, audit.HumanAdvisoryStatusLabel(a.Status))
		}
	}

	invRequested := false
	for _, c := range r.Coverage {
		if strings.HasPrefix(c.Name, "historical_") || c.Name == "compromise_investigation" || c.Name == "waf_log_investigation" {
			if !strings.EqualFold(c.Status, "NOT_REQUESTED") {
				invRequested = true
				break
			}
		}
	}
	if invRequested || (r.ExploitationAttemptStatus != "" && r.ExploitationAttemptStatus != "NOT_ASSESSED") {
		fmt.Fprintf(p.out, "  Investigation:     attempts=%s; possible-compromise=%s (not a clearance)\n",
			r.ExploitationAttemptStatus, r.PossibleCompromiseStatus)
	}

	incompleteCount := 0
	for _, c := range r.Coverage {
		switch strings.ToUpper(c.Status) {
		case "INCOMPLETE", "UNAVAILABLE", "TRUNCATED", "TIMEOUT", "ACCESS_DENIED":
			incompleteCount++
		}
	}
	// Highlight RPM / package inventory gap when relevant.
	for _, c := range r.Coverage {
		if c.Name == "packages" && strings.EqualFold(c.Status, "NOT_SUPPORTED") {
			fmt.Fprintln(p.out, p.paint(yellow, "  Coverage note:    OS package DB not inventoried (no dpkg/apk). On RPM hosts, rely on binary/PATH discovery and vendor advisories."))
			break
		}
	}
	if incomplete || incompleteCount > 0 || len(r.Warnings) > 0 {
		fmt.Fprintln(p.out, p.paint(yellow, "  Warnings / incomplete checks:"))
		for _, w := range r.Warnings {
			fmt.Fprintf(p.out, "    - %s\n", w)
		}
		shown := 0
		for _, c := range r.Coverage {
			switch strings.ToUpper(c.Status) {
			case "INCOMPLETE", "UNAVAILABLE", "TRUNCATED", "TIMEOUT", "ACCESS_DENIED":
				fmt.Fprintf(p.out, "    - [%s] %s\n", c.Status, c.Name)
				shown++
				if shown >= 6 {
					fmt.Fprintln(p.out, "    ... see HTML/CSV coverage details")
					goto afterWarn
				}
			}
		}
	afterWarn:
	}

	fmt.Fprintf(p.out, "  Duration:          %s\n", elapsed.Round(time.Millisecond))
	fmt.Fprintf(p.out, "  HTML report:       %s\n", htmlPath)
	if csvPath != "" {
		fmt.Fprintf(p.out, "  CSV report:        %s\n", csvPath)
	}
	fmt.Fprintln(p.out)
	fmt.Fprintln(p.out, p.paint(dim, "Process completion is not a vulnerability or compromise clearance."))
	fmt.Fprintln(p.out, p.paint(dim, "Open the HTML report for findings; use CSV for fleet consolidation."))
	if incomplete {
		fmt.Fprintln(p.out, p.paint(yellow, "Scan finished with incomplete coverage (exit code 2)."))
	}
}

func truncateConsole(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// ColorEnabled reports whether ANSI sequences would be emitted (for tests).
func (p *Printer) ColorEnabled() bool { return p.color }
