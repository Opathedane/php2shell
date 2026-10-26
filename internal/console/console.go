package console

import (
	"fmt"
	"io"
	"os"
	"runtime"
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
	ForceTTY bool // tests only: pretend stdout/stderr are TTYs (skips VT probe)
	NoColor  bool // force plain text (--no-color / tests)
	Stdout   io.Writer
	Stderr   io.Writer
}

// Printer writes professional scan status without implying security clearance.
type Printer struct {
	opts     Options
	colorOut bool
	colorErr bool
	out      io.Writer
	errOut   io.Writer
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
	p.colorOut = p.shouldColor(out)
	p.colorErr = p.shouldColor(errOut)
	return p
}

func (p *Printer) shouldColor(w io.Writer) bool {
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
	if !isTerminal(w) {
		return false
	}
	// Windows: enable VT when possible; otherwise plain text (2012 R2 / legacy conhost).
	if runtime.GOOS == "windows" {
		f, ok := w.(*os.File)
		if !ok || !enableVirtualTerminal(f) {
			return false
		}
	}
	return true
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

func (p *Printer) paintOut(code, s string) string {
	if !p.colorOut {
		return s
	}
	return code + s + reset
}

func (p *Printer) paintErr(code, s string) string {
	if !p.colorErr {
		return s
	}
	return code + s + reset
}

// Banner prints tool identity. Safe for interactive use; suppressed when quiet.
func (p *Printer) Banner(version, goos, goarch, hostname string) {
	if p.opts.Quiet {
		return
	}
	fmt.Fprintln(p.out, p.paintOut(bold, "PHP2Shell Assessment")+" "+p.paintOut(dim, version))
	fmt.Fprintf(p.out, "Host: %s  OS: %s/%s\n", hostname, goos, goarch)
	fmt.Fprintln(p.out, p.paintOut(dim, "Read-only local scan. No PHP execution. No automatic remediation or data upload."))
	fmt.Fprintf(p.out, "%s Upstream fix thresholds: %s\n", p.paintOut(dim, "·"), audit.OfficialFixThresholdsSummary())
	fmt.Fprintf(p.out, "%s Advisory rules reviewed: %s (offline; not a live vulnerability feed)\n", p.paintOut(dim, "·"), audit.AdvisoryRulesReviewedUTC)
	fmt.Fprintln(p.out)
}

// Phase announces the current scan phase (only call for work that is actually running).
func (p *Printer) Phase(name string) {
	if p.opts.Quiet {
		return
	}
	fmt.Fprintf(p.out, "%s %s\n", p.paintOut(cyan, "==>"), name)
}

// Warn prints a significant warning to stderr (still shown when quiet).
func (p *Printer) Warn(msg string) {
	fmt.Fprintf(p.errOut, "%s %s\n", p.paintErr(yellow, "WARN:"), msg)
}

// Error prints a fatal error to stderr.
func (p *Printer) Error(msg string) {
	fmt.Fprintf(p.errOut, "%s %s\n", p.paintErr(red, "ERROR:"), msg)
}

// Summary prints end-of-scan operational status. Never claims a successful security clearance.
func (p *Printer) Summary(r *audit.Report, htmlPath, csvPath string, elapsed time.Duration, incomplete bool) {
	if p.opts.Quiet {
		return
	}
	fmt.Fprintln(p.out)
	fmt.Fprintln(p.out, p.paintOut(bold, "Scan summary"))

	phpLabel, versions := audit.HumanPHPDetected(r)
	fmt.Fprintf(p.out, "  PHP discovery:     %s\n", phpLabel)
	fmt.Fprintf(p.out, "  Patch assessment:  %s\n", audit.HumanVulnerabilityLabelFor(r))
	fmt.Fprintf(p.out, "  Overall priority:  %s\n", audit.OverallPriority(r))
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
	if cov := audit.CountBinaryInstallCoverage(r); cov.BinaryCandidates > 0 {
		fmt.Fprintf(p.out, "  Binary coverage:   %d candidate(s); %d verified metadata, %d path-inferred, %d without comparable version (path-inferred ≠ confirmed install / active runtime)\n",
			cov.BinaryCandidates, cov.Verified, cov.PathInferred, cov.VersionUnknown)
	}

	groups := audit.GroupInstallations(r)
	if len(groups) > 0 {
		fmt.Fprintln(p.out, "  Installation review:")
		for i, g := range groups {
			if i >= 6 {
				fmt.Fprintln(p.out, "    ... see HTML report for additional installations")
				break
			}
			fmt.Fprintf(p.out, "    - %s: %s\n", g.Label, g.StatusLabel)
			if g.Priority == "CRITICAL" || g.Status == "BELOW_UPSTREAM_FIX" || g.Status == "LEGACY_VENDOR_VERIFICATION_REQUIRED" {
				action := ""
				for _, a := range g.Assessments {
					if a.RequiredAction != "" {
						action = a.RequiredAction
						break
					}
				}
				if action != "" {
					fmt.Fprintf(p.out, "      Action: %s\n", truncateConsole(action, 140))
				}
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
			audit.HumanExploitationAttemptLabel(r.ExploitationAttemptStatus),
			audit.HumanPossibleCompromiseLabel(r.PossibleCompromiseStatus))
	}

	next := r.Summary.NextSteps
	if len(next) == 0 {
		next = audit.BuildFocusedNextSteps(r)
	}
	if len(next) > 0 {
		fmt.Fprintf(p.out, "  Recommended next:  %s\n", truncateConsole(next[0], 220))
	}

	incompleteCount := 0
	for _, c := range r.Coverage {
		switch strings.ToUpper(c.Status) {
		case "INCOMPLETE", "UNAVAILABLE", "TRUNCATED", "TIMEOUT", "ACCESS_DENIED":
			incompleteCount++
		}
	}
	// Linux-centric package DB note only — never on Windows (packages=NOT_SUPPORTED is expected).
	if audit.ShouldWarnPackageDBNotSupported(r) {
		fmt.Fprintln(p.out, p.paintOut(yellow, "  Coverage note:    OS package DB not inventoried (no dpkg/apk). On RPM hosts, rely on binary/PATH discovery and vendor advisories."))
	}
	if incomplete || incompleteCount > 0 || len(r.Warnings) > 0 {
		fmt.Fprintln(p.out, p.paintOut(yellow, "  Warnings / incomplete checks:"))
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
	fmt.Fprintln(p.out, p.paintOut(dim, "Process completion is not a vulnerability or compromise clearance."))
	fmt.Fprintln(p.out, p.paintOut(dim, "Open the HTML report for findings; use CSV for fleet consolidation."))
	if incomplete {
		fmt.Fprintln(p.out, p.paintOut(yellow, "Scan finished with incomplete coverage (exit code 2)."))
	}
}

func truncateConsole(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// ColorEnabled reports whether ANSI sequences would be emitted on stdout (for tests).
func (p *Printer) ColorEnabled() bool { return p.colorOut }

// ErrColorEnabled reports whether ANSI sequences would be emitted on stderr (for tests).
func (p *Printer) ErrColorEnabled() bool { return p.colorErr }
