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
	fmt.Fprintln(p.out)
}

// Phase announces the current scan phase.
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
	fmt.Fprintf(p.out, "  PHP discovery:     %s\n", r.Summary.PHPDiscovery)
	fmt.Fprintf(p.out, "  Patch review:      %s\n", r.Summary.PatchReview)
	fmt.Fprintf(p.out, "  Compromise review: %s\n", r.Summary.CompromiseReview)
	fmt.Fprintf(p.out, "  Vulnerability:     %s\n", r.VulnerabilityStatus)
	fmt.Fprintf(p.out, "  Compromise:        %s\n", r.CompromiseStatus)
	fmt.Fprintf(p.out, "  Serving runtime:   %s\n", r.EffectiveWebRuntime)

	phpShown := 0
	for _, e := range r.Evidence {
		if e.Version == "" {
			continue
		}
		if phpShown == 0 {
			fmt.Fprintln(p.out, "  Detected versions (evidence, not attested runtime):")
		}
		if phpShown >= 8 {
			fmt.Fprintln(p.out, "    ... see HTML report for full evidence list")
			break
		}
		label := e.Name
		if label == "" {
			label = e.Type
		}
		fmt.Fprintf(p.out, "    - %s %s (%s)\n", label, e.Version, e.Type)
		phpShown++
	}
	if phpShown == 0 {
		fmt.Fprintln(p.out, "  Detected versions: none in this scan scope (absence is not proof)")
	}

	critical := 0
	for _, a := range r.PatchAssessments {
		if a.Priority != "CRITICAL" {
			continue
		}
		if critical == 0 {
			fmt.Fprintln(p.out, p.paint(yellow, "  Immediate patch review:"))
		}
		if critical >= 6 {
			fmt.Fprintln(p.out, "    ... additional assessments in the HTML/CSV reports")
			break
		}
		fmt.Fprintf(p.out, "    - %s %s: %s\n", a.Component, a.ObservedVersion, a.RequiredAction)
		critical++
	}

	incompleteCount := 0
	for _, c := range r.Coverage {
		switch strings.ToUpper(c.Status) {
		case "INCOMPLETE", "UNAVAILABLE", "TRUNCATED", "TIMEOUT":
			incompleteCount++
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
			case "INCOMPLETE", "UNAVAILABLE", "TRUNCATED", "TIMEOUT":
				fmt.Fprintf(p.out, "    - [%s] %s: %s\n", c.Status, c.Name, c.Detail)
				shown++
				if shown >= 8 {
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

// ColorEnabled reports whether ANSI sequences would be emitted (for tests).
func (p *Printer) ColorEnabled() bool { return p.color }
