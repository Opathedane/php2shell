package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"example.org/php2shell-assessment/internal/audit"
)

type paths []string

func (p *paths) String() string { return strings.Join(*p, ",") }
func (p *paths) Set(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("empty path")
	}
	*p = append(*p, s)
	return nil
}

const help = `PHP2Shell Assessment (standalone preview)

No PHP execution. No network scanning. No exploit tests. No customer data upload.
This build DOES NOT verify vulnerability status or past compromise.

Usage:
  php2shell doctor
  php2shell scan [--webroot DIR] [--repo DIR] [--access-log FILE] [--docker] [--out PREFIX]
  php2shell rollup [--tenant-map JSON] --out FILE.csv REPORT.json [REPORT.json ...]
  php2shell version

Examples:
  php2shell scan --out reports/my-webserver
  php2shell scan --webroot /var/www --access-log /var/log/nginx/access.log --out reports/server-1
  php2shell scan --repo /srv/project --out reports/project-1
  php2shell rollup --tenant-map /private/tenant-map.json --out reports/fleet.csv reports/server-1.json

Each scan creates PREFIX.json, PREFIX.csv and PREFIX.html, never overwrites files.
Read the limitations in README.md. Run only on authorized systems.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(help)
		return nil
	}
	switch args[0] {
	case "help", "--help", "-h":
		fmt.Print(help)
		return nil
	case "version":
		fmt.Printf("php2shell %s %s/%s\n", audit.Version, runtime.GOOS, runtime.GOARCH)
		return nil
	case "doctor":
		fmt.Printf("PHP2Shell standalone %s (%s/%s)\nNo Python or PHP required. No external modules.\n", audit.Version, runtime.GOOS, runtime.GOARCH)
		fmt.Println("Host metadata: best-effort; Linux dpkg/apk and /proc; macOS/Windows partial.")
		fmt.Println("Runtime patch verification: NOT IMPLEMENTED. CVE compromise detector: NOT IMPLEMENTED.")
		fmt.Println("Default: offline, no code execution, reports written only to local files.")
		return nil
	case "scan":
		fs := flag.NewFlagSet("scan", flag.ContinueOnError)
		webroot := fs.String("webroot", "", "authorized website document root (file names only)")
		out := fs.String("out", "", "private output prefix; auto-generate if omitted; fail if exists")
		customer := fs.String("customer", "", "optional self-declared label; not authenticated tenant")
		docker := fs.Bool("docker", false, "read local privileged Unix Docker API container metadata (opt-in)")
		var repos, logs paths
		fs.Var(&repos, "repo", "authorized local repo; repeatable")
		fs.Var(&logs, "access-log", "local HTTP access log; repeatable; limit 32MiB")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected arguments; use --repo PATH or --access-log PATH")
		}
		if len(repos) > 20 || len(logs) > 20 {
			return fmt.Errorf("limit is 20 repositories and 20 log files per scan")
		}
		name, _ := os.Hostname()
		r := audit.NewReport(name, runtime.GOOS, runtime.GOARCH)
		r.CustomerLabel = *customer
		audit.ScanHost(r, *webroot, *docker)
		for _, p := range repos {
			audit.ScanRepository(r, p)
		}
		if len(repos) == 0 {
			r.AddCheck("repositories", "NOT_REQUESTED", "Use --repo PATH to inspect static PHP declarations; not proof of deployment")
		} else {
			status := "PARTIAL"
			for _, repo := range r.Repositories {
				if repo.Status == "UNAVAILABLE" || repo.Status == "TRUNCATED" {
					status = "INCOMPLETE"
					break
				}
			}
			r.AddCheck("repositories", status, fmt.Sprintf("Requested %d repositories; see detailed coverage; declarations are not deployed runtimes", len(repos)))
		}
		for _, p := range logs {
			audit.ScanAccessLog(r, p)
		}
		if len(logs) == 0 {
			r.AddCheck("historical_access_logs", "NOT_REQUESTED", "Use --access-log PATH to summarize bounded logs; no CVE-specific signature checks")
		} else {
			status := "SUMMARIZED_NO_IOCS"
			for _, log := range r.Logs {
				if log.Status != "SUMMARIZED_NO_IOCS" {
					status = "INCOMPLETE"
					break
				}
			}
			r.AddCheck("historical_access_logs", status, fmt.Sprintf("Requested %d log files; see detailed coverage; no CVE-specific indicators", len(logs)))
		}
		if *out == "" {
			*out = fmt.Sprintf("reports/assessment-%s-%d", time.Now().UTC().Format("20060102T150405Z"), os.Getpid())
		}
		if err := audit.Save(r, *out); err != nil {
			return err
		}
		fmt.Printf("Assessment saved: %s.json, %s.csv, %s.html\n", *out, *out, *out)
		fmt.Printf("Evidence observations: %d | Vulnerability: %s | Compromise: %s | Serving runtime: %s\n", len(r.Evidence), r.VulnerabilityStatus, r.CompromiseStatus, r.EffectiveWebRuntime)
		fmt.Println("IMPORTANT: No exploit check or verified PHP2Shell compromise analysis has been performed. Review coverage and warnings.")
		return nil
	case "rollup":
		fs := flag.NewFlagSet("rollup", flag.ContinueOnError)
		out := fs.String("out", "reports/rollup.csv", "exclusive output CSV path")
		m := fs.String("tenant-map", "", "optional JSON object: SHA-256 of exact report file to trusted tenant")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := audit.Rollup(fs.Args(), *m, *out); err != nil {
			return err
		}
		fmt.Printf("MSSP rollup saved: %s (reports are NOT authenticated; unmapped tenant identifiers remain UNMAPPED)\n", *out)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], help)
	}
}
