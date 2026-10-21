package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Opathedane/php2shell/internal/audit"
	"github.com/Opathedane/php2shell/internal/console"
	"github.com/Opathedane/php2shell/internal/rules"
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

const help = `PHP2Shell Security Assessment

No PHP execution. No network scanning. No exploit tests. No customer data upload.
No automatic remediation or browser opening. Reports official upstream patch-level
comparisons but cannot attest the serving SAPI or exclude compromise.

Usage:
  php2shell doctor
  php2shell scan [options]
  php2shell rules trust --key trusted-public.hex
  php2shell rules update --url https://raw.githubusercontent.com/Opathedane/php2shell/main/rules/signed.json
  php2shell rules status
  php2shell rules keygen --out-dir PRIVATE-KEY-DIRECTORY
  php2shell rules sign --input rules/source.json --private PRIVATE.hex --out rules/signed.json
  php2shell rollup --out FILE.csv [--input-dir DIR] [REPORT.csv ...]
  php2shell rollup --format json [--tenant-map JSON] --out FILE.csv REPORT.json [...]
  php2shell version

Scan options:
  --webroot DIR          authorized website document root (file names only)
  --php-ini PATH         inspect an explicit php.ini (or .ini) path (repeatable; limit 32)
  --config-root DIR      bounded PHP binary + php.ini/conf.d inspection under DIR (repeatable; limit 8; no drive walk)
  --repo DIR             authorized local repo (repeatable)
  --access-log FILE      local HTTP access log (repeatable; limit 32MiB)
  --docker               local privileged Docker API metadata (opt-in)
  --output-dir DIR       directory for HTML+CSV reports (local or UNC if accessible)
  --out PATH             explicit HTML path or prefix (overrides --output-dir); matching .csv is written beside it
  --quiet                unattended mode: no progress, no ANSI, stdout silent on success
  --timeout DURATION     wall-clock budget (e.g. 30m); incomplete scan exits 2
  --customer LABEL       optional self-declared label (not authenticated tenancy)
  --runtime-version VER  operator-supplied WEB runtime (with --runtime-sapi and --runtime-source)
  --rules PATH           local Ed25519-signed indicator bundle
  --update-rules         opt-in download signed rules (requires --rules-url)

Default report directory:
  Windows: C:\ProgramData\PHP2Shell\Reports
  Unix:    $HOME/.php2shell/reports (or /var/tmp/php2shell/reports if HOME unset)

Each scan writes a matching pair:
  php2shell-<hostname>-<timestamp>.html
  php2shell-<hostname>-<timestamp>.csv
Existing reports are never overwritten. If either file cannot be written, the pair is not left half-complete.

Exit codes:
  0  scan finished and HTML+CSV written (findings may exist; not a clearance)
  1  fatal tool, configuration, or report write failure
  2  report pair written but scan incomplete (permissions, truncation, timeout)

Examples:
  php2shell scan
  php2shell scan --output-dir \\fileserver\php2shell$\fleet --quiet
  php2shell scan --webroot /var/www --access-log /var/log/nginx/access.log
  php2shell scan --out reports/customer-check.html
  php2shell rollup --input-dir ./server-reports --out ./customer-summary.csv

Read the limitations in README.md. Run only on authorized systems.
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Print(help)
		return audit.ExitOK
	}
	switch args[0] {
	case "help", "--help", "-h":
		fmt.Print(help)
		return audit.ExitOK
	case "rules":
		if err := runRules(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			return audit.ExitFatal
		}
		return audit.ExitOK
	case "version":
		fmt.Printf("php2shell %s %s/%s\n", audit.Version, runtime.GOOS, runtime.GOARCH)
		return audit.ExitOK
	case "doctor":
		fmt.Printf("PHP2Shell %s (%s/%s)\nNo Python or PHP required. No external modules.\n", audit.Version, runtime.GOOS, runtime.GOARCH)
		fmt.Println("Host metadata: best-effort; Linux dpkg/apk and /proc; macOS/Windows partial.")
		fmt.Println("Official upstream PHP2Shell fix thresholds: AVAILABLE. Web-runtime patch attestation: NOT IMPLEMENTED.")
		fmt.Println("Signed indicator packs: manually trusted Ed25519 key; no automatic internet access.")
		fmt.Println("Default: offline, no code execution, HTML+CSV report pair, no automatic browser or upload.")
		fmt.Println("Exit codes: 0=report pair written, 1=fatal error, 2=report pair written but incomplete.")
		fmt.Println("Not a clearance: missing findings do not prove a host is patched or uncompromised.")
		return audit.ExitOK
	case "scan":
		return runScan(args[1:])
	case "rollup":
		return runRollup(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "ERROR: unknown command %q\n%s", args[0], help)
		return audit.ExitFatal
	}
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	webroot := fs.String("webroot", "", "authorized website document root (file names only)")
	out := fs.String("out", "", "explicit HTML path or prefix; matching .csv written beside it; overrides --output-dir")
	outputDir := fs.String("output-dir", "", "directory for unique HTML+CSV report pair (local or accessible UNC)")
	quiet := fs.Bool("quiet", false, "unattended: no progress, no ANSI; stdout silent on success")
	timeoutStr := fs.String("timeout", "", "wall-clock scan budget (e.g. 30m)")
	customer := fs.String("customer", "", "optional self-declared label; not authenticated tenant")
	runtimeVersion := fs.String("runtime-version", "", "operator-supplied WEB runtime PHP version; requires --runtime-sapi and --runtime-source; NOT independently verified")
	runtimeSAPI := fs.String("runtime-sapi", "", "web SAPI of operator-reported version, e.g. fpm, apache/mod_php, cgi, litespeed")
	runtimeSource := fs.String("runtime-source", "", "human-readable evidence provenance for operator-reported WEB runtime; NOT attestation")
	docker := fs.Bool("docker", false, "read local privileged Unix Docker API container metadata (opt-in)")
	updateRules := fs.Bool("update-rules", false, "opt-in download signed indicator rules; requires --rules-url and previously trusted key")
	rulesURL := fs.String("rules-url", "", "trusted signed rule bundle HTTPS URL")
	signedRules := fs.String("rules", "", "local Ed25519-signed bundle; requires previously trusted key")
	var repos, logs, phpInis, configRoots paths
	fs.Var(&repos, "repo", "authorized local repo; repeatable")
	fs.Var(&logs, "access-log", "local HTTP access log; repeatable; limit 32MiB")
	fs.Var(&phpInis, "php-ini", "inspect an explicit php.ini path; repeatable; limit 32; not version/runtime authority")
	fs.Var(&configRoots, "config-root", "bounded PHP binary + php.ini/conf.d under DIR; repeatable; limit 8; no drive walk")
	if err := fs.Parse(args); err != nil {
		return audit.ExitFatal
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "ERROR: unexpected arguments; use --repo PATH, --access-log PATH, --php-ini PATH, or --config-root DIR")
		return audit.ExitFatal
	}
	if (*runtimeVersion != "" || *runtimeSAPI != "" || *runtimeSource != "") && (*runtimeVersion == "" || *runtimeSAPI == "" || *runtimeSource == "") {
		fmt.Fprintln(os.Stderr, "ERROR: --runtime-version, --runtime-sapi and --runtime-source must be supplied together")
		return audit.ExitFatal
	}
	if len(*runtimeVersion) > 60 || len(*runtimeSAPI) > 80 || len(*runtimeSource) > 256 {
		fmt.Fprintln(os.Stderr, "ERROR: runtime evidence fields too long")
		return audit.ExitFatal
	}
	if len(repos) > 20 || len(logs) > 20 {
		fmt.Fprintln(os.Stderr, "ERROR: limit is 20 repositories and 20 log files per scan")
		return audit.ExitFatal
	}
	if len(phpInis) > 32 {
		fmt.Fprintln(os.Stderr, "ERROR: limit is 32 --php-ini paths per scan")
		return audit.ExitFatal
	}
	if len(configRoots) > 8 {
		fmt.Fprintln(os.Stderr, "ERROR: limit is 8 --config-root directories per scan")
		return audit.ExitFatal
	}
	var timeout time.Duration
	if strings.TrimSpace(*timeoutStr) != "" {
		var err error
		timeout, err = time.ParseDuration(*timeoutStr)
		if err != nil || timeout <= 0 {
			fmt.Fprintln(os.Stderr, "ERROR: invalid --timeout; use a positive duration such as 30m")
			return audit.ExitFatal
		}
	}

	started := time.Now()
	name, _ := os.Hostname()
	con := console.New(console.Options{Quiet: *quiet})
	con.Banner(audit.Version, runtime.GOOS, runtime.GOARCH, name)

	r := audit.NewReport(name, runtime.GOOS, runtime.GOARCH)
	r.CustomerLabel = *customer

	var deadline time.Time
	if timeout > 0 {
		deadline = started.Add(timeout)
	}
	timedOut := false
	checkTimeout := func() bool {
		if timeout <= 0 || timedOut {
			return timedOut
		}
		if time.Now().After(deadline) {
			timedOut = true
			r.AddCheck("scan_timeout", "TIMEOUT", "Wall-clock scan budget exhausted; remaining phases skipped")
			r.AddWarning("Scan timeout reached; report coverage may be incomplete")
			con.Warn("Scan timeout reached; finishing with available evidence")
			return true
		}
		return false
	}

	var indicators []rules.Indicator
	if !checkTimeout() {
		con.Phase("Loading indicator rules")
		if *updateRules {
			key, e := rules.InstalledPublic()
			if e != nil {
				con.Error("rules update requires trusted Ed25519 public key: " + e.Error())
				return audit.ExitFatal
			}
			if *rulesURL == "" {
				con.Error("--update-rules requires --rules-url HTTPS_URL")
				return audit.ExitFatal
			}
			payload, e := rules.FetchHTTPS(*rulesURL)
			if e != nil {
				con.Error("rules update failed: " + e.Error())
				return audit.ExitFatal
			}
			if _, e = rules.InstallSigned(payload, key); e != nil {
				con.Error("rule verification/update failed: " + e.Error())
				return audit.ExitFatal
			}
		} else if *rulesURL != "" {
			con.Error("--rules-url needs --update-rules")
			return audit.ExitFatal
		}
		var bundle *rules.Bundle
		if *signedRules != "" {
			key, e := rules.InstalledPublic()
			if e != nil {
				con.Error("no trusted rule key: " + e.Error())
				return audit.ExitFatal
			}
			bundle, e = rules.LoadSignedPath(*signedRules, key)
			if e != nil {
				con.Error("invalid signed rules: " + e.Error())
				return audit.ExitFatal
			}
		} else {
			var e error
			bundle, e = rules.LoadCached()
			if e != nil {
				r.AddCheck("signed_indicator_rules", "NOT_LOADED", "No trusted unexpired rule bundle available: "+e.Error())
				r.AddWarning("IOC analysis not available: no trusted unexpired rule bundle. Inventory still runs.")
			}
		}
		if bundle != nil {
			indicators = bundle.Indicators
			r.RuleSequence = bundle.Sequence
			r.RuleCount = len(bundle.Indicators)
			r.AddCheck("signed_indicator_rules", "VERIFIED", fmt.Sprintf("Signed Ed25519 bundle sequence %d with %d validated data-only indicators", bundle.Sequence, len(bundle.Indicators)))
		}
	}

	if !checkTimeout() {
		con.Phase("Host and PHP inventory")
		audit.ScanHost(r, audit.HostScanOptions{
			Webroot:     *webroot,
			Docker:      *docker,
			PHPIniPaths: phpInis,
			ConfigRoots: configRoots,
		})
		if *runtimeVersion != "" {
			r.AddEvidence(audit.Evidence{Type: "operator_reported_web_runtime", Name: *runtimeSAPI, Version: *runtimeVersion, Source: "operator-supplied serving runtime statement: " + *runtimeSource, Interpretation: "UNVERIFIED_OPERATOR_ASSERTION_NO_ACTIVE_RUNTIME_ATTESTATION"})
			r.EffectiveWebRuntime = "OPERATOR_REPORTED_NOT_ATTESTED"
		}
	}

	if !checkTimeout() {
		con.Phase("Repository declarations")
		for _, p := range repos {
			if checkTimeout() {
				break
			}
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
	}

	if !checkTimeout() {
		con.Phase("Access logs and file indicators")
		for _, p := range logs {
			if checkTimeout() {
				break
			}
			audit.ScanAccessLogWithIndicators(r, p, indicators)
		}
		audit.ScanFileHashes(r, *webroot, indicators)
		if len(r.Findings) > 0 {
			r.CompromiseStatus = "INDICATORS_MATCHED_REVIEW_REQUIRED"
		} else if len(indicators) > 0 && (len(logs) > 0 || *webroot != "") {
			r.CompromiseStatus = "NO_MATCHES_SCOPE_LIMITED"
		}
		if len(logs) == 0 {
			r.AddCheck("historical_access_logs", "NOT_REQUESTED", "Use --access-log PATH to summarize bounded logs; no CVE-specific signature checks")
		} else {
			status := "SUMMARIZED_NO_IOCS"
			if len(indicators) > 0 {
				status = "RULES_APPLIED_COVERAGE_LIMITED"
			}
			for _, log := range r.Logs {
				if log.Status != "SUMMARIZED_NO_IOCS" && log.Status != "RULES_APPLIED_COVERAGE_LIMITED" {
					status = "INCOMPLETE"
					break
				}
			}
			r.AddCheck("historical_access_logs", status, fmt.Sprintf("Requested %d log files; see detailed coverage. Matched indicators require validation, and missing matches do not prove safety", len(logs)))
		}
	}

	if !checkTimeout() {
		con.Phase("Patch assessment")
		audit.EvaluatePatchPosture(r)
	}

	con.Phase("Writing HTML and CSV reports")
	audit.FinalizeSummary(r)

	htmlPath, csvPath, err := audit.ResolveScanReportPair(*out, *outputDir, name, time.Now().UTC())
	if err != nil {
		con.Error(err.Error())
		return audit.ExitFatal
	}
	saveErr := audit.SaveReportPair(r, htmlPath, csvPath)
	if saveErr != nil {
		con.Error("cannot write report pair: " + saveErr.Error())
		return audit.ExitFatal
	}

	incomplete := audit.ScanIncomplete(r)
	elapsed := time.Since(started)
	con.Summary(r, htmlPath, csvPath, elapsed, incomplete)
	return audit.ScanExitCode(r, nil)
}

func runRollup(args []string) int {
	fs := flag.NewFlagSet("rollup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("out", "", "exclusive output CSV path (required)")
	inputDir := fs.String("input-dir", "", "directory of php2shell fleet *.csv files (non-recursive)")
	format := fs.String("format", "csv", "input format: csv (default) or json (legacy)")
	m := fs.String("tenant-map", "", "legacy JSON rollup only: SHA-256 of exact report file to trusted tenant")
	if err := fs.Parse(args); err != nil {
		return audit.ExitFatal
	}
	if strings.TrimSpace(*out) == "" {
		fmt.Fprintln(os.Stderr, "ERROR: rollup requires --out PATH.csv")
		return audit.ExitFatal
	}
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "csv", "":
		if err := audit.RollupFleetCSV(audit.FleetRollupOptions{
			InputDir:   *inputDir,
			InputFiles: fs.Args(),
			Output:     *out,
		}); err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			return audit.ExitFatal
		}
		fmt.Printf("Fleet CSV rollup saved: %s\n", *out)
		fmt.Println("Operator-selected input set only. customer_label is not authenticated tenancy; do not mix customers.")
		return audit.ExitOK
	case "json":
		if *inputDir != "" {
			fmt.Fprintln(os.Stderr, "ERROR: --input-dir is for fleet CSV rollup; use explicit JSON paths with --format json")
			return audit.ExitFatal
		}
		if err := audit.Rollup(fs.Args(), *m, *out); err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			return audit.ExitFatal
		}
		fmt.Printf("Legacy JSON rollup saved: %s (reports are NOT authenticated; unmapped tenants remain UNMAPPED)\n", *out)
		return audit.ExitOK
	default:
		fmt.Fprintln(os.Stderr, "ERROR: --format must be csv or json")
		return audit.ExitFatal
	}
}

func runRules(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("rules subcommands: trust, update, status, keygen, sign, verify")
	}
	switch args[0] {
	case "trust":
		f := flag.NewFlagSet("rules trust", flag.ContinueOnError)
		key := f.String("key", "", "Ed25519 public key file (hex)")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *key == "" || f.NArg() != 0 {
			return fmt.Errorf("usage: rules trust --key PUBLIC.hex")
		}
		if e := rules.InstallPublic(*key); e != nil {
			return e
		}
		fmt.Println("Trusted rule key pinned in user configuration. Changing it requires an explicit key-rotation procedure.")
		return nil
	case "update":
		f := flag.NewFlagSet("rules update", flag.ContinueOnError)
		url := f.String("url", "", "direct HTTPS URL of signed JSON")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *url == "" || f.NArg() != 0 {
			return fmt.Errorf("usage: rules update --url HTTPS_URL")
		}
		pub, e := rules.InstalledPublic()
		if e != nil {
			return e
		}
		data, e := rules.FetchHTTPS(*url)
		if e != nil {
			return e
		}
		b, e := rules.InstallSigned(data, pub)
		if e != nil {
			return e
		}
		fmt.Printf("Signature verified; rule sequence %d installed with %d indicators.\n", b.Sequence, len(b.Indicators))
		return nil
	case "status":
		b, e := rules.LoadCached()
		if e != nil {
			fmt.Println("No usable signed rules:", e)
			return nil
		}
		fmt.Printf("Trusted signed rules: sequence %d, %d indicators, expires %s\n", b.Sequence, len(b.Indicators), b.Expires.Format(time.RFC3339))
		return nil
	case "keygen":
		f := flag.NewFlagSet("rules keygen", flag.ContinueOnError)
		dir := f.String("out-dir", "", "PRIVATE directory outside the Git checkout")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *dir == "" || f.NArg() != 0 {
			return fmt.Errorf("usage: rules keygen --out-dir SECURE_DIRECTORY")
		}
		pub, priv, e := rules.Keygen()
		if e != nil {
			return e
		}
		if e = rules.WriteNew(filepath.Join(*dir, "rule-signing-private.hex"), []byte(hex.EncodeToString(priv)+"\n")); e != nil {
			return e
		}
		if e = rules.WriteNew(filepath.Join(*dir, "rule-signing-public.hex"), []byte(hex.EncodeToString(pub)+"\n")); e != nil {
			return e
		}
		fmt.Println("Keypair generated. NEVER commit PRIVATE signing keys to GitHub or distribute them with binaries.")
		return nil
	case "sign":
		f := flag.NewFlagSet("rules sign", flag.ContinueOnError)
		file := f.String("input", "", "unsigned rule data JSON")
		privFile := f.String("private", "", "signing key path")
		out := f.String("out", "", "output signed envelope JSON")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *file == "" || *privFile == "" || *out == "" || f.NArg() != 0 {
			return fmt.Errorf("usage: rules sign --input SOURCE.json --private PRIVATE.hex --out signed.json")
		}
		key, e := rules.ReadPrivate(*privFile)
		if e != nil {
			return e
		}
		raw, e := audit.ReadRegular(*file, 1024*1024)
		if e != nil {
			return e
		}
		var bundle rules.Bundle
		if e = json.Unmarshal(raw, &bundle); e != nil {
			return e
		}
		signed, e := rules.Sign(bundle, key)
		if e != nil {
			return e
		}
		if e = rules.WriteNew(*out, append(signed, '\n')); e != nil {
			return e
		}
		fmt.Println("Created signed rules:", *out)
		return nil
	case "verify":
		f := flag.NewFlagSet("rules verify", flag.ContinueOnError)
		file := f.String("bundle", "", "signed JSON")
		keyFile := f.String("key", "", "trusted Ed25519 public key")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *file == "" || *keyFile == "" || f.NArg() != 0 {
			return fmt.Errorf("usage: rules verify --bundle signed.json --key PUBLIC.hex")
		}
		key, e := rules.ReadPublic(*keyFile)
		if e != nil {
			return e
		}
		b, e := rules.LoadSignedPath(*file, key)
		if e != nil {
			return e
		}
		fmt.Printf("VALID signed rules: sequence %d, %d indicators\n", b.Sequence, len(b.Indicators))
		return nil
	default:
		return fmt.Errorf("unknown rules subcommand %q", args[0])
	}
}
