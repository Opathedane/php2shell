package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Opathedane/php2shell/internal/rules"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Opathedane/php2shell/internal/audit"
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
Reports official upstream patch-level comparisons but cannot attest the serving SAPI or exclude compromise.

Usage:
  php2shell doctor
  php2shell scan [--webroot DIR] [--repo DIR] [--access-log FILE] [--docker] [--out PREFIX]
  php2shell rules trust --key trusted-public.hex
  php2shell rules update --url https://raw.githubusercontent.com/Opathedane/php2shell/main/rules/signed.json
  php2shell rules status
  php2shell rules keygen --out-dir PRIVATE-KEY-DIRECTORY
  php2shell rules sign --input rules/source.json --private PRIVATE.hex --out rules/signed.json
  php2shell rollup [--tenant-map JSON] --out FILE.csv REPORT.json [REPORT.json ...]
  php2shell version

Examples:
  php2shell scan --out reports/my-webserver
  php2shell scan --runtime-version 8.4.26 --runtime-sapi fpm --runtime-source "approved FPM status evidence" --out reports/fpm-reviewed
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
	case "rules":
		return runRules(args[1:])
	case "version":
		fmt.Printf("php2shell %s %s/%s\n", audit.Version, runtime.GOOS, runtime.GOARCH)
		return nil
	case "doctor":
		fmt.Printf("PHP2Shell standalone %s (%s/%s)\nNo Python or PHP required. No external modules.\n", audit.Version, runtime.GOOS, runtime.GOARCH)
		fmt.Println("Host metadata: best-effort; Linux dpkg/apk and /proc; macOS/Windows partial.")
		fmt.Println("Official upstream PHP2Shell fix thresholds: AVAILABLE. Web-runtime patch attestation: NOT IMPLEMENTED.")
		fmt.Println("Signed indicator packs: manually trusted Ed25519 key; no automatic internet access.")
		fmt.Println("Default: offline, no code execution, reports written only to local files.")
		return nil
	case "scan":
		fs := flag.NewFlagSet("scan", flag.ContinueOnError)
		webroot := fs.String("webroot", "", "authorized website document root (file names only)")
		out := fs.String("out", "", "private output prefix; auto-generate if omitted; fail if exists")
		customer := fs.String("customer", "", "optional self-declared label; not authenticated tenant")
		runtimeVersion := fs.String("runtime-version", "", "operator-supplied WEB runtime PHP version; requires --runtime-sapi and --runtime-source; NOT independently verified")
		runtimeSAPI := fs.String("runtime-sapi", "", "web SAPI of operator-reported version, e.g. fpm, apache/mod_php, cgi, litespeed")
		runtimeSource := fs.String("runtime-source", "", "human-readable evidence provenance for operator-reported WEB runtime; NOT attestation")
		docker := fs.Bool("docker", false, "read local privileged Unix Docker API container metadata (opt-in)")
		updateRules := fs.Bool("update-rules", false, "opt-in download signed indicator rules; requires --rules-url and previously trusted key")
		rulesURL := fs.String("rules-url", "", "trusted signed rule bundle HTTPS URL")
		signedRules := fs.String("rules", "", "local Ed25519-signed bundle; requires previously trusted key")
		var repos, logs paths
		fs.Var(&repos, "repo", "authorized local repo; repeatable")
		fs.Var(&logs, "access-log", "local HTTP access log; repeatable; limit 32MiB")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected arguments; use --repo PATH or --access-log PATH")
		}
		if (*runtimeVersion != "" || *runtimeSAPI != "" || *runtimeSource != "") && (*runtimeVersion == "" || *runtimeSAPI == "" || *runtimeSource == "") {
			return fmt.Errorf("--runtime-version, --runtime-sapi and --runtime-source must be supplied together")
		}
		if len(*runtimeVersion) > 60 || len(*runtimeSAPI) > 80 || len(*runtimeSource) > 256 {
			return fmt.Errorf("runtime evidence fields too long")
		}
		if len(repos) > 20 || len(logs) > 20 {
			return fmt.Errorf("limit is 20 repositories and 20 log files per scan")
		}
		name, _ := os.Hostname()
		r := audit.NewReport(name, runtime.GOOS, runtime.GOARCH)
		r.CustomerLabel = *customer
		var indicators []rules.Indicator
		if *updateRules {
			key, e := rules.InstalledPublic()
			if e != nil {
				return fmt.Errorf("rules update requires trusted Ed25519 public key: %w", e)
			}
			if *rulesURL == "" {
				return fmt.Errorf("--update-rules requires --rules-url HTTPS_URL")
			}
			payload, e := rules.FetchHTTPS(*rulesURL)
			if e != nil {
				return fmt.Errorf("rules update failed: %w", e)
			}
			if _, e = rules.InstallSigned(payload, key); e != nil {
				return fmt.Errorf("rule verification/update failed: %w", e)
			}
		} else if *rulesURL != "" {
			return fmt.Errorf("--rules-url needs --update-rules")
		}
		var bundle *rules.Bundle
		if *signedRules != "" {
			key, e := rules.InstalledPublic()
			if e != nil {
				return fmt.Errorf("no trusted rule key: %w", e)
			}
			bundle, e = rules.LoadSignedPath(*signedRules, key)
			if e != nil {
				return fmt.Errorf("invalid signed rules: %w", e)
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
		audit.ScanHost(r, *webroot, *docker)
		if *runtimeVersion != "" {
			r.AddEvidence(audit.Evidence{Type: "operator_reported_web_runtime", Name: *runtimeSAPI, Version: *runtimeVersion, Source: "operator-supplied serving runtime statement: " + *runtimeSource, Interpretation: "UNVERIFIED_OPERATOR_ASSERTION_NO_ACTIVE_RUNTIME_ATTESTATION"})
			r.EffectiveWebRuntime = "OPERATOR_REPORTED_NOT_ATTESTED"
		}
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
			audit.ScanAccessLogWithIndicators(r, p, indicators)
		}
		audit.ScanFileHashes(r, *webroot, indicators)
		audit.EvaluatePatchPosture(r)
		if len(r.Findings) > 0 {
			r.CompromiseStatus = "INDICATORS_MATCHED_REVIEW_REQUIRED"
		} else if bundle != nil && len(indicators) > 0 && (len(logs) > 0 || *webroot != "") {
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
		audit.FinalizeSummary(r)
		if *out == "" {
			*out = fmt.Sprintf("reports/assessment-%s-%d", time.Now().UTC().Format("20060102T150405Z"), os.Getpid())
		}
		if err := audit.Save(r, *out); err != nil {
			return err
		}
		fmt.Printf("Assessment saved: %s.json, %s.csv, %s.html\n", *out, *out, *out)
		fmt.Printf("PHP evidence: %s | Patch review: %s | Compromise review: %s\n", r.Summary.PHPDiscovery, r.Summary.PatchReview, r.Summary.CompromiseReview)
		fmt.Printf("Evidence observations: %d | Vulnerability: %s | Compromise: %s | Serving runtime: %s\n", len(r.Evidence), r.VulnerabilityStatus, r.CompromiseStatus, r.EffectiveWebRuntime)
		fmt.Printf("Signed rules: %d (sequence %d) | Matched indicators: %d\n", r.RuleCount, r.RuleSequence, len(r.Findings))
		criticalShown := 0
		for _, a := range r.PatchAssessments {
			if a.Priority != "CRITICAL" {
				continue
			}
			if criticalShown == 0 {
				fmt.Println("IMMEDIATE PATCH REVIEW:")
			}
			if criticalShown >= 8 {
				fmt.Println("  ... additional findings and required actions are in the HTML / JSON report")
				break
			}
			fmt.Printf("  - %s %s (%s): %s\n", a.Component, a.ObservedVersion, a.Status, a.RequiredAction)
			criticalShown++
		}
		fmt.Println("Next steps and source qualifications: open the .html report > Official PHP2Shell patch assessment / Recommended follow-up.")
		fmt.Println("IMPORTANT: Patch-level comparison does not attest the active HTTP runtime or exclude compromise. Review assessments, coverage and required actions.")
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
