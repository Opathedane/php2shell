# Standalone Go preview – security and reliability review

Date: 21 October 2026 | Version: 2.0.0-alpha.1 | Status: developer preview, not production approved

## Intended scope
Local, operator-authorized inventory and evidence triage. No PHP execution and no exploitation. The tool is NOT a verifier of CVE-2026-109618/-109619 patch or compromise state.

## Mitigations implemented in this rewrite

- Native builds for Linux amd64/arm64, Windows amd64, macOS amd64/arm64: no PHP, Python, Go or package installation on the target required.
- No os/exec, no shell invocations, no remotely sourced rules; default scanner does not initiate network requests.
- Optional Docker metadata uses one GET against local Unix socket; no command exec, no mutation calls. Socket permissions are inherently privileged and not automatically requested.
- Bounded reads, no deliberate input symlink/special file traversal, discovery counts capped, Webroot reads filenames only.
- Exclusive report creation; existing reports/symlinks are never overwritten. Output mode 0600 on POSIX.
- HTML reports escape all observed fields and carry a restrictive Content Security Policy. CSV formula-like inputs are prefixed to avoid spreadsheet evaluation.
- No raw HTTP request lines, URL queries or client IPs in log summaries; retain sensitive report file paths/host/package metadata.
- Unverified runtime and compromise statuses are NOT_VERIFIED and NOT_ASSESSED, respectively. Observed `session.upload_progress.enabled=Off` is NOT a verified mitigation.
- No automatic tenant identity from report input; offline rollup requires analyst hash-to-tenant mapping.

## Tests completed here

- 12 Go unit/regression tests (Linux) including CSV injection, HTML escaping, symlink output, FIFO/special file avoidance, bounded log scan, tenant spoofing rejection, repo-only declarations.
- `go vet ./...` and `go test ./...` on Linux/amd64.
- Linux/amd64 binary smoke execution: `doctor`, `scan`, `rollup` with local HTML/JSON/CSV report creation.
- Successfully cross-compiled binaries for Linux amd64/arm64, Windows amd64, macOS amd64/arm64.

**Limitations of those tests:** Not run on a real Windows Server/IIS host, macOS system, ARM Linux, or installed Apache/LSAPI/PHP-FPM production runtime. Compilation is not runtime certification.

## Open critical release blockers

1. No validated CVE-specific fixed/affected version logic or active HTTP SAPI verification; cannot say vulnerable/clean/patched.
2. No compromise indicators, process lineage history, EDR or forensic log detection; cannot say exploited/not exploited.
3. Windows/IIS runtime detection and standard enterprise Windows package enumeration missing.
4. No RPM native package inventory (RHEL, Rocky, AlmaLinux, Amazon Linux); default Linux coverage is incomplete.
5. Rotated/compressed or >32 MiB access logs unsupported; absence of log data is not negative evidence.
6. TOCTOU filesystem races on attacker-modifiable paths possible; does not provide forensic-grade acquisition or integrity attestation.
7. Binaries and reports unsigned; app publisher trust, code signing/notarization, SBOM, security contact and public license not approved.
8. Repository parsing is intentionally narrow; only declared image/Composer/CI versions, not build provenance, deployment, image digests or vendor backports.
9. Need independent code review, fuzz tests for log/config parsers, platform integration tests, container scenarios, permissions/ACL checks, performance tests, supply-chain security and change-control approval.

## VirusTotal article application

VirusTotal describes roughly 5.1 million IPs fingerprinted with PHP and only ~1.1 million reporting PHP version via banners, so **header absence is not evidence of PHP absence**. Its October 21 numbers are exposure footprint, not proven vulnerability. The scanner defaults to local evidence, with optional repo/log scope, explicit coverage, and no banner-only conclusions. VirusTotal enrichment is a **future separate, explicitly authorized MSSP workflow**, not automated uploading or scanning from customer systems.

A configuration change to disable session upload progress may be a temporary risk reduction; neither it nor `expose_php=Off`, edge/WAF rules, or PHP CLI package version is a validated fix for these CVEs. Focus on the actively serving runtime, origins bypassing WAF and vendor backports. Treat post-patch compromise triage separately from vulnerability assessment.

## Conclusion

The Go standalone preview is a safer, simpler transport/collection foundation than Python scripts on servers without Python. It is **not yet a trustworthy PHP2Shell vulnerability or compromise scanner**. Do not label it a public production release without closing the blockers above.
