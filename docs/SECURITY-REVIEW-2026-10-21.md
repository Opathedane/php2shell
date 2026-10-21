# Security assessment — 2.1.0-alpha.2 (21 October 2026)

Scope: original Go source + GitHub workflows. **Developer pre-release; no independent penetration test or customer production validation.**

## Threat model and mitigations

- Payload integrity: Ed25519 signature over the precise JSON payload bytes. Public key must be pinned once via trusted out-of-band channel. SHA-256 checksums and HTTPS alone do not authenticate publisher. Invalid, expired, unexpected schema/type, oversize, wrong-key, changed and rollback packages are rejected. Exact current version is idempotent; changed same sequence rejected. No automatic trust-key rotation.
- Download: Only explicitly requested direct `https://raw.githubusercontent.com/` URL, timeout 12 seconds, at most 1MiB, redirects rejected. No user logs/data are uploaded. No default remote lookup.
- Rule execution: no arbitrary code, no shell, no regex from downloaded rules, no exploit probes; only fixed HTTP request-target literals and SHA256 file hashes. Reasonable caps apply.
- Static host evidence: Python/PHP unnecessary. Scanner never runs discovered PHP executables. `--docker` requires explicit permission and accesses a highly privileged Docker socket only for metadata.
- Bounded reads: input files must be regular/non-symlink when opened; size limits. Repo walker ignores symlinks/devices; file IOC walker ignores symlinks and caps data read. Residual race conditions on attacker-writable filesystem remain.
- Output controls: exclusive no-overwrite creation, restrictive POSIX permissions, escaped HTML and spreadsheet-safe CSV. Reports may expose sensitive hostnames, paths and package versions. Windows ACL behavior depends on account/user profile/volume.
- Privacy: HTTP matches store rule, path and line number but not request URI, client IP or query. No automatic data sharing with GitHub.
- Interpretation: signed indicators represent possible evidence, not verified compromise. No matches do not clear a system. No PHP2Shell-specific rule pack until upstream documentation is verified. Runtime version/backport attestation remains unimplemented.

## Tests in this build environment

`go test ./...`, `go vet ./...`, `go test -race ./...` (when available), Linux native executable smoke and cross-platform compilation. Fixture tests cover Windows/IIS config and access logs but **no real Windows Server/IIS test** can be claimed here. GitHub CI is configured for Windows/macOS/Linux, but it must be run and inspected by repository maintainers.

## Open findings — release blocking

1. **Critical functional limitation:** cannot attest the PHP runtime actually serving requests or official CVE-affected/fixed versions; no trustworthy patch verdict.
2. **Critical functional limitation:** no validated PHP2Shell-specific exploit indicators, historical process lineage or comprehensive forensic acquisition. A successful exploitation verdict or clean verdict is unsupported.
3. **High:** no production integration testing on IIS/Windows Server, nginx/FPM, Apache, enterprise patches and containers; static config metadata may be stale or overridden.
4. **Medium:** authenticated rule signing key provisioning and publication are operator responsibilities; no actual signed bundle included, and initial public-key distribution must be out-of-band. Signing-key compromise requires manual re-trust.
5. **Medium:** static paths/OS metadata may be incomplete; file access TOCTOU is not forensically robust; rotated/compressed access logs are unsupported.
6. **Operational:** unsigned native executables can trigger Windows SmartScreen/AV and cannot yet be distributed as an approved enterprise security product; license remains a proposal.
7. **Operational:** GitHub Actions uses version tags rather than commit hash pins; independently review release pipeline before public distribution.

## Source validation policy

As of pre-disclosure 21 Oct 2026, PHP's upstream team has not published CVE-specific patch/trigger information in its announcement. This tool does not incorporate the unconfirmed X PoC or claims about `session.upload_progress` providing a fix. Following The Hacker News / VirusTotal guidance: WAF, masked banners and session tweaks are not validated patch status; patch and verify effective web runtime, restrict origin exposure, retain logs, and separately assess prior compromise.
