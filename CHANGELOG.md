## Unreleased

- Fix Windows AppData PHP installs that were discovered but reported "no version marker found": directed PE `.rsrc` reads, labelled path-based version inference (e.g. `Programs\PHP\8.4.24\...`), distinguish inferred vs verified metadata, corroborate `current` aliases without assuming identity, and emit patch assessments with confidence in HTML and CSV. Regression covers the TestVM v2.3.0 report scenario (8.4.24 below 8.4.27). Does not execute PHP or attest CLI as the web runtime.
- Post-release documentation audit for v2.3.0 (issue templates, governance). v2.3.0 release assets remain unchanged.

## v2.3.0 — 2026-10-21

- First official public release (non-prerelease).
- Redesigned HTML-only assessment report: executive summary cards, grouped PHP installations, prioritized next steps, and collapsible technical sections (`<details>`).
- Fix false PHP version extraction from Ubuntu `php-common` packaging revisions (e.g. `24.04.1`).
- Exclude the scanner process (`php2shell*`) from PHP process discovery; tighten process-name matching.
- CLI: HTML-only output, `--output-dir`, `--quiet`, operational exit codes `0`/`1`/`2`.
- Preserve security limitations: no active-runtime attestation, no compromise clearance from empty IOC results, no automatic remediation or data upload.

## v2.2.0-alpha.2 — 2026-10-21 (prerelease)

- Add a concise, evidence-qualified summary to HTML, JSON and CSV reports: PHP discovery, patch review and compromise review.
- Add prioritized next steps and tests ensuring no evidence/no IOC matches never mean safe.
- Simplify README, add maintainer contact, retain explicit alpha, validation and licensing notices.
- No new compromise signatures or active web-runtime attestation in this release.

## v2.2.0-alpha.1 — 2026-10-21

- Integrate official PHP upstream fix thresholds for CVE-2026-109618 and CVE-2026-109619: 8.2.35, 8.3.36, 8.4.27, 8.5.12.
- Add evidence-qualified per-version remediation assessments and priorities in JSON, HTML and CSV; no "safe" inference from package metadata, version declarations or vendor-backported packages.
- Add operator-supplied web-runtime version and provenance flags (never independently attested).
- Document verified remediation, worker restarts, legacy and vendor patches, and **incomplete** official temporary mitigations.
- Extend passive INI observation to memory_limit, post_max_size, upload_max_filesize and fatal_error_backtraces.
- Add official-version and false-assurance regression tests. Preserve existing signed IOC and read-only collection mechanisms.
- **Still alpha:** does not verify active HTTP SAPI versions, vendor backports or absence of compromise; Windows/IIS version discovery remains limited.

# Changelog

## 2.1.0-alpha.2 — 2026-10-21 (developer-only)

- Implemented pinned Ed25519 signed, data-only indicator rule packs (one-time trust key, HTTPS GitHub download, fail closed signature/expiry checks, sequence rollback prevention, cached-only scanning without network).
- Added optional `--update-rules` and `--rules` scanner modes; maintainer `rules keygen/sign/verify` commands; deliberately no PHP2Shell-specific speculative indicators.
- Added matching of exact SHA-256 file hashes within bounded authorized webroots and fixed-string request-target indicators in bounded access logs, without saving raw client IP/query data.
- IIS W3C access-log format and timestamp parsing; passive IIS FastCGI handler and Windows process snapshots.
- Added tests for corrupted signatures, untrusted keys, expiration, rollback, HTTP/IIS privacy and hashes; CI test matrix includes Windows/macOS runners.
- Kept vulnerability status `NOT_VERIFIED`. Reports never treat no matches as compromise clearance. Real Windows Server/IIS, SAPI/vendor patch attestation and validated CVE-specific IOCs remain release blockers.

## 2.0.0-alpha.1

- Standalone Go proof of concept with local host/repo inventory, basic log coverage, HTML/CSV/JSON reports and analyst-controlled rollups.
