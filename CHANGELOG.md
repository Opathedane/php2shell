## Unreleased

## v2.7.3 — 2026-10-25

- Fix: OS-aware no-PHP reporting — distinguish completed inventory coverage from incomplete discovery; suppress Windows dpkg/apk/RPM false gaps; avoid patch/runtime remediation spam when no PHP is found within coverage; never claim the host is PHP-free, patched, or uncompromised.
- Improve: HTML executive summary layout for no-PHP and incomplete-coverage cases; consistent CLI/HTML/CSV/`summary.php_discovery` semantics (`NO_PHP_DETECTED_WITHIN_SCAN_COVERAGE`, `NO_PHP_SPECIFIC_REMEDIATION_IDENTIFIED`) without changing vulnerability-detection rules or exit codes.
- Docs: [docs/releases/v2.7.3.md](docs/releases/v2.7.3.md); PR preview assets under `docs/pr-assets/v2.7.3-no-php/`.
- Scope: reporting/usability only — no new CTI/IOC packs, discovery features, or CVE threshold changes.
- Field: original Windows no-PHP host retest **NOT TESTED** at publish; automated regressions/CI passed.

## v2.7.2 — 2026-10-24

- Feature: CVE-2026-115560 informational advisory assessment from observed `session.serialize_handler` + `session.upload_progress.enabled` (static config only; no invented fixed versions; separate from CVE-2026-109618/109619 patch thresholds).
- Improve: enterprise QA — humanized console, patch-first HTML, glued RC handling, WAF RuleID casings + incomplete coverage, status JSON integrity, PSADT/GPO/Intune docs.
- License: Apache License 2.0 (`LICENSE`).
- Fix: legacy Go 1.20.14 archive SHA-256 verification; release workflow binds workflow_dispatch to the named tag commit.
- Docs: [docs/releases/v2.7.2.md](docs/releases/v2.7.2.md).

## v2.7.1 — 2026-10-22

- Improve: Calif-aligned IR accuracy — SAPI-aware investigation hints (mod_php vs PHP-FPM; never active-runtime attestation); explicit HTTP body/form/multipart unavailability vs long request-target heuristics; in-process exploitation-without-child warnings; stronger OBSERVED≠EFFECTIVE configuration labelling; evidence-source availability distinguishing REQUESTED_UNAVAILABLE from completed NO_MATCHES_IN_SCOPE.
- Feature: offline `--waf-log` ingestion for Cloudflare Logpush **firewall_events** JSONL — allowlisted php2shell Anomalous Execution RuleIDs; optional `PHP_SESSION_UPLOAD_PROGRESS` query-presence heuristic; block≠success; WAF alone never sets possible-compromise; no raw bodies/cookies/session values retained.
- Feature: Windows Server **2012 R2** legacy artifact `php2shell-windows-legacy-amd64.exe` (Go **1.20.14** only; runtime field-unverified); primary Windows build stays on current Go and refuses NT &lt; 10 with an actionable redirect; see [docs/WINDOWS-LEGACY-2012R2.md](docs/WINDOWS-LEGACY-2012R2.md).
- Fix: absent IIS / missing dpkg|apk no longer mark coverage `UNAVAILABLE` (was forcing exit **2** on common Windows/RHEL inventory scans and breaking PSADT uploads).
- Feature: execution-status JSON (`.status.json`), stable error IDs, `--status-json`, `--accept-incomplete`; `--quiet` still emits stderr status. Deployment guide: [docs/EXIT-CODES-AND-DEPLOYMENT.md](docs/EXIT-CODES-AND-DEPLOYMENT.md); PSADT reference under `deploy/`.
- Docs: [docs/releases/v2.7.1.md](docs/releases/v2.7.1.md).

## v2.7.0 — 2026-10-22

- Feature: **Compromise investigation assist** — offline `--access-log` / `--error-log` / `--process-telemetry` / `--webroot` metadata investigation; independent exploitation-attempt, possible-compromise, and investigation-coverage statuses; birth-aware webroot leads with path context vs timestamp evidence; ±15m temporal correlation (proximity ≠ causality); fleet CSV **v3** with IR columns and v1–v3 rollup. Never auto-confirmed compromise; never equates no matches with a clean host. See [docs/COMPROMISE-INVESTIGATION.md](docs/COMPROMISE-INVESTIGATION.md) and [docs/releases/v2.7.0.md](docs/releases/v2.7.0.md).
- Docs: field validation guide [docs/FIELD-VALIDATION-2.7.0.md](docs/FIELD-VALIDATION-2.7.0.md).

## v2.6.0 — 2026-10-21

- Feature: optional `--deep-root DIR` Deep Discovery (repeatable, off by default) — recursive bounded search for PHP binaries and php.ini-like files under consultant-authorized roots only; rejects UNC/network paths and volume roots; never executes PHP.
- Feature: multi-install retention under deep roots with weaker evidence provenance than well-known/PATH/IIS sources; alias merge still requires content corroboration.
- Feature: expanded bounded well-known binary globs — Windows WAMP/Wamp64/Laragon/`C:\tools\php`; Linux Remi/cPanel `php-fpm` sbin, `/usr/local/php*`, `/opt/php/*`.
- Safety: depth ≤ 6, ≤ 25 000 entries, ≤ 400 binaries, ≤ 200 ini candidates, 90s wall-clock budget; truncation/permission gaps reported as TRUNCATED/INCOMPLETE (exit 2) — absence of findings is not proof PHP is absent.
- Docs: version-specific [docs/releases/v2.6.0.md](docs/releases/v2.6.0.md); consultant guidance for normal scan vs Deep Discovery.

## v2.5.1 — 2026-10-21

- Fix: PATH / Programs\PHP discovery no longer skips directory junctions/symlinks such as `...\PHP\current` (bounded reparse resolve, max 4 hops, cycle detection; binaries never executed).
- Fix: php.ini inspection beside PATH-resolved directories; `--php-ini` / `--config-root` for non-standard layouts; configuration-only labelling and skip coverage diagnostics in HTML+CSV.
- Fix: multi-version hosts — discover all eligible PATH entries (not only the first), combine well-known/IIS/Apache/custom roots, keep independent install records (alias merge only when corroborated), assess each against its upstream threshold, list all in HTML+CSV/rollup; coverage text states discovery is not complete host coverage.
- Regression: TestVM-style `Temp\PHP\current`; three Windows installs (PATH + IIS + `--config-root`); hermetic php.ini CI isolation.

## v2.5.0 — 2026-10-21

- Windows + Linux bounded `php.ini` discovery: well-known roots, binary sidecars, `PHPRC` / `PHP_INI_SCAN_DIR`, IIS `-c` / Apache `PHPIniDir` path follow-up; sample/template classification; whitelist setting observations remain OBSERVED≠EFFECTIVE.
- Fleet CSV schema **`php2shell-fleet-csv/v2`**: structured `config_*` columns for discovery status, counts, install correlation, and primary ini path; rollup accepts v1+v2 and writes v2. php.ini alone never fills `php_version` / confirmed install.

## v2.4.0 — 2026-10-21

- Every `scan` writes a matching **HTML + CSV** pair from the same assessment (`php2shell-fleet-csv/v1`); `--out report.html` implies `report.csv`.
- Refuse overwrite of either file; if CSV write fails after HTML, remove the incomplete HTML pair member.
- Add offline `rollup --input-dir` / explicit CSV inputs for customer-wide consolidation; reject conflicting non-empty customer labels; keep legacy `rollup --format json`.
- Preserve v2.3.1 Windows detection (AppData/PATH, PE `.rsrc`, path inference, `current` aliases) with HTML/CSV consistency tests and synthetic demos under `testdata/demos/`.
- IIS: inventory site/app/vdir `physicalPath` values (including non-`C:` paths such as `E:\websites\prod\...`), read accessible per-mapping `web.config` PHP handlers, follow FastCGI executables on other drives when referenced by trusted config, redact handler arguments, correlate site↔handler↔version↔patch where supported, and mark coverage **INCOMPLETE** when a configured handler binary cannot be versioned — without drive-wide recursion or PHP execution; `.php` filenames still require explicit `--webroot`. IIS lock/clear/remove inheritance is not fully simulated (documented).
- Apache HTTP Server (bounded, passive): well-known config roots on Linux/Windows; VirtualHost DocumentRoot/ServerName; mod_php LoadModule; SetHandler/AddHandler/Action/ProxyPassMatch; local handler binary version inspection; remote FPM backends flagged as non-local (**INCOMPLETE**); Tomcat explicitly out of scope. Not a full Apache merge simulator — see ADVANCED-USAGE.
- Documentation and GitHub presentation refresh; Apache-2.0 licensing remains pending owner approval.

## v2.3.1 — 2026-10-21

- Fix Windows AppData PHP installs that were discovered but reported "no version marker found": directed PE `.rsrc` reads, labelled path-based version inference (e.g. `Programs\PHP\8.4.24\...`), distinguish inferred vs verified metadata, corroborate `current` aliases without assuming identity, and emit patch assessments with confidence in HTML and CSV.
- Regression covers the TestVM v2.3.0 report scenario (8.4.24 below 8.4.27). Does not execute PHP or attest CLI as the web runtime.
- Post-2.3.0 documentation/governance updates shipped earlier on `main` remain available; v2.3.0 release assets are unchanged.

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
