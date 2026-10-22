# Compromise investigation (v2.7.0+)

Evidence-based **investigation assist** for CVE-2026-109618 / CVE-2026-109619. This extends PHP2Shell beyond patch inventory. It is **not** a clearance tool and never claims a host is clean or confirmed compromised.

**Shipped from [v2.7.0](https://github.com/Opathedane/php2shell/releases/tag/v2.7.0); latest [v2.7.1](https://github.com/Opathedane/php2shell/releases/tag/v2.7.1)** adds Calif-aligned IR accuracy, offline Cloudflare WAF `firewall_events` ingestion (attempt axis only), and deployment status JSON. Field validation baseline: [FIELD-VALIDATION-2.7.0.md](FIELD-VALIDATION-2.7.0.md). Notes: [releases/v2.7.1.md](releases/v2.7.1.md).

## Independent statuses

| Status | Meaning when investigation inputs are absent | Meaning when assessed |
| --- | --- | --- |
| Vulnerability / patch exposure | Existing host vulnerability rollup | Unchanged; independent of IR |
| Exploitation attempts | **`NOT_ASSESSED`** (not a negative finding) | `NO_MATCHES_IN_SCOPE` or `SUSPECTED_ATTEMPTS_REVIEW` (access/error logs and/or offline `--waf-log`) |
| Possible compromise | **`NOT_ASSESSED`** | Assessed when usable `--process-telemetry` and/or `--webroot` investigation inputs exist: `NO_MATCHES_IN_SCOPE` or `POSSIBLE_COMPROMISE_REVIEW`. Never auto-`CONFIRMED_COMPROMISE`. WAF alone never sets this axis. |
| Investigation coverage | **`NOT_REQUESTED`** | `ASSESSED_SCOPE_LIMITED`, `PARTIAL_TIMESTAMP_UNCERTAIN`, or `INCOMPLETE` (requested sources unavailable — distinct from completed no-match) |

Without usable process telemetry or webroot investigation (or when those inputs fail), possible compromise stays **`NOT_ASSESSED`** — not a negative clearance. Signed-pack IOC matches continue to set legacy `compromise_status` only. Successful in-process exploitation may produce neither a crash nor a suspicious child process.

## CLI

```bash
php2shell scan \
  --webroot /var/www/html \
  --access-log /var/log/nginx/access.log \
  --error-log /var/log/php8.3-fpm.log \
  --waf-log ./exports/cloudflare-firewall_events.jsonl \
  --process-telemetry ./exports/DeviceProcessEvents.csv \
  --process-telemetry ./exports/sysmon-eventid1.csv \
  --investigate-from 2026-10-17 \
  --output-dir "$HOME/.php2shell/reports"
```

- `--investigate-from` / `--investigate-to`: UTC `RFC3339` or `YYYY-MM-DD`. Default from **2026-10-17** when investigating; analysts may choose an **earlier** date. Requires `--access-log`, `--error-log`, `--process-telemetry`, `--waf-log`, and/or `--webroot`.
- `--error-log`: bounded PHP/Apache error logs (≤32 MiB each).
- `--waf-log`: offline WAF exports (≤32 MiB each, ≤8 files, ≤50 000 events). Currently **Cloudflare Logpush `firewall_events` JSONL** only. Documented fields only — no raw bodies/cookies/session values. Block/challenge ≠ successful exploitation. WAF leads feed **exploitation-attempt** review only.
- `--process-telemetry`: offline EDR/process exports only (≤32 MiB each, ≤8 files, ≤50 000 events). **No live EDR APIs, credentials, or uploads.**
- `--webroot`: authorized document root — existing filename inventory + SHA-256 IOC hashing unchanged; when investigating, also runs a **metadata-only** filesystem investigation (depth≤8, ≤25k entries, symlinks skipped, **contents never read**).
- First/last timestamps **do not** prove continuous coverage (rotation, gaps, timezone ambiguity, PID reuse, parser failures).
- Ordinary access logs do **not** expose HTTP bodies, form-field names, or multipart nesting. Long request-target length is a distinct, weak heuristic — not body size.

## Configured SAPI hints (not active-runtime attestation)

Reports summarize inventory hints for **Apache mod_php**, **PHP-FPM**, CGI/IIS, and LiteSpeed when evidence exists. Configuration/process/binary artifacts **do not** prove the HTTP-serving SAPI. Calif-documented interrupt behavior differs by SAPI (mod_php may reuse a worker after some startup fatals; PHP-FPM exits on `php_request_startup` failure) but **PHP-FPM remains exploitable** via post-startup paths — do not treat FPM as safe.

Observed `php.ini` whitelist settings (`memory_limit`, `post_max_size`, `session.upload_progress.enabled`, …) remain **OBSERVED≠EFFECTIVE** text only; temporary mitigations are unverified and do not replace patching.

## Supported offline WAF formats

| Format | Detection | Documented fields used | Not available (not invented) |
| --- | --- | --- | --- |
| Cloudflare Logpush `firewall_events` JSONL | `Action` + `RuleID` + `Datetime` | Action, RuleID, Description, Source, RayID, ClientRequestMethod/Host/Path/Query, EdgeResponseStatus, Datetime | Content-Length, multipart nesting, empty `filename`, raw bodies |

High-confidence `waf_php2shell_rule_match` leads require an allowlisted Cloudflare php2shell / Anomalous Execution **RuleID** from the public Cloudflare blog. Query-string **presence** of `PHP_SESSION_UPLOAD_PROGRESS` may emit a weak heuristic (value never retained). ClientIP is not retained in findings.

## Supported offline process telemetry formats

| Format | Detection | Documented fields used |
| --- | --- | --- |
| Microsoft Defender for Endpoint DeviceProcessEvents CSV | Header: `Timestamp`, `FileName`, `InitiatingProcessFileName`, … | Timestamp, DeviceName, FileName, FolderPath, ProcessId, ProcessCommandLine, InitiatingProcess*, ReportId, ActionType |
| Sysmon Event ID 1 CSV | Header: `Image`/`ParentImage` + time / EventID | UtcTime, Image, ParentImage, ProcessId, ParentProcessId, ProcessGuid, CommandLine |
| Linux auditd EXECVE text | `type=SYSCALL` / `type=EXECVE` with `audit(…)` | exe, comm, pid, ppid, a0…; parent via PPID→exe map (PID reuse noted) |
| Elastic ECS process JSONL | JSON lines with `process` / `@timestamp` | `@timestamp`, `host.name`, `process.{name,executable,pid,entity_id,command_line,parent.*}` |

Unsupported or invented schemas are rejected (`UNSUPPORTED_FORMAT`). SentinelOne Deep Visibility is **not** mapped until a documented sample/schema is available.

Command lines are **never** retained verbatim in findings or reports — only short classification tokens (e.g. `shell_invocation`). Entity/report IDs are kept for analyst trace-back.

## Process relationship leads

Suspicious **web/PHP parent → child** relationships (behavioral convergent; not confirmed compromise):

| Parent examples | Child examples | Kind |
| --- | --- | --- |
| `php.exe`, `php-cgi.exe`, `php-fpm`, `httpd`/`apache2`, `w3wp.exe`, `nginx` | `cmd.exe`, `powershell.exe`, `sh`/`bash`, interpreters, download utilities, temp-path binaries | `web_parent_shell_child` / `_interpreter_child` / `_download_child` / `_temp_path_child` |

Ordinary admin activity (e.g. `explorer.exe` → `cmd.exe`) and application-specific shells are **not** treated as compromise. Missing parents, incomplete ancestry, and PID reuse reduce confidence (`unconfirmed`) and never invent relationships.

## Research-backed log patterns

| Pattern | Class | Max confidence | Notes |
| --- | --- | --- | --- |
| PHP Fatal memory exhausted **in Unknown on line 0** | verified_public_pattern | suspected | Datadog; memory exhaustion alone ≠ attack |
| Apache `AH00052` / child Segmentation fault | verified_public_pattern | suspected | Datadog; successful exploits may not crash |
| Long POST **request-target** (≥2048 characters of URI path/query as logged) | heuristic | unconfirmed | Measures **request-target length only** — not body size, form-field names, or multipart nesting |
| Cloudflare allowlisted php2shell WAF RuleID | verified_public_pattern | suspected | Attempt assist; **block≠success**; never alone sets possible-compromise |
| WAF query token `PHP_SESSION_UPLOAD_PROGRESS` (presence) | heuristic | unconfirmed | Value not retained; body multipart fields still unavailable |
| Error research pattern within ±15 m of long request-target | correlation | unconfirmed | **Temporal proximity only — not causality** |
| Process lead within ±15 m of error/access lead | correlation | unconfirmed | **Not causality**; does not confirm successful exploitation |

## Fleet CSV

Writers emit **`php2shell-fleet-csv/v3`** with independent IR columns. Rollup accepts **v1–v3**.

## Webroot filesystem investigation

Metadata-only leads from an authorized `--webroot` (not a webshell scanner). **All webroot leads are `unconfirmed` weak evidence** — weaker than EDR process-relationship leads. Non-executable outer double extensions (e.g. `.php.txt`, `.php.bak`) are not treated as unusual PHP leads.

| Kind | Role | Meaning |
| --- | --- | --- |
| `webroot_php_in_upload_dir` | Location context | PHP-like name under upload/writable paths — emitted only with timestamp corroboration |
| `webroot_unusual_extension` | Location context | `.phtml` / `.phar` / executable-looking double-extension (e.g. `.php.jpg`) |
| `webroot_birth_in_window` | Timestamp evidence | OS birth/creation in window (even when mtime is old / preserved) |
| `webroot_mtime_in_window` | Timestamp evidence | Modification time in window when birth is unavailable or outside |

**Critical:** filesystem **mtime is never treated as file creation or execution**. Birth/creation time is used only when the OS exposes it (often unavailable on Linux `stat`). Historical CMS files with **both** timestamps outside the investigation window produce **no** leads. Path location context alone never flips `POSSIBLE_COMPROMISE_REVIEW` — only timestamp evidence kinds (plus process/EDR) do.

**Temporal correlation** (`correlated_webroot_and_*`) requires an available **birth** timestamp within ±15m of independent access/error/process evidence. **mtime proximity alone never creates correlation and never elevates confidence.** Proximity ≠ causality.

When `POSSIBLE_COMPROMISE_REVIEW` rests **only** on webroot metadata (no EDR process leads), HTML/CSV explicitly label it a **low-confidence investigative lead**, not confirmed webshell activity or successful exploitation. Existing signed SHA-256 IOC matching is unchanged and remains the only hash-based malware path (publicly verified packs only).

## Hard limits

- Offline, read-only, passive — never execute PHP, command lines, imported telemetry, or webroot file contents.
- No exploit probes, uploads, live EDR APIs, automatic remediation, or generic webshell/`eval` content scanning.
- Findings omit HTTP query secrets, raw command lines, file contents, and sensitive EDR fields by default.
- AWS source IPs / RPM inventory / PHP lifecycle calendar are **out of scope** for v2.7.0.

## Synthetic demos (lab only)

`testdata/demos/process-telemetry/` and `testdata/demos/webroot-investigation/` — **not** a substitute for real-host field validation.

```bash
PHP2SHELL_WRITE_DEMOS=1 go test ./internal/audit -run 'TestGenerateProcessTelemetryDemos|TestGenerateWebrootInvestigationDemos' -count=1
```

## Related

- [FIELD-VALIDATION-2.7.0.md](FIELD-VALIDATION-2.7.0.md)
- [IOC-RULE-LIMITATIONS.md](IOC-RULE-LIMITATIONS.md)
- [THREAT-INTELLIGENCE.md](THREAT-INTELLIGENCE.md)
- [CSV-SCHEMA.md](CSV-SCHEMA.md)
- [ADVANCED-USAGE.md](ADVANCED-USAGE.md)
- [releases/v2.7.1.md](releases/v2.7.1.md) · [releases/v2.7.0.md](releases/v2.7.0.md)
- [EXIT-CODES-AND-DEPLOYMENT.md](EXIT-CODES-AND-DEPLOYMENT.md)
