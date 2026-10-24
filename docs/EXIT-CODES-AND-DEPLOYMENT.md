# Exit codes and enterprise deployment

Operational exit codes are **not** a vulnerability or compromise clearance.

| Code | Meaning | Reports | Typical cause |
| --- | --- | --- | --- |
| **0** | Completed | HTML+CSV written | Inventory/investigation finished; findings may exist. With `--accept-incomplete`, also used when coverage is incomplete. |
| **1** | Fatal | Usually **absent** (or incomplete pair removed) | Bad args, unsupported OS, output path failure, overwrite refusal, internal error |
| **2** | Completed with incomplete coverage | HTML+CSV **written** | Truncation, timeout, ACCESS_DENIED / UNAVAILABLE on **requested** evidence, deep-discovery limits |

## Status JSON

Every successful path resolution writes (by default) a sibling:

`report.html` → `report.csv` + `report.status.json`

Schema: `php2shell-execution-status/v1`. Fields include `execution_status` (`COMPLETED` / `COMPLETED_INCOMPLETE` / `FAILED`), `exit_code`, `error_ids`, `reports_written`, **`status_json_written`**, paths, and remediation text. No request bodies, cookies, or tokens.

Override path with `--status-json PATH`. Refuses overwrite (same as reports). If the primary status path cannot be written, the tool tries an execution-scoped `*.failed-<id>.status.json` and then an HTML-sibling fallback. A successful fallback still sets `error_ids` to include `OUTPUT_WRITE_FAILED` so automation can detect the degraded path **on disk** (do not rely on stderr alone).

`--quiet` still prints a one-line status summary (including `status_json_written=…`) on **stderr**.

**Intune / PSADT:** Treat missing status when HTML+CSV exist as a packaging defect; still collect reports. Prefer unique `--out` names.

## Customer command pitfalls

```text
php2shell-windows-amd64.exe scan --quiet --output-dir C:\...\Logs --out C:\...\Logs\SERVER.csv
```

- `--out` **wins** over `--output-dir` when both are set.
- A `--out` ending in `.csv` is remapped to `SERVER.html` + `SERVER.csv` (not CSV-only).
- Prefer unique names or `--output-dir` alone so re-runs do not hit overwrite refusal (exit **1**).
- On **Windows Server 2012 R2**, the standard EXE will not start (“not a valid application…”). Use `php2shell-windows-legacy-amd64.exe` — see [WINDOWS-LEGACY-2012R2.md](WINDOWS-LEGACY-2012R2.md).

## PSAppDeployToolkit / Intune

Exit **2** means reports are present and should be **uploaded**; it is not a tool crash. Wrappers that treat any non-zero as failure will drop valid evidence.

Options:

1. **Preferred:** treat exit codes **0 and 2** as success for file collection; treat **1** as failure.
2. Or pass `--accept-incomplete` so coverage gaps still exit **0** while status JSON records `SCAN_INCOMPLETE` / `COMPLETED_INCOMPLETE`.

Integration contract (uploads stay customer-specific / external):

| Check | Expected |
| --- | --- |
| Exit 0 or 2 | Require HTML+CSV present; upload |
| Exit 1 | Fail step; do not upload stale prior reports |
| Status JSON | Resolve sibling or `*.failed-*.status.json`; read `status_json_written`, `error_ids`, `scan_incomplete` |
| `OUTPUT_WRITE_FAILED` | Packaging/permissions; reports may still be valid |
| Incomplete | Upload but do not close as cleared |
| Stale outputs | Unique host+UTC `--out` each run |

Reference: [deploy/PSADT-PHP2Shell-Reference.ps1](../deploy/PSADT-PHP2Shell-Reference.ps1).

Enterprise guides: [Intune](deployment/INTUNE.md) · [GPO](deployment/GPO.md) · [Report collection](deployment/REPORT-COLLECTION.md) · [Understanding reports](UNDERSTANDING-REPORTS.md).

## Error identifiers (stable)

Examples: `UNSUPPORTED_OS`, `INVALID_ARGUMENT`, `ACCESS_DENIED`, `EVIDENCE_UNAVAILABLE`, `SCAN_INCOMPLETE`, `OUTPUT_WRITE_FAILED`, `OUTPUT_EXISTS`, `TIMEOUT`, `INTERNAL_ERROR`.

Failures **before** the process starts (wrong PE for the OS) must be caught by the deployment preflight, not by in-process diagnostics.
