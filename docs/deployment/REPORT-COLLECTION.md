# Enterprise report collection

PHP2Shell writes reports **locally**. Central collection is a **customer integration** — the scanner has no built-in cloud upload.

This guide describes a reliable collection contract that works with Intune, GPO, PSADT, SMB, or an EDR file pull.

---

## 1. Per-host identification

| Field | Source |
| --- | --- |
| Hostname | HTML meta / CSV / status `hostname` |
| Execution ID | status JSON `execution_id` |
| Scan time | status `started_utc` / `ended_utc`; filename UTC stamp |
| Tool version | status `tool_version` / HTML footer |
| Customer/tenant | **Never** trust `--customer` alone for tenancy — map by collection path or authenticated agent |

Suggested remote layout:

```text
\\fileserver\php2shell-reports$\
  tenants\<tenant-id>\
    hosts\<hostname>\
      php2shell-<hostname>-<utc>.html
      php2shell-<hostname>-<utc>.csv
      php2shell-<hostname>-<utc>.status.json
```

---

## 2. Validation before accept

For each candidate run folder/files:

1. HTML and CSV exist and are non-empty.
2. Status JSON parses as `php2shell-execution-status/v1`.
3. `reports_written` is true.
4. Prefer `status_json_written` true; if false / missing status → packaging defect but HTML/CSV may still be kept.
5. `exit_code` is 0 or 2 (reject orphan HTML from a failed run paired with exit 1 elsewhere).
6. Filename UTC stamp and `ended_utc` are within the expected job window (reject **stale** copies from previous weeks when the job just failed).
7. Optional: compare SHA-256 of HTML/CSV if you store digests in status (not currently embedded — compute at collection time).

---

## 3. Complete vs incomplete vs failed

| Outcome | Collect? | Ops meaning |
| --- | --- | --- |
| Exit 0 + status COMPLETED | Yes | Inventory finished; still review findings |
| Exit 2 / COMPLETED_INCOMPLETE | Yes | Partial evidence; not a clearance |
| Exit 1 / FAILED | No new reports (or discard half-writes) | Fix packaging; do not upload yesterday’s HTML as “this run” |
| OUTPUT_WRITE_FAILED in error_ids | Yes if HTML/CSV present | Fix ACLs; note degraded status path |

**Report generation ≠ successful upload.** Log collection success separately.

---

## 4. SMB collection example (reference)

```powershell
# EXAMPLE — adapt ACLs and tenant paths; do not embed credentials
$src = Join-Path $env:ProgramData 'PHP2Shell\Reports'
$dst = "\\fileserver\php2shell-reports$\tenants\CONTOSO\hosts\$env:COMPUTERNAME"
New-Item -ItemType Directory -Force -Path $dst | Out-Null
Get-ChildItem $src -Filter 'php2shell-*.html' |
  Where-Object { $_.LastWriteTimeUtc -gt (Get-Date).ToUniversalTime().AddDays(-1) } |
  ForEach-Object {
    $base = [IO.Path]::GetFileNameWithoutExtension($_.Name)
    foreach ($ext in '.html','.csv','.status.json') {
      $f = Join-Path $src ($base + $ext)
      # status may be *.failed-*.status.json — resolve via status_json_path if needed
      if (Test-Path -LiteralPath $f) {
        Copy-Item -LiteralPath $f -Destination $dst -Force
      }
    }
  }
```

Use a computer account or managed service identity with **least privilege**. Prefer SMB encryption / signed SMB where policy requires.

---

## 5. Offline buffering & retries

- Keep local reports under ProgramData until collection ACK.
- Retry with exponential backoff; never delete local copies on first transfer failure.
- Deduplicate by `execution_id` or basename on the server.

---

## 6. Multi-customer separation

- Separate shares or top-level tenant prefixes.
- Do not mix customers in one rollup without an authenticated tenant map ([CSV-SCHEMA.md](../CSV-SCHEMA.md), `rollup`).
- Consultants: one working directory per engagement.

---

## 7. Sensitive data & retention

Reports may contain hostnames, paths, and package names. Treat as **internal confidential**.

| Policy | Suggestion |
| --- | --- |
| Retention | Align with vulnerability management (e.g. 90–365 days) |
| Access | SOC / patch owners only |
| Deletion | Secure delete after retention; retain legal holds separately |

---

## 8. Fleet consolidation

After collection:

```bash
php2shell rollup --input-dir ./collected-csv --out ./fleet-summary.csv
```

See [CSV-SCHEMA.md](../CSV-SCHEMA.md).

---

## 9. Demonstrated vs untested

| Item | Status |
| --- | --- |
| Local HTML/CSV/status contract | Implemented in product |
| SMB/Intune/GPO copy scripts | **Examples** — require customer pilot |
| Encryption at rest / DLP | Customer controls |
