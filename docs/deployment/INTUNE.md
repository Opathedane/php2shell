# Microsoft Intune deployment (Win32)

Practical guidance for packaging PHP2Shell as an Intune **Win32** app for **Windows clients** (Windows 10/11 and supported client SKUs).

## Critical platform note

**Standard Microsoft Intune Win32 app deployment targets Windows client devices.** It is **not** a supported way to manage general **Windows Server** fleets the way ConfigMgr/GPO do.

| Scenario | Recommended path |
| --- | --- |
| Windows 10/11 workstations / VDI with Intune | This document (Win32) |
| Domain-joined Windows Server | [GPO.md](GPO.md) and/or [PSADT](../../deploy/PSADT-PHP2Shell-Reference.ps1) |
| Server 2012 R2 | Legacy EXE + GPO/PSADT — [WINDOWS-LEGACY-2012R2.md](../WINDOWS-LEGACY-2012R2.md) |

Do not claim “Intune covers all Windows Servers” in customer designs.

---

## 1. Concepts (do not conflate)

| State | Meaning |
| --- | --- |
| Application installed | Win32 content present under a fixed path |
| Scan executed | Process started |
| Scan completed / incomplete | Exit **0** or **2** with HTML+CSV |
| Reports generated | Unique `.html` / `.csv` / `.status.json` for **this** run |
| Reports collected | Customer copy/upload succeeded (external to PHP2Shell) |

A Win32 “Installed” detection rule must **not** mean “host is patched” or “reports reached the SOC.”

---

## 2. Prerequisites

- Intune admin rights; Win32 Lob app capability
- [Microsoft Win32 Content Prep Tool](https://learn.microsoft.com/mem/intune/apps/apps-win32-app-management) (`IntuneWinAppUtil`)
- 64-bit PowerShell on targets
- Ability for **SYSTEM** to write under `%ProgramData%\PHP2Shell\`
- Correct EXE: `php2shell-windows-amd64.exe` (not legacy) for Win10/11

---

## 3. Suggested package layout

```text
PHP2Shell-Intune/
  php2shell-windows-amd64.exe
  Install-PHP2Shell.ps1
  Detect-PHP2Shell.ps1
  (optional) Deploy-Scan.ps1   # thin wrapper around scan
```

Build:

```powershell
IntuneWinAppUtil.exe -c .\PHP2Shell-Intune -s Install-PHP2Shell.ps1 -o .\out -q
```

Produces `Install-PHP2Shell.intunewin`.

---

## 4. Install command (place binary only)

Install should **stage** the EXE (and optional scripts), not pretend the vulnerability assessment finished.

Example `Install-PHP2Shell.ps1` (adapt; **example — field-test before production**):

```powershell
# Requires: 64-bit PowerShell; runs as SYSTEM via Intune
$ErrorActionPreference = 'Stop'
$dest = Join-Path $env:ProgramFiles 'PHP2Shell'
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item -Force -LiteralPath (Join-Path $PSScriptRoot 'php2shell-windows-amd64.exe') `
  -Destination (Join-Path $dest 'php2shell-windows-amd64.exe')
# Optional: copy Deploy-Scan.ps1 next to EXE
exit 0
```

**Intune install command:**

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-PHP2Shell.ps1
```

**Uninstall (example):** remove `C:\Program Files\PHP2Shell` (does not delete historical reports under ProgramData).

---

## 5. Detection rule

Detect **binary presence**, not “last scan succeeded”:

| Rule | Example |
| --- | --- |
| File | `C:\Program Files\PHP2Shell\php2shell-windows-amd64.exe` exists |
| Optional version | File version / script that checks `php2shell … version` output contains `2.7.` |

Do **not** detect solely on “any HTML under ProgramData” — that confuses stale reports with a current install.

---

## 6. Running the scan (separate from install)

### Option A — Win32 install also runs one scan (simple pilots)

Append to install script after copy:

```powershell
$exe = Join-Path $dest 'php2shell-windows-amd64.exe'
$outRoot = Join-Path $env:ProgramData 'PHP2Shell\Reports'
New-Item -ItemType Directory -Force -Path $outRoot | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$hostSafe = ($env:COMPUTERNAME -replace '[<>:"/\\|?*]', '-')
$html = Join-Path $outRoot ("php2shell-{0}-{1}.html" -f $hostSafe, $stamp)
& $exe scan --quiet --out $html
$code = $LASTEXITCODE
# Treat 0 and 2 as “scan produced reports”; 1 as install/scan failure for this pattern
if ($code -eq 1) { exit 1 }
exit 0   # Win32 success = app present + reports attempted; incomplete still exit 0 for Intune soft success
```

**Trade-off:** Intune marks the app Successful even when scan was incomplete (exit 2 mapped to 0). Prefer Option B for accuracy.

### Option B — Scheduled task / Proactive Remediations / separate Win32 “scan” package (recommended)

Keep install detection = EXE present. Run scans on a schedule with unique `--out` names. Collect reports centrally (see [REPORT-COLLECTION.md](REPORT-COLLECTION.md)).

### Option C — PSADT wrapper

Use [deploy/PSADT-PHP2Shell-Reference.ps1](../../deploy/PSADT-PHP2Shell-Reference.ps1) inside a PSADT package called from Intune.

---

## 7. Exit codes for automation

| Scanner exit | Reports | Intune guidance |
| --- | --- | --- |
| **0** | HTML+CSV (+ status) | Success for collection |
| **1** | Usually absent | Fail; do not upload stale prior HTML |
| **2** | HTML+CSV written | **Collect**; coverage incomplete — not a clearance |

`--quiet` keeps stdout clean; **stderr** still has the status line and errors. Prefer reading `.status.json` (`status_json_written`, `error_ids`, `scan_incomplete`).

---

## 8. Requirements / 64-bit / SYSTEM

- Use the **64-bit** PowerShell host (`SysNative` if a 32-bit Intune context launches scripts).
- Default SYSTEM profile; ensure `ProgramData\PHP2Shell\Reports` is writable.
- No interactive desktop required.

---

## 9. Repeat scans vs “application installation”

| Concern | Approach |
| --- | --- |
| One-time inventory | Option A install+scan |
| Recurring | Scheduled task / Remediations; unique timestamps |
| Version upgrade | New Win32 version; detection on new EXE; do not delete all historical reports blindly |
| Rollback | Keep previous EXE versioned under `PHP2Shell\bin\vX.Y.Z\` if required by change control |

---

## 10. Report locations & validation

Default customer path: `C:\ProgramData\PHP2Shell\Reports\`

Per run expect:

- `php2shell-<host>-<utc>.html`
- `php2shell-<host>-<utc>.csv`
- `php2shell-<host>-<utc>.status.json` (or `*.failed-<execution_id>.status.json`)

Validate before collection: HTML+CSV exist; status JSON parses; `execution_id` / timestamps match this run; reject files older than the current install/scan start.

---

## 11. Logging & troubleshooting

| Symptom | Check |
| --- | --- |
| Win32 failed | Intune Management Extension logs; script exit 1 |
| No reports | ACLs on ProgramData; disk full; wrong working directory |
| Exit 2 | Status `coverage_incomplete`; permissions on `--php-ini` / logs |
| “Not a valid Win32 application” | Wrong EXE (legacy vs standard) |
| SmartScreen | Unsigned binary — see [DISTRIBUTION-SIGNING.md](DISTRIBUTION-SIGNING.md) |

---

## 12. What requires customer integration

| Built into PHP2Shell | Customer-specific |
| --- | --- |
| Local HTML/CSV/status | Intune tenant, assignments, Azure storage, ticket systems |
| Exit codes + status schema | Win32 detection rules, collection agents |
| `--quiet` stderr status line | Log Analytics ingestion parsers |

**Field status:** Package layout and exit contract are designed for Intune Win32; **end-to-end Intune tenant validation is not claimed** until your pilot checklist passes.
