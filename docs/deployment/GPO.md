# Group Policy deployment (Windows Server & domain clients)

For domain-joined Windows environments, GPO is often more appropriate than Intune—especially for **Windows Server**.

**Field status:** Patterns below are **reference designs**. Validate with `gpresult`, Task Scheduler history, and a pilot OU before production. Marked PowerShell blocks are **examples requiring adaptation**, not certified Microsoft support statements.

---

## 1. Choose a pattern

| Pattern | Best for | Caveats |
| --- | --- | --- |
| **A. Startup script (one-time / infrequent)** | Simple rollout, “run soon after boot” | Can delay startup; harder to schedule off-hours; overlaps on reboot storms |
| **B. GPO Preferences Scheduled Task (preferred for repeats)** | Recurring scans, controlled windows | Needs correct SYSTEM task ACL; test on Server 2016+ and 2012 R2 separately |

Both must:

- Run as **SYSTEM**
- Use a **unique** report filename each execution
- Select **standard vs legacy** EXE correctly
- Never embed credentials in GPO/SYSVOL scripts

---

## 2. Binary staging (shared for A and B)

1. Publish read-only binaries on a share, for example:
   - `\\fileserver\soft$\PHP2Shell\bin\php2shell-windows-amd64.exe`
   - `\\fileserver\soft$\PHP2Shell\bin\php2shell-windows-legacy-amd64.exe`
2. ACL the share so **Domain Computers** (or a dedicated group) have **Read & execute** only — not Modify.
3. Copy locally on first run to `%ProgramFiles%\PHP2Shell\` (avoids holding SMB locks during scan).

### EXE selection (example)

```powershell
# Example — adapt; not a signed Microsoft script
function Get-PHP2ShellExe {
  $root = Join-Path $env:ProgramFiles 'PHP2Shell'
  $v = [Environment]::OSVersion.Version
  $is2012R2 = ($v.Major -eq 6 -and $v.Minor -eq 3)
  if ($is2012R2) {
    return (Join-Path $root 'php2shell-windows-legacy-amd64.exe')
  }
  return (Join-Path $root 'php2shell-windows-amd64.exe')
}
```

See [WINDOWS-LEGACY-2012R2.md](../WINDOWS-LEGACY-2012R2.md) for Go 1.20.14 security limitations.

---

## 3. Pattern A — Computer startup script

**Placement:** Computer Configuration → Policies → Windows Settings → Scripts → Startup  
**Filtering:** Link GPO to server/workstation OUs; Security Filtering = intended computer groups.

**Advantages:** Simple; runs with computer context.  
**Limitations:** Extends boot time; concurrent boots hammer file servers; poor for frequent repeats.

**Startup.ps1 sketch (example):**

```powershell
$ErrorActionPreference = 'Stop'
$binShare = '\\fileserver\soft$\PHP2Shell\bin'
$local = Join-Path $env:ProgramFiles 'PHP2Shell'
New-Item -ItemType Directory -Force -Path $local | Out-Null
# Copy only if missing or hash mismatch (customer implements Get-FileHash vs published SHA256)
Copy-Item -Force (Join-Path $binShare 'php2shell-windows-amd64.exe') $local -ErrorAction SilentlyContinue
Copy-Item -Force (Join-Path $binShare 'php2shell-windows-legacy-amd64.exe') $local -ErrorAction SilentlyContinue

$exe = Get-PHP2ShellExe
$outRoot = Join-Path $env:ProgramData 'PHP2Shell\Reports'
New-Item -ItemType Directory -Force -Path $outRoot | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$html = Join-Path $outRoot ("php2shell-{0}-{1}.html" -f $env:COMPUTERNAME, $stamp)
$lock = Join-Path $outRoot '.scan.lock'
if (Test-Path $lock) { exit 0 }  # prevent overlap — example only
New-Item $lock -ItemType File | Out-Null
try {
  & $exe scan --quiet --out $html --timeout 30m
  $code = $LASTEXITCODE
  # Local log; do not write secrets
  Add-Content (Join-Path $outRoot 'gpo-startup.log') "$(Get-Date -Format o) exit=$code html=$html"
} finally {
  Remove-Item $lock -Force -ErrorAction SilentlyContinue
}
# Startup scripts: non-zero may be logged; prefer logging exit rather than failing boot hard
exit 0
```

---

## 4. Pattern B — Scheduled Task via Group Policy Preferences (preferred)

**Placement:** Computer Configuration → Preferences → Control Panel Settings → Scheduled Tasks → **New → Scheduled Task (At least Windows 7)**

Suggested settings:

| Setting | Value |
| --- | --- |
| Name | `PHP2Shell-Inventory-Scan` |
| When running | Whether user is logged on or not |
| Run as | **SYSTEM** (built-in) |
| Trigger | Weekly / daily off-peak (customer choice) |
| Action | `powershell.exe` |
| Arguments | `-NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\PHP2Shell\Scan-PHP2Shell.ps1"` |
| Stop if runs longer than | e.g. 1 hour (align with `--timeout`) |

**Idempotency / concurrency:** Use a lock file or `schtasks` single-instance pattern; skip if lock younger than timeout.

**Offline hosts:** Task runs when machine is on; report collection must tolerate delayed upload ([REPORT-COLLECTION.md](REPORT-COLLECTION.md)).

### Local Scan-PHP2Shell.ps1 (example)

Deploy this file with the EXE (GPP Files or your software distribution).

```powershell
# Example reference — customer must adapt paths and collection
$ErrorActionPreference = 'Stop'
$exe = if (([Environment]::OSVersion.Version.Major -eq 6) -and ([Environment]::OSVersion.Version.Minor -eq 3)) {
  Join-Path ${env:ProgramFiles} 'PHP2Shell\php2shell-windows-legacy-amd64.exe'
} else {
  Join-Path ${env:ProgramFiles} 'PHP2Shell\php2shell-windows-amd64.exe'
}
if (-not (Test-Path -LiteralPath $exe)) { throw "PHP2Shell EXE missing: $exe" }

$outRoot = Join-Path $env:ProgramData 'PHP2Shell\Reports'
New-Item -ItemType Directory -Force -Path $outRoot | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$hostSafe = ($env:COMPUTERNAME -replace '[<>:"/\\|?*]', '-')
$html = Join-Path $outRoot ("php2shell-{0}-{1}.html" -f $hostSafe, $stamp)

& $exe scan --quiet --out $html --timeout 30m
$code = $LASTEXITCODE
# Preserve scanner exit for Task Scheduler history / monitoring
exit $code
```

Exit **2** means reports exist but coverage incomplete — collection should still pick them up.

---

## 5. Central report drop (optional)

GPP or the scan script may copy HTML/CSV/status to:

`\\fileserver\php2shell-reports$\incoming\<hostname>\`

**ACL:** create folders with permissions so computer accounts can write **only** their own subtree (or use a broker service). Never grant Domain Computers Modify on the entire share root without design review.

Do **not** store service-account passwords in GPO preference items or SYSVOL scripts.

---

## 6. Verification

| Check | How |
| --- | --- |
| GPO applied | `gpresult /h gp.html` on a pilot host |
| Task present | `schtasks /Query /TN "PHP2Shell-Inventory-Scan" /V /FO LIST` |
| Last run | Task Scheduler → History; or `ProgramData\PHP2Shell\Reports` |
| Correct EXE | `php2shell-windows-*.exe version` |
| Removal | Unlink GPO; delete task; optionally remove local EXE (retain reports per retention policy) |

---

## 7. Rollback

1. Disable GPO link or remove security filtering.
2. Delete scheduled task via GPO Preferences “Delete” action or manual cleanup.
3. Stop distributing binaries; revoke share ACLs if retiring the product.

---

## 8. Relation to PSADT

For packaged change windows, prefer [PSADT-PHP2Shell-Reference.ps1](../../deploy/PSADT-PHP2Shell-Reference.ps1) invoked by your deployment tool, with GPO used only for recurrence if needed.
