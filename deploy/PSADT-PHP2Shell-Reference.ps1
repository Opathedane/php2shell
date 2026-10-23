<#
.SYNOPSIS
  Reference PSAppDeployToolkit-style wrapper for PHP2Shell (not a full PSADT package).

.DESCRIPTION
  Integration contract (keep customer-specific uploads OUT of this script):

  Exit codes
  - 0 : completed; HTML+CSV written (findings may still exist)
  - 1 : fatal; usually no usable report pair — fail the deployment step
  - 2 : completed with incomplete coverage; HTML+CSV written — still upload

  Reports
  - Require HTML + CSV on exit 0 or 2 before considering collection successful
  - Prefer unique --out names (timestamp) to avoid overwrite → exit 1 / stale reuse

  Status JSON (machine-readable)
  - Default sibling: report.html → report.status.json
  - Fields: execution_status, exit_code, error_ids, reports_written,
    status_json_written, scan_incomplete, html/csv/status paths, remediation
  - If primary status path fails, the tool may write an execution-scoped or
    HTML-sibling fallback; on-disk JSON then includes OUTPUT_WRITE_FAILED
  - Automation MUST read status_json_written / error_ids — do not rely on stderr alone
  - Missing status file when HTML+CSV exist = packaging/permissions defect; still
    collect HTML+CSV, do not treat as “scan never ran”

  Incomplete scans
  - exit 2 or status execution_status=COMPLETED_INCOMPLETE / SCAN_INCOMPLETE
  - Upload reports; do not close the engagement as cleared

  Stale outputs
  - Never point --out at a fixed SERVER.html; use host+UTC stamp
  - Do not upload older HTML/CSV from a previous run when the current exit is 1

  Customer uploads
  - Implement tenant upload externally (Intune win32 detection, PSADT copy, SIEM drop)
  - This reference only validates local artifacts and exit-code policy

.NOTES
  Preflight: if the wrong EXE is deployed to Server 2012 R2, CreateProcess fails before PHP2Shell runs.
  See docs/EXIT-CODES-AND-DEPLOYMENT.md and docs/WINDOWS-LEGACY-2012R2.md.
#>

[CmdletBinding()]
param(
    [string]$DeployRoot = $PSScriptRoot,
    [string]$OutputRoot = $(Join-Path $env:ProgramData 'PHP2Shell\Reports'),
    [switch]$AcceptIncomplete
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsWindows2012R2 {
    try {
        $v = [System.Environment]::OSVersion.Version
        # 6.3 = Windows 8.1 / Server 2012 R2 (verify ProductType in production if needed)
        return ($v.Major -eq 6 -and $v.Minor -eq 3)
    } catch {
        return $false
    }
}

function Find-StatusJson([string]$HtmlPath, [string]$PreferredStatus) {
    $candidates = @()
    if ($PreferredStatus) { $candidates += $PreferredStatus }
    $candidates += ($HtmlPath -replace '\.html$', '.status.json')
    $dir = Split-Path -Parent $HtmlPath
    $base = [System.IO.Path]::GetFileNameWithoutExtension($HtmlPath)
    if (Test-Path -LiteralPath $dir) {
        Get-ChildItem -LiteralPath $dir -Filter ($base + '.failed-*.status.json') -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending |
            ForEach-Object { $candidates += $_.FullName }
    }
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    return $null
}

$standard = Join-Path $DeployRoot 'php2shell-windows-amd64.exe'
$legacy = Join-Path $DeployRoot 'php2shell-windows-legacy-amd64.exe'

if (Test-IsWindows2012R2) {
    $exe = $legacy
    if (-not (Test-Path -LiteralPath $exe)) {
        throw "UNSUPPORTED_OS preflight: Server 2012 R2 requires php2shell-windows-legacy-amd64.exe at $exe"
    }
} else {
    $exe = $standard
    if (-not (Test-Path -LiteralPath $exe)) {
        throw "Missing standard EXE: $exe"
    }
}

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$hostSafe = ($env:COMPUTERNAME -replace '[<>:"/\\|?*]', '-')
$outHtml = Join-Path $OutputRoot ("php2shell-{0}-{1}.html" -f $hostSafe, $stamp)

$argList = @(
    'scan',
    '--quiet',
    '--out', $outHtml
)
if ($AcceptIncomplete) {
    $argList += '--accept-incomplete'
}

Write-Output "Running: $exe $($argList -join ' ')"
$p = Start-Process -FilePath $exe -ArgumentList $argList -Wait -PassThru -NoNewWindow `
    -RedirectStandardError (Join-Path $OutputRoot ("php2shell-{0}-{1}.stderr.log" -f $hostSafe, $stamp))
$code = $p.ExitCode

$csv = [System.IO.Path]::ChangeExtension($outHtml, '.csv')
$preferredStatus = ($outHtml -replace '\.html$', '.status.json')
$status = Find-StatusJson -HtmlPath $outHtml -PreferredStatus $preferredStatus

Write-Output "ExitCode=$code HTML=$outHtml CSV=$csv STATUS=$status"

$htmlOk = Test-Path -LiteralPath $outHtml
$csvOk = Test-Path -LiteralPath $csv
$statusOk = [bool]$status

# Fatal: exit 1, or 0/2 without report pair
if ($code -eq 1 -or -not ($htmlOk -and $csvOk)) {
    throw "PHP2Shell fatal or missing reports (exit=$code html=$htmlOk csv=$csvOk). Do not treat as clean host. See docs/EXIT-CODES-AND-DEPLOYMENT.md"
}

if ($code -ne 0 -and $code -ne 2) {
    throw "PHP2Shell unexpected exit=$code"
}

# Status JSON is required for machine-readable incomplete / write-failure detection.
$statusObj = $null
if (-not $statusOk) {
    Write-Warning "STATUS_JSON_MISSING: HTML+CSV present but no .status.json (packaging/permissions defect). Collect reports; fix output ACLs. Do not treat as clearance."
} else {
    try {
        $statusObj = Get-Content -LiteralPath $status -Raw | ConvertFrom-Json
    } catch {
        Write-Warning "STATUS_JSON_UNREADABLE: $status ($($_.Exception.Message))"
    }
}

if ($null -ne $statusObj) {
    if ($statusObj.PSObject.Properties.Name -contains 'status_json_written' -and -not $statusObj.status_json_written) {
        Write-Warning "status_json_written=false in $status"
    }
    $ids = @()
    if ($statusObj.error_ids) { $ids = @($statusObj.error_ids) }
    if ($ids -contains 'OUTPUT_WRITE_FAILED') {
        Write-Warning "OUTPUT_WRITE_FAILED recorded in status JSON (fallback path or total failure). Verify status_json_path=$($statusObj.status_json_path)"
    }
    if ($code -eq 2 -or $statusObj.scan_incomplete -or $statusObj.execution_status -eq 'COMPLETED_INCOMPLETE' -or ($ids -contains 'SCAN_INCOMPLETE')) {
        Write-Warning "SCAN_INCOMPLETE: upload reports but do not close as cleared (execution_status=$($statusObj.execution_status))"
    }
    Write-Output ("Status execution_status={0} exit_code={1} status_json_written={2} errors={3}" -f `
        $statusObj.execution_status, $statusObj.exit_code, $statusObj.status_json_written, ($ids -join ','))
}

Write-Output "Reports eligible for upload (exit $code). Review HTML patch assessment first; DFIR/WAF sections are secondary. Customer upload remains external."
# Preserve incomplete signal for upstream detection rules when desired:
# exit $code
exit 0
