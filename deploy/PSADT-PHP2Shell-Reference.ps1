<#
.SYNOPSIS
  Reference PSAppDeployToolkit-style wrapper for PHP2Shell (not a full PSADT package).

.DESCRIPTION
  Integration contract (keep customer-specific uploads OUT of this script):

  Exit codes (scanner)
  - 0 : completed; HTML+CSV written (findings may still exist)
  - 1 : fatal; usually no usable report pair — fail the deployment step
  - 2 : completed with incomplete coverage; HTML+CSV written — still collect

  This wrapper defaults to exiting with the **scanner's exit code** so Intune/PSADT/
  Task Scheduler see incomplete (2) distinctly from success (0). Pass
  -NormalizeSuccessExit to map 0/2 → 0 for tools that cannot accept exit 2.

  Reports
  - Require HTML + CSV on exit 0 or 2 before considering collection eligible
  - Unique --out names (host + UTC) avoid overwrite → exit 1 / stale reuse
  - Reject pairing this run with older HTML when exit is 1

  Status JSON (machine-readable)
  - Sibling report.status.json or *.failed-<execution_id>.status.json
  - Read status_json_written, error_ids, scan_incomplete, execution_id
  - Missing status with HTML+CSV present = packaging defect; still collect reports

  Customer uploads
  - Implement externally — see docs/deployment/REPORT-COLLECTION.md

.NOTES
  Preflight: wrong EXE on Server 2012 R2 fails before PHP2Shell runs.
  Demonstrated: local EXE selection + report validation patterns.
  Untested here: your PSADT Deploy-Application.ps1, Intune tenant, SMB ACLs.
  See docs/EXIT-CODES-AND-DEPLOYMENT.md and docs/WINDOWS-LEGACY-2012R2.md.
#>

[CmdletBinding()]
param(
    [string]$DeployRoot = $PSScriptRoot,
    [string]$OutputRoot = $(Join-Path $env:ProgramData 'PHP2Shell\Reports'),
    [switch]$AcceptIncomplete,
    # When set, wrapper exits 0 for scanner 0 or 2 (collection-oriented soft success).
    [switch]$NormalizeSuccessExit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsWindows2012R2 {
    try {
        $v = [System.Environment]::OSVersion.Version
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

$runStartedUtc = (Get-Date).ToUniversalTime()
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
$stamp = $runStartedUtc.ToString('yyyyMMddTHHmmssZ')
$hostSafe = ($env:COMPUTERNAME -replace '[<>:"/\\|?*]', '-')
$outHtml = Join-Path $OutputRoot ("php2shell-{0}-{1}.html" -f $hostSafe, $stamp)
$stderrLog = Join-Path $OutputRoot ("php2shell-{0}-{1}.stderr.log" -f $hostSafe, $stamp)

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
    -RedirectStandardError $stderrLog
$code = $p.ExitCode

$csv = [System.IO.Path]::ChangeExtension($outHtml, '.csv')
$preferredStatus = ($outHtml -replace '\.html$', '.status.json')
$status = Find-StatusJson -HtmlPath $outHtml -PreferredStatus $preferredStatus

Write-Output "ExitCode=$code HTML=$outHtml CSV=$csv STATUS=$status STDERR=$stderrLog"

$htmlOk = Test-Path -LiteralPath $outHtml
$csvOk = Test-Path -LiteralPath $csv

# Fatal: exit 1, or missing report pair — never treat as success; do not collect stale priors as this run
if ($code -eq 1 -or -not ($htmlOk -and $csvOk)) {
    throw "PHP2Shell fatal or missing reports (exit=$code html=$htmlOk csv=$csvOk). Do not upload prior-run HTML as this execution. See docs/EXIT-CODES-AND-DEPLOYMENT.md"
}

if ($code -ne 0 -and $code -ne 2) {
    throw "PHP2Shell unexpected exit=$code"
}

# Stale guard: HTML must be newer than wrapper start (minus small skew)
$htmlItem = Get-Item -LiteralPath $outHtml
if ($htmlItem.LastWriteTimeUtc -lt $runStartedUtc.AddMinutes(-5)) {
    throw "STALE_REPORT: $outHtml is older than this run start; refusing to treat as current results"
}

$statusObj = $null
if (-not $status) {
    Write-Warning "STATUS_JSON_MISSING: HTML+CSV present but no .status.json (packaging/permissions defect). Collect reports; fix ACLs. Do not treat as clearance."
} else {
    try {
        $statusObj = Get-Content -LiteralPath $status -Raw | ConvertFrom-Json
    } catch {
        Write-Warning "STATUS_JSON_UNREADABLE: $status ($($_.Exception.Message))"
    }
}

$collectionEligible = $true
if ($null -ne $statusObj) {
    if ($statusObj.PSObject.Properties.Name -contains 'status_json_written' -and -not $statusObj.status_json_written) {
        Write-Warning "status_json_written=false in $status"
    }
    $ids = @()
    if ($statusObj.error_ids) { $ids = @($statusObj.error_ids) }
    if ($ids -contains 'OUTPUT_WRITE_FAILED') {
        Write-Warning "OUTPUT_WRITE_FAILED recorded (fallback or failure). status_json_path=$($statusObj.status_json_path)"
    }
    if ($code -eq 2 -or $statusObj.scan_incomplete -or $statusObj.execution_status -eq 'COMPLETED_INCOMPLETE' -or ($ids -contains 'SCAN_INCOMPLETE')) {
        Write-Warning "SCAN_INCOMPLETE: collect reports but do not close as cleared (execution_status=$($statusObj.execution_status))"
    }
    if ($statusObj.PSObject.Properties.Name -contains 'reports_written' -and -not $statusObj.reports_written) {
        $collectionEligible = $false
        Write-Warning "reports_written=false — not collection-eligible"
    }
    Write-Output ("Status execution_id={0} execution_status={1} exit_code={2} status_json_written={3} errors={4}" -f `
        $statusObj.execution_id, $statusObj.execution_status, $statusObj.exit_code, $statusObj.status_json_written, ($ids -join ','))
}

if (-not $collectionEligible) {
    throw "Reports not collection-eligible"
}

Write-Output "Reports collection-eligible (scanner exit $code). Upload/copy is customer-specific — see docs/deployment/REPORT-COLLECTION.md. Generation success ≠ upload success."

if ($NormalizeSuccessExit -and ($code -eq 0 -or $code -eq 2)) {
    exit 0
}
exit $code
