<#
.SYNOPSIS
  Reference PSAppDeployToolkit-style wrapper for PHP2Shell (not a full PSADT package).

.DESCRIPTION
  - Selects legacy vs standard Windows EXE (2012 R2 vs modern).
  - Runs scan --quiet with unique output-dir (avoids overwrite exit 1).
  - Treats exit 0 and 2 as eligible for report upload; exit 1 is failure.
  - Surfaces stderr status line and .status.json paths.

  Copy patterns into Deploy-Application.ps1; adjust $DirFiles / upload logic for your tenant.
  Does not implement customer-specific upload APIs.

.NOTES
  Preflight: if the wrong EXE is deployed to Server 2012 R2, CreateProcess fails before PHP2Shell runs.
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
$p = Start-Process -FilePath $exe -ArgumentList $argList -Wait -PassThru -NoNewWindow
$code = $p.ExitCode

$csv = [System.IO.Path]::ChangeExtension($outHtml, '.csv')
$status = ($outHtml -replace '\.html$', '.status.json')

Write-Output "ExitCode=$code HTML=$outHtml CSV=$csv STATUS=$status"

# Upload eligibility: reports present on 0 or 2
$uploadOk = ($code -eq 0 -or $code -eq 2) -and (Test-Path -LiteralPath $outHtml) -and (Test-Path -LiteralPath $csv)
if (-not $uploadOk) {
    throw "PHP2Shell fatal or missing reports (exit=$code). Do not treat as clean host. See docs/EXIT-CODES-AND-DEPLOYMENT.md"
}

Write-Output "Reports eligible for upload (exit $code). Review status JSON for SCAN_INCOMPLETE before closing the engagement."
# exit 0 from wrapper after successful collection — or exit $code to preserve incomplete signal upstream
exit 0
