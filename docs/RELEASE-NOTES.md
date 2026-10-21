# PHP2Shell 2.3.0

First official public release of the PHP2Shell Security Assessment Scanner.

## Downloads

Standalone binaries (no Python, PHP, or Go required on the target host):

- `php2shell-windows-amd64.zip`
- `php2shell-linux-amd64.tar.gz`
- `php2shell-linux-arm64.tar.gz`
- `php2shell-darwin-amd64.tar.gz` / `php2shell-darwin-arm64.tar.gz` (developer convenience builds)

Verify checksums in `SHA256SUMS`. Release binaries are **not code-signed**.

### Verify download integrity

```bash
# Linux / macOS — from the directory containing the binary and SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

```powershell
Get-FileHash .\php2shell-windows-amd64.exe -Algorithm SHA256
```

Confirm the release is published by the `Opathedane/php2shell` repository and that the tag matches the embedded `php2shell version` string.

## What this release does

- Discovers PHP-related packages, binaries, processes, and configuration on authorized hosts (read-only).
- Compares observed PHP versions to official upstream fix thresholds for the 21 October 2026 advisories (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35).
- Writes a **single self-contained HTML report** with an executive summary, grouped installations, prioritized next steps, and collapsible technical evidence.
- Supports unattended execution (`--quiet`, `--output-dir`, documented exit codes) for consultants and enterprise distribution.
- Optional signed indicator packs for limited compromise-indicator triage (not bundled by default).

## Important limitations (unchanged)

- Does **not** attest which PHP runtime is actively serving HTTP.
- Does **not** verify distribution/vendor security backports.
- Does **not** prove absence of compromise when no indicators match.
- Does **not** upload customer data, modify PHP/webserver configuration, or apply remediation.
- Does **not** execute discovered PHP binaries.

## Quick start

```bash
# Linux
./php2shell-linux-amd64 scan --quiet --output-dir /var/tmp/php2shell

# Windows (PowerShell)
.\php2shell-windows-amd64.exe scan --quiet --output-dir C:\ProgramData\PHP2Shell\Reports
```

Open the generated HTML report locally. See [INSTALL-FOR-CONSULTANTS.md](INSTALL-FOR-CONSULTANTS.md) and [ADVANCED-USAGE.md](ADVANCED-USAGE.md).

## Supported platforms (tested in CI)

- Linux (ubuntu-24.04 runners)
- Windows (windows-latest runners)
- macOS Intel (macos-15-intel runners)

macOS ARM64 binaries are built for convenience; CI currently validates darwin/amd64 rather than native arm64 runners.
