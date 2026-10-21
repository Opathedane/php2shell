# PHP2Shell – consultant quick start

**This tool does not certify a server as patched or uncompromised.** Use it for authorized inventory and evidence-qualified patch review.

Download the build matching the destination server from GitHub **Releases**. No Python, Go, PHP, installer, or network access is required for the basic local inventory. The optional IOC update requires an independently authenticated rule signing key and a reviewed signed ruleset; the repository does **not** include a validated PHP2Shell-specific rulepack yet.

## Windows Server x64 (PowerShell)

Download `php2shell-windows-amd64.zip`, extract, and run in PowerShell:

```powershell
.\php2shell-windows-amd64.exe doctor
.\php2shell-windows-amd64.exe scan
```

For an explicitly authorized IIS assessment (adjust paths):

```powershell
.\php2shell-windows-amd64.exe scan --webroot 'C:\inetpub\wwwroot' --access-log 'C:\inetpub\logs\LogFiles\W3SVC1\u_ex261021.log'
```

Windows executables are **not Authenticode signed** and may generate SmartScreen warnings. Do not bypass endpoint protection or organizational application-control policy. Contact your security administrator for approval; do not run with admin privileges unless reading specific authorized artifacts requires them.

## Linux x86-64

Download `php2shell-linux-amd64.tar.gz`, extract, and run:

```bash
tar xzf php2shell-linux-amd64.tar.gz
chmod +x php2shell-linux-amd64
./php2shell-linux-amd64 doctor
./php2shell-linux-amd64 scan
```

Optional authorized evidence (adjust paths):

```bash
./php2shell-linux-amd64 scan --webroot /var/www --access-log /var/log/nginx/access.log
```

Linux ARM64 has `php2shell-linux-arm64.tar.gz`; macOS builds are included for consultant convenience.

## Reports and integrity

Each scan writes **one HTML report** only (unique hostname + UTC timestamp). Defaults:

- Windows: `C:\ProgramData\PHP2Shell\Reports`
- Linux/macOS: `$HOME/.php2shell/reports`

Use `--output-dir` for a central share (including UNC when the account already has access) or `--out path.html` for an explicit name. Existing files are never overwritten. Keep reports private: they may contain server names and file paths.

**Unattended / GPO / scheduled task:** prefer `scan --quiet --output-dir DIR`. No prompts, no browser, no elevation request. Exit codes: `0` report written, `1` fatal error, `2` report written but incomplete. When running as SYSTEM to a UNC path, grant the computer account (`DOMAIN\MACHINE$`) share and NTFS permissions; the scanner does not map drives or upload data.

Verify download against `SHA256SUMS` **from a trusted GitHub release** (checksums do not replace binary signing):

- Linux/macOS: `sha256sum php2shell-linux-amd64` and compare to the published checksum.
- Windows: `Get-FileHash .\php2shell-windows-amd64.exe -Algorithm SHA256`.

If no approved signed IOC pack is configured, the scanner performs inventory and coverage assessment **only**. Even with signed IOCs, no match does **not** prove there was no compromise. The actual runtime behind the web service and backported vendor fixes are not attested by this scanner.

## Official PHP2Shell patch assessment (21 October 2026)

The HTML action report now compares observed PHP package and repository patch versions with the official upstream minima: **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**. It suggests the next steps for every comparable observation.

When you have independently examined a web-serving PHP runtime (such as an approved IIS/FastCGI deployment inventory or FPM pool change record), record the *reported* version and evidence source:

```powershell
.\php2shell-windows-amd64.exe scan --runtime-version 8.4.26 --runtime-sapi iis-fastcgi --runtime-source "verified IIS FastCGI deployment record 2026-10-21"
```

```bash
./php2shell-linux-amd64 scan --runtime-version 8.5.11 --runtime-sapi apache-mod_php --runtime-source "approved Apache module deployment record 2026-10-21"
```

This is **operator-supplied** information, not an automatic verification: confirm the running worker after the update. A Linux vendor security backport may fix both CVEs without matching the upstream version numbers. Record the exact package release and vendor advisory separately; do not classify it as unpatched on version comparison alone.

See [official patch guidance](OFFICIAL-PHP2SHELL-PATCH-GUIDANCE.md) for interim mitigation limits and post-patch verification. No IOC match cannot rule out previous exploitation.
