# PHP2Shell – standalone preview: consultant quick start

**TEST / TRIAGE ONLY. This does not certify a server as PHP2Shell-safe or uncompromised.**

Download the file matching the destination server from the repository's GitHub **Releases**. No Python, Go, PHP, installer, or network access is required for the basic local inventory. The optional IOC update requires an independently authenticated rule signing key and a reviewed signed ruleset; the repository does **not** include a validated PHP2Shell-specific rulepack yet.

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

Windows executables in this alpha are **not Authenticode signed** and may generate SmartScreen warnings. Do not bypass endpoint protection or organizational application-control policy. Contact your security administrator for approval; do not run with admin privileges unless reading specific authorized artifacts requires them.

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

Linux ARM64 has `php2shell-linux-arm64.tar.gz`; macOS is also included as a developer preview.

## Reports and integrity

The default command creates `.html`, `.json`, `.csv` in `reports/` without overwriting files. Open `.html` locally. Keep files private: they may contain server names and file paths.

Verify download against `SHA256SUMS` **from a trusted GitHub release** (checksums do not replace binary signing):

- Linux/macOS: `sha256sum php2shell-linux-amd64` and compare to the published checksum.
- Windows: `Get-FileHash .\php2shell-windows-amd64.exe -Algorithm SHA256`.

If no approved signed IOC pack is configured, the scanner performs inventory and coverage assessment **only**. Even with signed IOCs, no match does **not** prove there was no compromise. The actual runtime behind the web service and backported vendor fixes are not attested by this alpha.
