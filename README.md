# PHP2Shell Assessment

**Standalone PHP exposure inventory and incident-triage toolkit for Windows and Linux.** No Python, PHP, or Go installation required on the target server.

> **Alpha preview — not a vulnerability clearance tool.** This version cannot confirm whether a server is affected by CVE-2026-109618 / CVE-2026-109619 or whether it has been compromised. Do not treat an empty scan or missing IOC match as proof of safety.

## 1. Download

**[Download the latest available alpha release](https://github.com/Opathedane/php2shell/releases)**

Choose the archive matching your system:

- **Windows (x64):** `php2shell-windows-amd64.zip`
- **Linux (x64):** `php2shell-linux-amd64.tar.gz`
- **Linux (ARM64):** `php2shell-linux-arm64.tar.gz`

Extract the archive. These binaries are **unsigned development previews**; verify release checksums and obtain approval before use on production servers.

## 2. Run a scan

**Windows Server — PowerShell:**

```powershell
.\php2shell-windows-amd64.exe scan
```

**Linux — terminal:**

```bash
chmod +x php2shell-linux-amd64
./php2shell-linux-amd64 scan
```

Run only on systems you own or are authorized to assess. The default scan is local and does not execute PHP, exploit vulnerabilities, or upload customer data.

## 3. View your results

The scan saves an **HTML report** along with JSON and CSV files in the local `reports/` directory. Open the `.html` file to review observed PHP evidence, checks performed, and coverage gaps.

**What it can do:** collect partial host evidence; review specified webroots, repository metadata and HTTP logs; and evaluate *verified, separately provided* signed IOC rules.

**What it cannot yet do:** verify the PHP runtime serving web requests, establish vendor patch status, or reliably rule out past compromise. No validated PHP2Shell-specific indicator pack is bundled with this alpha.

## Documentation

- [Consultant quick start and additional scanning options](docs/INSTALL-FOR-CONSULTANTS.md)
- [Advanced commands, signed IOC updates and MSSP usage](docs/ADVANCED-USAGE.md)
- [IOC rule format and publishing process](rules/README.md)
- [Security policy](SECURITY.md) and [known limitations](docs/SECURITY-REVIEW-2026-10-21.md)
- [Release checklist for maintainers](docs/RELEASE-CHECKLIST.md)

**Current status:** v2.1.0-alpha.2 · [Changelog](CHANGELOG.md) · [All releases](https://github.com/Opathedane/php2shell/releases)
