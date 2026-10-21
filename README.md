# PHP2Shell Assessment

**Standalone PHP exposure inventory and incident-triage toolkit for Windows and Linux.** No Python, PHP, or Go installation required on the target server.

> **Alpha preview — actionable patch review, not a vulnerability clearance or compromise detector.** Uses the official PHP2Shell patch thresholds published on 21 October 2026. The runtime actually serving HTTP and vendor backports still require independent verification. No IOC match does not mean no compromise.

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

Run only on systems you own or are authorized to assess. The default scan is local and does not execute PHP, exploit vulnerabilities, or upload customer data. For version evidence collected separately from the web service, see the [official patch guide](docs/OFFICIAL-PHP2SHELL-PATCH-GUIDANCE.md).

## 3. View your results

The scan saves an **HTML action report** plus JSON and CSV in the local `reports/` directory. Open the `.html` file first: it lists observed PHP versions, the minimum official fixed version, recommended fixes, priority and verification gaps. **Windows/IIS cannot yet infer the exact active PHP patch version automatically.**

**What it can do:** compare observed PHP package/repository versions against the official upstream fixes (8.5.12, 8.4.27, 8.3.36, 8.2.35), produce remediation actions; collect partial host evidence and apply separately verified signed IOC packs.

**What it cannot yet do:** independently verify the active HTTP-serving PHP runtime, establish vendor-backport patch status, or reliably rule out past compromise. No validated PHP2Shell-specific compromise-indicator pack is bundled with this alpha.

## Documentation

- [Official PHP2Shell patch levels and response guidance](docs/OFFICIAL-PHP2SHELL-PATCH-GUIDANCE.md)
- [Consultant quick start and additional scanning options](docs/INSTALL-FOR-CONSULTANTS.md)
- [Advanced commands, signed IOC updates and MSSP usage](docs/ADVANCED-USAGE.md)
- [IOC rule format and publishing process](rules/README.md)
- [Security policy](SECURITY.md) and [known limitations](docs/SECURITY-REVIEW-2026-10-21.md)
- [Release checklist for maintainers](docs/RELEASE-CHECKLIST.md)

**Current status:** v2.2.0-alpha.1 · [Changelog](CHANGELOG.md) · [All releases](https://github.com/Opathedane/php2shell/releases)
