# PHP2Shell

**Assess whether PHP installations may need updating for the October 2026 critical advisories — and what to do next.**

PHP2Shell is a read-only Windows/Linux scanner. It discovers PHP on a host, compares observed versions to official upstream fix thresholds, and writes a local **HTML + CSV** report pair. It does **not** prove a host is fully patched or uncompromised.

**Version in this tree:** 2.7.2 (unreleased). Latest public release: [v2.7.1](https://github.com/Opathedane/php2shell/releases/tag/v2.7.1).

| | |
| --- | --- |
| **Primary CVEs** | CVE-2026-109618, CVE-2026-109619 (upstream fixes 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) |
| **Additional advisory** | CVE-2026-115560 (informational; no fixed versions yet — prefer `session.upload_progress.enabled=0`) |

## 1. Choose the right executable

| Platform | Asset |
| --- | --- |
| Windows 10 / Server 2016+ | `php2shell-windows-amd64.zip` |
| Windows Server **2012 R2** | `php2shell-windows-legacy-amd64.zip` (Go 1.20 legacy — see [WINDOWS-LEGACY-2012R2.md](docs/WINDOWS-LEGACY-2012R2.md)) |
| Linux amd64 / arm64 | `php2shell-linux-amd64.tar.gz` / `php2shell-linux-arm64.tar.gz` |
| macOS | darwin amd64/arm64 archives (consultant use) |

1. Download from [GitHub Releases](https://github.com/Opathedane/php2shell/releases/latest).
2. Verify `SHA256SUMS`.
3. Builds are **not Authenticode-signed**.

## 2. First scan

**Windows (PowerShell):**

```powershell
.\php2shell-windows-amd64.exe doctor
.\php2shell-windows-amd64.exe scan --quiet --output-dir C:\ProgramData\PHP2Shell\Reports
```

**Linux:**

```bash
chmod +x php2shell-linux-amd64
./php2shell-linux-amd64 doctor
./php2shell-linux-amd64 scan --quiet --output-dir "$HOME/.php2shell/reports"
```

Each successful scan writes `*.html`, `*.csv`, and `*.status.json` with a unique basename.

| Exit | Meaning |
| --- | --- |
| **0** | Reports written |
| **1** | Fatal (often no reports) |
| **2** | Reports written, coverage incomplete — still collect them |

Exit **0** is not a security clearance. Deployment guide: [EXIT-CODES-AND-DEPLOYMENT.md](docs/EXIT-CODES-AND-DEPLOYMENT.md). PSADT reference: [deploy/PSADT-PHP2Shell-Reference.ps1](deploy/PSADT-PHP2Shell-Reference.ps1).

## 3. How to read the result

1. Open the **HTML** report.
2. Read **Patch assessment** first (update vs verify vs inconclusive).
3. Check **PHP installations found** and recommended next steps.
4. Review **What could not be verified** (runtime, package DB, permissions).
5. Treat CVE-2026-115560 (if present) as a separate, conservative config review — not a replacement for patching 109618/109619.

CSV is for fleet rollup (`php2shell rollup`). Advanced IR/WAF/IOC: [COMPROMISE-INVESTIGATION.md](docs/COMPROMISE-INVESTIGATION.md), [ADVANCED-USAGE.md](docs/ADVANCED-USAGE.md).

## 4. What PHP2Shell cannot establish

- That the **HTTP-serving** PHP runtime is the version observed in packages/binaries
- That a vendor **backport** is present when the version string is still below upstream
- That the host is **uncompromised** (or compromised) without authorized investigation inputs
- Full package inventory on **RPM**-based Linux (dpkg/apk only in this release)

Authoritative updates: [php.net archive 2026](https://www.php.net/archive/2026.php), [supported versions](https://www.php.net/supported-versions.php), your OS/vendor security advisories.

## 5. More documentation

| Topic | Doc |
| --- | --- |
| Consultant install | [INSTALL-FOR-CONSULTANTS.md](docs/INSTALL-FOR-CONSULTANTS.md) |
| Release notes | [RELEASE-NOTES.md](docs/RELEASE-NOTES.md) |
| v2.7.2 draft | [releases/v2.7.2.md](docs/releases/v2.7.2.md) |
| Enterprise QA / readiness | [ENTERPRISE-QA-READINESS-2.7.2.md](docs/ENTERPRISE-QA-READINESS-2.7.2.md) |
| Licensing (not yet approved) | [LICENSING.md](docs/LICENSING.md), `LICENSE.proposed` |
| Report bugs / wrong assessment | GitHub Issues |

## 6. Safety defaults

Read-only local scan · no execution of discovered PHP · no automatic upload · no browser open · offline by default.
