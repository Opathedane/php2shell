# PHP2Shell

**Find PHP on a host, compare it to the October 2026 critical security fixes, and see what to do next.**

PHP2Shell is a **read-only**, offline-friendly scanner for Windows and Linux. It writes a local **HTML + CSV** report pair (plus a small **status JSON** file). It does **not** exploit systems, execute discovered PHP binaries, upload your data, or prove that a host is uncompromised.

**Version in this tree:** 2.7.2 (unreleased). Latest public release: [v2.7.1](https://github.com/Opathedane/php2shell/releases/tag/v2.7.1).

| Currently assessed | Detail |
| --- | --- |
| **CVE-2026-109618**, **CVE-2026-109619** | Upstream fixes: **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** (21 Oct 2026) |
| **CVE-2026-115560** | Informational only — prefer `session.upload_progress.enabled=0`; **no fixed versions invented** |

## Documentation map

| Start here | |
| --- | --- |
| **Getting started** | Sections below |
| **Understanding reports** | [docs/UNDERSTANDING-REPORTS.md](docs/UNDERSTANDING-REPORTS.md) |
| **Enterprise deployment** | [Intune](docs/deployment/INTUNE.md) · [Group Policy](docs/deployment/GPO.md) · [PSADT](deploy/PSADT-PHP2Shell-Reference.ps1) · [Report collection](docs/deployment/REPORT-COLLECTION.md) |
| **Exit codes** | [docs/EXIT-CODES-AND-DEPLOYMENT.md](docs/EXIT-CODES-AND-DEPLOYMENT.md) |
| **DFIR / advanced** | [COMPROMISE-INVESTIGATION.md](docs/COMPROMISE-INVESTIGATION.md) · [ADVANCED-USAGE.md](docs/ADVANCED-USAGE.md) |
| **Security & verification** | SHA256 below · [signing plan](docs/deployment/AUTHENTICODE-IMPLEMENTATION.md) · [LICENSING-DECISION.md](docs/LICENSING-DECISION.md) |
| **Release acceptance** | [RELEASE-ACCEPTANCE-CHECKLIST-2.7.2.md](docs/RELEASE-ACCEPTANCE-CHECKLIST-2.7.2.md) · [field tests](docs/FIELD-ACCEPTANCE-TESTS-2.7.2.md) |
| **Troubleshooting** | Exit codes doc · `php2shell doctor` · GitHub Issues |

---

## 1. What PHP2Shell does (and does not)

### Does

- **PHP discovery** — packages (dpkg/apk), binaries, PATH/well-known paths, IIS/Apache hints, optional authorized roots
- **Vulnerability / patch assessment** — compare observed versions to official upstream thresholds; call out vendor-verification cases
- **Reporting** — HTML for humans, CSV for fleet rollup, status JSON for automation
- **Optional compromise investigation** — only when you supply logs / telemetry / webroot / WAF exports

### Does not

- Attest which PHP process is **actually serving HTTP**
- Prove a **vendor backport** without your vendor evidence
- Inventory **RPM** package databases in this release (binary discovery still runs)
- Declare the host **clean**, **safe**, or **uncompromised**

---

## 2. Choose and verify the executable

| Platform | Download |
| --- | --- |
| Windows 10 / 11 / Server 2016+ | `php2shell-windows-amd64.zip` |
| Windows Server **2012 R2** | `php2shell-windows-legacy-amd64.zip` — [WINDOWS-LEGACY-2012R2.md](docs/WINDOWS-LEGACY-2012R2.md) |
| Linux amd64 / arm64 | `php2shell-linux-*.tar.gz` |

1. Get files from [GitHub Releases](https://github.com/Opathedane/php2shell/releases/latest).
2. Verify checksums against `SHA256SUMS` (Windows: `Get-FileHash … -Algorithm SHA256`).
3. Binaries are **not Authenticode-signed** today — [signing plan](docs/deployment/DISTRIBUTION-SIGNING.md).

**Licensing:** only `LICENSE.proposed` exists — **no approved open-source license is in force** until the maintainer confirms ownership rights ([LICENSING.md](docs/LICENSING.md)). Do not redistribute broadly until that is resolved.

---

## 3. Quick Start (interactive)

Use these commands the first time you try the tool. **Do not use `--quiet` here** — you want progress and a readable summary.

### Windows (PowerShell)

```powershell
.\php2shell-windows-amd64.exe doctor
.\php2shell-windows-amd64.exe scan --output-dir $env:ProgramData\PHP2Shell\Reports
```

Server 2012 R2:

```powershell
.\php2shell-windows-legacy-amd64.exe doctor
.\php2shell-windows-legacy-amd64.exe scan --output-dir $env:ProgramData\PHP2Shell\Reports
```

### Linux

```bash
chmod +x php2shell-linux-amd64
./php2shell-linux-amd64 doctor
./php2shell-linux-amd64 scan --output-dir "$HOME/.php2shell/reports"
```

Open the newest `php2shell-*.html` in a browser. Read **Patch assessment** first — [Understanding reports](docs/UNDERSTANDING-REPORTS.md).

### Unattended / automation

Add `--quiet` so progress is suppressed; **errors and the status line still go to stderr**, and `.status.json` remains machine-readable:

```powershell
.\php2shell-windows-amd64.exe scan --quiet --output-dir $env:ProgramData\PHP2Shell\Reports
```

---

## 4. Feature overview

| Area | Capabilities |
| --- | --- |
| **PHP discovery** | dpkg/apk, Windows/Linux well-known + PATH binaries, `--php-ini` / `--config-root` / optional `--deep-root` |
| **Patch assessment** | CVE-2026-109618 / 109619 thresholds; EOL/vendor verification; RC rejection; multi-install grouping |
| **Additional advisory** | CVE-2026-115560 from observed php.ini text only |
| **Optional IR** | `--access-log`, `--error-log`, `--process-telemetry`, `--webroot`, `--waf-log` |
| **Reporting** | HTML + CSV + status JSON; `php2shell rollup` for fleet CSV |
| **Enterprise** | Exit 0/1/2 contract; Intune / GPO / PSADT guides under `docs/deployment/` |

---

## 5. Exit codes

| Code | Meaning |
| --- | --- |
| **0** | HTML+CSV written |
| **1** | Fatal (reports often missing) |
| **2** | HTML+CSV written, coverage incomplete — **still collect** |

Exit 0 is **not** a security clearance. Details: [EXIT-CODES-AND-DEPLOYMENT.md](docs/EXIT-CODES-AND-DEPLOYMENT.md).

---

## 6. Enterprise deployment

- [Intune Win32](docs/deployment/INTUNE.md) — **clients**; not a substitute for Server management
- [Group Policy](docs/deployment/GPO.md) — Server-friendly patterns
- [PSADT reference](deploy/PSADT-PHP2Shell-Reference.ps1)
- [Report collection](docs/deployment/REPORT-COLLECTION.md)

---

## 7. More documentation

| Topic | Doc |
| --- | --- |
| Consultant install notes | [INSTALL-FOR-CONSULTANTS.md](docs/INSTALL-FOR-CONSULTANTS.md) |
| Official patch guidance notes | [OFFICIAL-PHP2SHELL-PATCH-GUIDANCE.md](docs/OFFICIAL-PHP2SHELL-PATCH-GUIDANCE.md) |
| Release notes | [RELEASE-NOTES.md](docs/RELEASE-NOTES.md) · [v2.7.2 draft](docs/releases/v2.7.2.md) |
| Enterprise QA report | [ENTERPRISE-QA-READINESS-2.7.2.md](docs/ENTERPRISE-QA-READINESS-2.7.2.md) |
| Final readiness (this phase) | [FINAL-DISTRIBUTION-READINESS-2.7.2.md](docs/FINAL-DISTRIBUTION-READINESS-2.7.2.md) |

Report bugs or incorrect assessments via GitHub Issues.

---

## 8. Safety defaults

Read-only local scan · no PHP execution · no automatic upload · no browser open · offline by default.
