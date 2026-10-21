# PHP2Shell Assessment

Standalone Windows and Linux scanner for **PHP discovery, patch review and limited compromise-indicator triage**.

> **Alpha / testing only.** The scanner does not verify the live HTTP-serving PHP runtime, cannot verify distro backports, and cannot rule out compromise. Never interpret a missing finding as proof of safety.

## Download

[**Download the latest standalone release**](https://github.com/Opathedane/php2shell/releases)

Choose `php2shell-windows-amd64.zip`, `php2shell-linux-amd64.tar.gz`, or `php2shell-linux-arm64.tar.gz`. No Python, PHP or Go installation is required. Release builds are **not code-signed**; verify checksums and seek authorization before production use.

## Scan

**Windows (PowerShell):**

```powershell
.\php2shell-windows-amd64.exe scan
```

**Linux:**

```bash
chmod +x php2shell-linux-amd64
./php2shell-linux-amd64 scan
```

The scanner creates an **HTML action report**, plus JSON and CSV, under `reports/`. Open the HTML file first.

The report answers, with qualifications:

- **Was PHP-related evidence found?** A negative discovery is *not* proof that PHP is absent.
- **Does an observed PHP version require an urgent patch review?** It compares evidence to official PHP security releases and gives concrete upgrade targets.
- **Were compromise indicators matched?** Only when verified signed rules and eligible evidence are available. **No validated PHP2Shell-specific IOC pack is bundled**, so the default scan does not determine whether exploitation occurred.
- **What next?** It lists actions and records incomplete checks.

### Official minimum fixed versions (21 October 2026)

| PHP branch | First upstream fixed release |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 and older | Upgrade to a supported branch, or verify documented vendor/LTS backport |

**Use the update method for your actual deployment** (OS vendor packages, PHP Windows build, or rebuilt container), then restart workers and verify the web-serving runtime. A PHP CLI version is not necessarily the deployed runtime. See [official PHP advisory](https://www.php.net/archive/2026.php).

## More information

- [Patch instructions, supported branches and mitigations](docs/OFFICIAL-PHP2SHELL-PATCH-GUIDANCE.md)
- [Consultant instructions and log scanning](docs/INSTALL-FOR-CONSULTANTS.md)
- [IOC rule signing and update limitations](rules/README.md)
- [Advanced commands and optional integrations](docs/ADVANCED-USAGE.md)
- [Security and responsible disclosure](SECURITY.md)
- [Independent checks and open risks](docs/REVIEW-2026-10-21.md) and [release checklist](docs/RELEASE-CHECKLIST.md)

## Contact

Questions, feedback or responsible security disclosure: **[jesma@itm8.com](mailto:jesma@itm8.com)**. Please do not email customer reports, secrets or raw logs without an agreed secure channel. The contact address is not a statement of company sponsorship.

> Source code is public, but the project currently has **no approved open-source license** (`LICENSE.proposed` is not a license). Confirm ownership and choose a license before promoting reuse or redistribution.
