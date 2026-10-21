# PHP2Shell Security Assessment

Standalone Windows and Linux scanner for **PHP discovery, patch review, and limited compromise-indicator triage**.

PHP2Shell produces a single self-contained HTML report that answers: was PHP found, which versions were observed, whether an update review is required, whether the active web runtime was verified, and what to do next. It does **not** prove that a host is fully patched or uncompromised.

## Download

[**Latest release**](https://github.com/Opathedane/php2shell/releases/latest)

Choose `php2shell-windows-amd64.zip`, `php2shell-linux-amd64.tar.gz`, or `php2shell-linux-arm64.tar.gz`. No Python, PHP, or Go installation is required. Release builds are **not code-signed**; verify `SHA256SUMS` and obtain authorization before use.

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

Reports are HTML-only. Defaults: `C:\ProgramData\PHP2Shell\Reports` on Windows, `$HOME/.php2shell/reports` on Unix. Use `--output-dir` or `--out`. The scanner never opens a browser and never uploads data.

### What the report covers

| Question | How PHP2Shell answers |
| --- | --- |
| Was PHP detected? | Package, binary, process, and config evidence (coverage may be incomplete) |
| Which versions? | Grouped installation summary with expandable technical detail |
| Updates required? | Comparison to official upstream thresholds; vendor backports need separate verification |
| Active web runtime? | Candidates may be identified; serving HTTP runtime is not attested by default |
| Compromise? | Only when a trusted signed indicator pack is loaded; no match is not a clearance |

### Official minimum fixed versions (21 October 2026)

| PHP branch | First upstream fixed release |
| --- | --- |
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 and older | Upgrade to a supported branch, or verify documented vendor/LTS backport |

See the [official PHP advisory archive](https://www.php.net/archive/2026.php).

## Documentation

- [Release notes](docs/RELEASE-NOTES.md)
- [Consultant quick start](docs/INSTALL-FOR-CONSULTANTS.md)
- [Advanced usage and enterprise deployment](docs/ADVANCED-USAGE.md)
- [Official patch guidance](docs/OFFICIAL-PHP2SHELL-PATCH-GUIDANCE.md)
- [IOC rule signing](rules/README.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Contact

Questions or responsible disclosure: **[jesma@itm8.com](mailto:jesma@itm8.com)**. Do not email customer reports, secrets, or raw logs without an agreed secure channel.

> Source code is public, but the project currently has **no approved open-source license** (`LICENSE.proposed` is not a license). Confirm ownership and choose a license before promoting reuse or redistribution.
