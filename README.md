# PHP2Shell Security Assessment

Standalone Windows and Linux scanner for **PHP discovery, patch review, and limited compromise-indicator triage**.

PHP2Shell writes a single self-contained **HTML** report that answers: was PHP found, which versions were observed, whether an update review is required, whether an active web runtime was verified, and what to do next. It does **not** prove that a host is fully patched or uncompromised.

**Current release (when published):** [v2.3.1](https://github.com/Opathedane/php2shell/releases/tag/v2.3.1) — Windows PHP version-detection fixes on top of the public [v2.3.0](https://github.com/Opathedane/php2shell/releases/tag/v2.3.0) HTML-only scanner. Until the tag exists, use **Releases → latest**. Real-world validation is ongoing; treat findings as evidence-qualified inventory, not certification.

## Getting started

1. Obtain authorization to scan the target host.
2. Download the matching archive from [Releases](https://github.com/Opathedane/php2shell/releases/latest).
3. Verify integrity against `SHA256SUMS` (see [Release verification](#release-verification)).
4. Run `doctor`, then `scan`. Open the generated HTML report locally.

**Windows (PowerShell):**

```powershell
.\php2shell-windows-amd64.exe doctor
.\php2shell-windows-amd64.exe scan
```

**Linux:**

```bash
chmod +x php2shell-linux-amd64
./php2shell-linux-amd64 doctor
./php2shell-linux-amd64 scan
```

Reports are **HTML only**. Defaults: `C:\ProgramData\PHP2Shell\Reports` on Windows, `$HOME/.php2shell/reports` on Unix. Use `--output-dir` or `--out`. The scanner never opens a browser and never uploads data.

Exit codes: `0` report written, `1` fatal error, `2` report written but incomplete. Exit `0` is not a security clearance.

## Supported platforms

| Platform | Artifact | CI / validation notes |
| --- | --- | --- |
| Windows x64 | `php2shell-windows-amd64.zip` | Tested on GitHub `windows-latest`; Windows Server/IIS field validation ongoing |
| Linux x86-64 | `php2shell-linux-amd64.tar.gz` | Tested on `ubuntu-24.04` |
| Linux ARM64 | `php2shell-linux-arm64.tar.gz` | Cross-built; native ARM CI not required for every push |
| macOS Intel | `php2shell-darwin-amd64.tar.gz` | CI on `macos-15-intel` (developer convenience) |
| macOS Apple Silicon | `php2shell-darwin-arm64.tar.gz` | Cross-built convenience binary; not a primary target platform |

No Python, PHP, or Go installation is required on the scanned host. Release builds are **not code-signed**.

## What the report covers

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

## Known limitations

- Does **not** attest which PHP runtime is actively serving HTTP.
- Does **not** verify distribution/vendor security backports by advisory ID.
- Does **not** prove absence of compromise when no indicators match (and no validated PHP2Shell-specific IOC pack is bundled by default).
- Does **not** upload customer data, modify PHP/web server configuration, or apply remediation.
- Does **not** execute discovered PHP binaries or run exploit tests.
- Binaries are unsigned; SmartScreen / application-control policy may block execution until approved.

## Release verification

From a trusted [GitHub release](https://github.com/Opathedane/php2shell/releases/latest), download the platform archive **and** `SHA256SUMS`.

```bash
# Linux / macOS
sha256sum -c SHA256SUMS --ignore-missing
# or: sha256sum php2shell-linux-amd64
```

```powershell
# Windows
Get-FileHash .\php2shell-windows-amd64.exe -Algorithm SHA256
# Compare to the matching line in SHA256SUMS
```

Checksums prove bit-for-bit match with published assets; they do **not** replace Authenticode / notarization. Confirm the release tag and publisher account before use.

## Documentation

- [Release notes (v2.3.1)](docs/RELEASE-NOTES.md)
- [Consultant quick start](docs/INSTALL-FOR-CONSULTANTS.md)
- [Advanced usage and enterprise deployment](docs/ADVANCED-USAGE.md)
- [Official patch guidance](docs/OFFICIAL-PHP2SHELL-PATCH-GUIDANCE.md)
- [Release checklist](docs/RELEASE-CHECKLIST.md)
- [Supply-chain and governance notes](docs/GOVERNANCE.md)
- [IOC rule signing](rules/README.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Feedback

Use [GitHub Issues](https://github.com/Opathedane/php2shell/issues/new/choose) with the appropriate template (bug, PHP not detected, incorrect assessment, or feature request). Do **not** attach customer reports, credentials, or raw logs to public issues.

## Contact

Questions or responsible disclosure: **[jesma@itm8.com](mailto:jesma@itm8.com)**. Do not email customer reports, secrets, or raw logs without an agreed secure channel.

> Source code is public, but the project currently has **no approved open-source license** (`LICENSE.proposed` is not a license). Confirm ownership and choose a license before promoting reuse or redistribution.
