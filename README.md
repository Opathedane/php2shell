# PHP2Shell Security Assessment

Standalone Windows and Linux scanner for **PHP discovery, upstream patch review, and limited compromise-indicator triage**.

PHP2Shell writes a matching **HTML + CSV** report pair from one read-only scan. It does **not** prove that a host is fully patched or uncompromised.

**Version in this tree:** 2.5.1 (unreleased bugfix). Latest public release: [v2.5.0](https://github.com/Opathedane/php2shell/releases/tag/v2.5.0). Prior: [v2.4.0](https://github.com/Opathedane/php2shell/releases/tag/v2.4.0).

## 1. What PHP2Shell does

- Discovers PHP packages, binaries, processes, and configuration on **authorized** hosts
- Compares observed versions to official upstream fix thresholds (21 Oct 2026 advisories)
- Labels verified binary metadata vs path-inferred versions with explicit confidence
- Optional Ed25519-signed indicator packs for limited IOC triage (not bundled by default)
- Never executes discovered PHP binaries, never uploads customer data, never opens a browser

## 2. Download the latest release

[**GitHub Releases**](https://github.com/Opathedane/php2shell/releases/latest)

Choose `php2shell-windows-amd64.zip`, `php2shell-linux-amd64.tar.gz`, or `php2shell-linux-arm64.tar.gz`. Verify `SHA256SUMS`. Builds are **not code-signed**.

## 3. Quick start

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

Exit codes: `0` report pair written, `1` fatal error, `2` pair written but incomplete. Exit `0` is not a security clearance.

## 4. What each scan produces (HTML + CSV)

Every scan writes two files with the same basename:

| File | Purpose |
| --- | --- |
| `php2shell-<host>-<UTC>.html` | Offline executive summary, grouped installs, next steps, expandable evidence |
| `php2shell-<host>-<UTC>.csv` | Fleet schema for Excel / Power BI / scripts ([CSV-SCHEMA.md](docs/CSV-SCHEMA.md)) |

Defaults: `C:\ProgramData\PHP2Shell\Reports` (Windows), `$HOME/.php2shell/reports` (Unix). Use `--output-dir` or `--out path.html` (CSV becomes `path.csv`). Existing files are never overwritten; a failed CSV write does not leave a lone HTML file.

## 5. How to combine customer CSV reports

Scan many servers into one folder (or copy CSVs together), then:

```powershell
php2shell rollup --input-dir C:\ProgramData\PHP2Shell\Reports --out C:\ProgramData\PHP2Shell\customer-summary.csv
```

```bash
php2shell rollup --input-dir ./server-reports --out ./customer-summary.csv
```

Works offline in the same standalone binary. Select **one customer’s** files explicitly. Conflicting non-empty `--customer` labels are rejected. Hostname / customer labels are **not** proof of tenant ownership.

HTML remains the human-readable single-server report; the consolidated CSV is the customer-wide overview.

## 6. Supported platforms

| Platform | Artifact | Notes |
| --- | --- | --- |
| Windows x64 | `php2shell-windows-amd64.zip` | CI + field-tested (incl. AppData PHP layouts) |
| Linux x86-64 / ARM64 | `.tar.gz` | CI on ubuntu-24.04; ARM64 cross-built |
| macOS | darwin amd64/arm64 | Convenience / CI Intel |

## 7. Detection and assessment capabilities

- Windows: well-known paths, `%LOCALAPPDATA%\Programs\PHP`, PATH, PE resources, path inference, `current` alias corroboration
- Windows/IIS: site/app/vdir paths from `applicationHost.config` (any drive), global + per-mapping `web.config` PHP handlers, FastCGI binaries on non-`C:` drives when configured, incomplete coverage when handler binaries are inaccessible — **no volume-wide scan**; inheritance merge not fully simulated; `.php` filenames need `--webroot`
- Apache HTTP Server (Linux/Windows): bounded passive config inventory (VirtualHosts, mod_php, FPM/CGI/FastCGI handler directives, remote backends marked incomplete) — not full merge simulation; **Tomcat is not PHP evidence**
- PHP configuration: bounded `php.ini` / conf.d discovery on Windows and Linux (sidecars, well-known roots, `PHPRC` / `PHP_INI_SCAN_DIR`, web-server `-c` / `PHPIniDir` references) — settings are **observed only**, never attested as effective; ini files are not version authority
- Linux: common package/binary paths, partial process/config inventory (dpkg/apk; RPM DB not yet inventoried)
- Patch comparison to upstream 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35
- Operator-reported runtime flags (never silently attested)

## 8. Known limitations

- No attestation of the live HTTP-serving SAPI (Apache/IIS static config ≠ proof of the active runtime)
- IIS inventory does not fully simulate handler inheritance (`lockItem` / clear / remove); inaccessible handler binaries mark coverage **INCOMPLETE**, not “safe”
- Apache inventory is bounded (no full merge/`.htaccess`; remote FPM backends and inaccessible binaries mark coverage **INCOMPLETE**; nginx/LiteSpeed/Tomcat are not PHP scanners)
- No automatic vendor-backport verification
- No compromise clearance from empty IOC results
- Unsigned binaries (SmartScreen / application control may apply)
- Reports contain hostnames and paths — treat as confidential engagement data

## 9. Security, privacy and licensing

- Authorization required before scanning production systems
- Do not attach customer reports, credentials, or raw logs to public issues ([SECURITY.md](SECURITY.md))
- **No approved open-source license yet** (`LICENSE.proposed` / [docs/LICENSING.md](docs/LICENSING.md)). Apache-2.0 is proposed pending owner approval.

## 10. Contributing and reporting issues

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [Issue templates](https://github.com/Opathedane/php2shell/issues/new/choose)
- Maintainer contact: [jesma@itm8.com](mailto:jesma@itm8.com)

## Documentation

- [Release notes](docs/RELEASE-NOTES.md) · [Changelog](CHANGELOG.md)
- [Consultant quick start](docs/INSTALL-FOR-CONSULTANTS.md) · [Advanced usage](docs/ADVANCED-USAGE.md)
- [CSV schema](docs/CSV-SCHEMA.md) · [GitHub presentation](docs/GITHUB-PRESENTATION.md)
- [Official patch guidance](docs/OFFICIAL-PHP2SHELL-PATCH-GUIDANCE.md) · [Release checklist](docs/RELEASE-CHECKLIST.md)
