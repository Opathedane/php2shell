# PHP2Shell 2.4.0

Consultant-oriented release: every scan writes a matching **HTML + CSV** pair, and fleet CSV reports can be consolidated offline for a single customer.

Does **not** overwrite `v2.3.0` or `v2.3.1` release assets. Publish only as tag `v2.4.0`.

## Downloads

Standalone binaries (no Python, PHP, or Go required on the target host):

- `php2shell-windows-amd64.zip`
- `php2shell-linux-amd64.tar.gz`
- `php2shell-linux-arm64.tar.gz`
- `php2shell-darwin-amd64.tar.gz` / `php2shell-darwin-arm64.tar.gz` (developer convenience builds)

Verify checksums in `SHA256SUMS`. Release binaries are **not code-signed**. Confirm `php2shell version` prints `2.4.0`.

## What is new in 2.4.0

### Automatic HTML + CSV pair

Each `scan` writes:

- `php2shell-<hostname>-<timestamp>.html` — executive summary, grouped installations, next steps, expandable evidence
- `php2shell-<hostname>-<timestamp>.csv` — fleet schema `php2shell-fleet-csv/v1` (one row per installation)

Both files are generated from the same assessment. `--output-dir`, `--out`, `--quiet`, UNC paths, and no-overwrite behaviour are preserved. If `--out report.html` is set, the CSV is `report.csv`. A failed CSV write removes a just-written HTML file so operators are not left with a half pair.

### Offline CSV rollup

```bash
php2shell rollup --input-dir ./server-reports --out ./customer-summary.csv
```

Merges v2.4.0 fleet CSV files without Go/Python/cloud services. Conflicting non-empty `--customer` labels are rejected. Legacy JSON rollup remains as `rollup --format json`.

### Preserved from 2.3.1

Windows AppData / PATH discovery, PE `.rsrc` reads, confidence-aware path inference, corroborated `current` aliases, and the TestVM PHP 8.4.24 regression remain in force. Binaries are never executed.

### IIS non-standard locations

- Inventories IIS site, nested application, and virtualDirectory `physicalPath` values from `applicationHost.config` (including `E:\websites\...`)
- Follows PHP FastCGI/handler executables on non-system drives when referenced by trusted IIS configuration; `scriptProcessor` arguments are redacted in reports
- Reads accessible per-mapping `web.config` PHP handlers (bounded; no drive-wide or deep tree recursion)
- Correlates site/handler rows to versioned PHP installs and patch assessment when the handler executable is readable
- Reports **INCOMPLETE** IIS coverage when a configured handler binary cannot be versioned — not a “safe” verdict
- Does **not** scan whole drives; `.php` filename inventory still requires `--webroot`
- Does **not** fully simulate IIS handler inheritance (`lockItem` / clear / remove); see [ADVANCED-USAGE.md](ADVANCED-USAGE.md)

### Apache HTTP Server (bounded)

- Passive inventory of well-known Apache config roots on Linux and Windows: VirtualHost `DocumentRoot`/`ServerName`, mod_php `LoadModule`, `SetHandler`/`AddHandler`/`Action`/`ProxyPassMatch`, local handler binaries, and remote FPM backends  
- Distinguishes host installs vs configured handlers vs (never inferred) active serving runtime  
- Remote `fcgi://` backends and inaccessible handler binaries mark Apache coverage **INCOMPLETE**  
- **Tomcat is out of scope** and is never treated as PHP evidence  
- Full Apache merge / `.htaccess` / nginx / LiteSpeed effective-SAPI attestation remains a follow-up; see [ADVANCED-USAGE.md](ADVANCED-USAGE.md)

## Important limitations (unchanged)

- Does **not** attest which PHP runtime is actively serving HTTP (IIS/Apache configuration is not serving proof).
- IIS/Apache discovery may be **INCOMPLETE** when handler binaries are inaccessible or PHP backends are remote; that is not a “safe/patched” verdict.
- IIS handler inheritance and Apache merge/`.htaccess` are **not** fully simulated.
- Does **not** verify distribution/vendor security backports.
- Does **not** prove absence of compromise when no indicators match.
- Does **not** upload customer data or apply remediation.
- Does **not** execute discovered PHP binaries.
- `customer_label` is not authenticated tenancy.

## Quick start

```powershell
.\php2shell-windows-amd64.exe scan --quiet --output-dir C:\ProgramData\PHP2Shell\Reports
php2shell rollup --input-dir C:\ProgramData\PHP2Shell\Reports --out C:\ProgramData\PHP2Shell\customer-summary.csv
```

```bash
./php2shell-linux-amd64 scan --quiet --output-dir "$HOME/.php2shell/reports"
php2shell rollup --input-dir "$HOME/.php2shell/reports" --out ./customer-summary.csv
```

See [CSV-SCHEMA.md](CSV-SCHEMA.md), [INSTALL-FOR-CONSULTANTS.md](INSTALL-FOR-CONSULTANTS.md), and [ADVANCED-USAGE.md](ADVANCED-USAGE.md).

## Supported platforms (CI)

- Linux (`ubuntu-24.04`), Windows (`windows-latest`), macOS Intel (`macos-15-intel`)
