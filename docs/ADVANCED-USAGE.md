> [Back to the quick start](../README.md)

# Advanced usage — PHP2Shell Assessment

Latest public release: **v2.8.0** (bounded nginx/PHP-FPM configuration discovery). Confirm `php2shell version`.

PHP2Shell does **not** certify that a host is patched or uncompromised. It performs authorized, read-only inventory, evidence-qualified patch review, and offline compromise investigation assist for CVE-2026-109618 / CVE-2026-109619.

## Download

Open [Releases](https://github.com/Opathedane/php2shell/releases), choose **v2.8.0**, and download the archive for the destination OS/CPU (use `php2shell-windows-legacy-amd64` only for Server 2012 R2 testing). Binaries are **not code-signed**. Maintainers publish via `.github/workflows/release.yml` after tagging `vX.Y.Z`. Never overwrite existing tags (`v2.3.0`–`v2.8.0`, …).

## Scan output pair

```bash
./php2shell-linux-amd64 scan
```

```powershell
.\php2shell-windows-amd64.exe scan
```

Writes matching HTML and CSV under the platform default directory with unique `php2shell-<hostname>-<timestamp>` basenames. Use `--output-dir` / `--out` / `--quiet` / `--timeout`. **Always read coverage and limitations.** Process exit `0` is not a security clearance.

If `--out reports/customer-check.html` is supplied, the CSV is `reports/customer-check.csv`.

## Fleet consolidation

```bash
php2shell rollup --input-dir ./server-reports --out ./customer-summary.csv
php2shell rollup --out ./customer-summary.csv ./server-reports/*.csv
```

Analyst selects one customer’s CSV collection. Conflicting non-empty `customer_label` values are rejected. See [CSV-SCHEMA.md](CSV-SCHEMA.md).

Legacy JSON rollup (operator-supplied alpha/JSON exports):

```bash
php2shell rollup --format json --tenant-map /secure/trusted-map.json --out reports/fleet.csv reports/*.json
```

Tenant mapping uses exact SHA-256 of report bytes; labels are never trusted for tenancy.

## Evidence options

```bash
./php2shell-linux-amd64 scan --webroot /var/www --access-log /var/log/nginx/access.log --repo /srv/source --out reports/customer-check.html
```

```powershell
.\php2shell-windows-amd64.exe scan --quiet --output-dir \\fileserver\php2shell$\fleet --timeout 30m
```

### IIS sites outside `C:\inetpub` / PHP outside default folders

From `applicationHost.config` the scanner records site, nested application, and virtualDirectory `physicalPath` values (any drive letter), PHP FastCGI/handler `scriptProcessor` executables (arguments redacted), and accessible per-mapping `web.config` PHP handlers. When a handler binary is readable, version evidence and patch assessment are correlated to that install and, where a site name is present on the handler, to matching site/app/vdir rows. It does **not** recursively scan entire volumes, execute PHP binaries, or emit `web.config` secrets from handler arguments.

To inventory `.php` filenames under a specific site (for example `E:\websites\prod\somewebsite`), pass that path as `--webroot`. Without `--webroot`, site path evidence alone means “IIS is configured to use this directory,” not “PHP files were enumerated” and not “the active runtime is verified.”

```powershell
.\php2shell-windows-amd64.exe scan --webroot 'E:\websites\prod\somewebsite' --quiet --output-dir C:\ProgramData\PHP2Shell\Reports
```

### Apache HTTP Server (bounded, passive)

On Linux and Windows, when a well-known Apache config root is accessible (`/etc/apache2`, `/etc/httpd`, `/usr/local/apache2/conf`, common Windows `Apache24\conf` paths), the scanner reads a **bounded** set of config files and records:

1. **VirtualHost `DocumentRoot` / `ServerName`** (any drive or directory spelling in config) — configured site path only  
2. **PHP-related handlers** — `SetHandler`, `AddHandler`, `Action`, `ProxyPassMatch` / `ProxyPass` to `fcgi` / `unix:`, `FcgidWrapper`, `PHPIniDir`  
3. **mod_php** — `LoadModule php*_module` / `libphp*`  
4. **Local handler binaries** referenced by Action/FcgidWrapper when the path is readable (version inspection only; never executed)  
5. **Remote PHP-FPM/proxy backends** (non-loopback `fcgi://host:port`) — recorded as **not** local installs; coverage marked **INCOMPLETE** for those backends  

**Evidence ladder (do not collapse these):**

| Layer | Meaning in reports |
| --- | --- |
| Host PHP install | Packages/binaries/`LoadModule`/handler exe version evidence |
| Configured for an app | `apache_vhost_config` / `apache_php_handler_config` / remote backend rows |
| Actively serving HTTP | **Never** inferred from Apache config alone |

#### Apache coverage limits (v2.4.0)

- Does **not** fully simulate Apache merge order, `IfModule`/`IfDefine`, `<Directory>` precedence, or `.htaccess`  
- `Include` / `IncludeOptional` followed at most **one** level deep and only under the same allowlisted config root (no `..`, no off-root traversal)  
- Does **not** inventory nginx, LiteSpeed, or **Apache Tomcat** / Catalina (Tomcat is a Java Servlet container and is **not** PHP evidence)  
- Does **not** open remote FPM ports or follow DocumentRoot trees for `.php` files (use `--webroot`)  
- Comprehensive multi-SAPI architecture (full effective-vhost resolution, pool↔socket binding attestation) is a **follow-up release** candidate — see release notes  

#### IIS coverage limits (v2.4.0)

- **Inheritance is not fully simulated.** Handlers under `<location>` sections are recorded with their `location` path when present, and site `web.config` handlers are read separately. The scanner does **not** apply IIS `lockItem` / `<clear/>` / `<remove/>` merge rules or compute the effective handler for every URL. Overrides may therefore appear as multiple configured handlers rather than a single resolved mapping.
- **Nested apps and vdirs** are inventoried from `applicationHost.config` physical paths. Only the top-level `web.config` in each distinct physical path is examined (bounded; no recursive tree walk). Child folders’ `web.config` files are not followed unless that folder is itself a mapped physical path.
- **Inaccessible handler binaries** (missing path, wrong host, permission denied) produce `windows_iis_configuration` **INCOMPLETE** coverage and version-unknown evidence. That must not be read as “the site is patched/safe.”
- **Active HTTP serving runtime** remains unverified even when site, handler, and binary version evidence align.

## Compromise investigation (v2.7.0+)

Offline review of consultant-supplied **access logs**, **error logs**, **process/EDR exports**, optional **`--waf-log`** (Cloudflare `firewall_events`), and authorized **`--webroot` filesystem metadata**. Full detail: [COMPROMISE-INVESTIGATION.md](COMPROMISE-INVESTIGATION.md). Exit codes / PSADT: [EXIT-CODES-AND-DEPLOYMENT.md](EXIT-CODES-AND-DEPLOYMENT.md). Field checklist: [FIELD-VALIDATION-2.7.0.md](FIELD-VALIDATION-2.7.0.md).

```bash
./php2shell-linux-amd64 scan \
  --webroot /var/www/html \
  --access-log /var/log/nginx/access.log \
  --error-log /var/log/php-fpm/error.log \
  --process-telemetry ./exports/DeviceProcessEvents.csv \
  --process-telemetry ./exports/auditd-execve.log \
  --investigate-from 2026-10-17 \
  --quiet --output-dir "$HOME/.php2shell/reports"
```

Supported offline process formats: MDE DeviceProcessEvents CSV, Sysmon Event ID 1 CSV, Linux auditd EXECVE text, Elastic ECS process JSONL. No live EDR APIs. Command lines are redacted; entity/report IDs remain for analyst trace-back.

`--webroot` investigation is metadata-only (upload-path PHP-like files, unusual extensions, birth/mtime notes). **mtime ≠ creation or execution.** Path location context is distinct from timestamp evidence; historical CMS files (timestamps outside the window) are not treated as recent compromise. In-window birth is still reported when mtime is old. All webroot leads are weak/`unconfirmed` (weaker than EDR). Temporal correlation requires birth timestamps — mtime±15m alone never elevates confidence. File contents are never read; this is not a webshell/`eval` scanner. Signed SHA-256 IOC hashing is unchanged.

Independent statuses: vulnerability exposure, exploitation attempts, possible compromise, investigation coverage. No inputs ⇒ `NOT_ASSESSED` (not a negative finding). Possible compromise is assessed when usable `--process-telemetry` and/or `--webroot` investigation inputs exist; leads yield `POSSIBLE_COMPROMISE_REVIEW` (webroot-only = low-confidence investigative lead), never automatic confirmed compromise. First/last timestamps do not prove continuous coverage. The ≥2048 heuristic measures **access-log request-target (URI) length only**, not request-body size.

## Signed indicators

Same Ed25519 trust/update workflow as prior releases. Empty template only in-repo. See [rules/README.md](../rules/README.md).

## PHP configuration (`php.ini`) inventory

On Windows and Linux, `scan` performs bounded discovery of `php.ini` and related fragments:

- Well-known install trees, directories next to discovered PHP binaries, `PHPRC` / `PHP_INI_SCAN_DIR` (process environment only)
- Paths referenced by Apache `PHPIniDir` or IIS FastCGI `-c` (path only; handler arguments remain redacted)
- Sample/template names (`php.ini-development`, `php.ini-production`, …) labelled separately from primary candidates
- Optional nearby PHP executable probe in the same directory / parent `bin`/`sbin` when a `php.ini` is found (still not runtime attestation)
- PATH directories (and `%LOCALAPPDATA%\Programs\PHP` trees) may resolve a **bounded** directory junction/symlink chain (e.g. `current` → versioned dir; max 4 hops, cycle detection). File symlinks are never followed. Binaries are never executed.
- Unreadable, oversized, or symlink *file* candidates emit `php_ini_skip` (path + reason only; no secrets)

**Operator-authorized custom locations** (no drive-wide walk):

```bash
php2shell scan --php-ini 'D:\Apps\CustomPHP\php.ini'
php2shell scan --config-root /opt/app/php/etc
php2shell scan --php-ini /etc/custom/php.ini --config-root C:\tools\php
```

`--php-ini` inspects an explicit file (repeatable, max 32). `--config-root` authorizes a **shallow** bounded walk for PHP binaries under that directory (same depth/reparse caps as Programs\\PHP) plus `php.ini` / sample names and one `conf.d/*.ini` layer (repeatable, max 8) — it does **not** recurse into nested trees. Multiple independent installs from PATH, well-known roots, IIS/Apache handlers, and custom roots are retained as separate records (aliases such as `current` merge only when content-corroborated). Configuration-only findings appear in HTML/CSV without claiming installation, version, or active HTTP runtime. Discovery is never complete host coverage.

Whitelisted settings (for example `memory_limit`, `session.upload_progress.enabled`) appear as `configuration_observation` with interpretation **OBSERVED_NOT_EFFECTIVE_SETTING_NOT_VERIFIED_MITIGATION**. A `php.ini` file never supplies the authoritative PHP version and never attests the active HTTP runtime. Secrets and full file dumps are not reported. Fleet CSV `limitations_summary` notes when config candidates or skips were observed.

## Optional Deep Discovery (`--deep-root`)

Use **default scan** (and `--php-ini` / `--config-root` when you already know shallow install roots) first. Add `--deep-root` only when consultants have authorized specific custom trees that may hold PHP installs **not** on PATH (for example `C:\Temp\PHP`, `E:\Applications\PHP`, `/opt/app/php`).

```powershell
php2shell scan --deep-root 'C:\Temp\PHP' --deep-root 'E:\websites'
```

```bash
php2shell scan --deep-root /opt --deep-root /srv/www
```

Behaviour:

- **Off by default**; omit the flag and behaviour matches v2.5.1 standard discovery
- Repeatable (max 8 roots); refuses UNC/network paths and volume roots (`C:\`, `/`)
- Recursive walk: depth ≤ 6, ≤ 25 000 filesystem entries, ≤ 400 PHP-like binaries, ≤ 200 ini candidates, 90s wall-clock budget across deep roots
- Directory junctions/symlinks followed only when the resolved target stays inside the authorized start directory; file symlinks never followed; binaries never executed
- Evidence provenance is weaker than well-known/PATH/IIS/`--config-root` sources
- Truncation, duration, or permission gaps set coverage to **TRUNCATED** / **INCOMPLETE** (process exit **2** when the report pair is written) — empty results are **not** proof PHP is absent outside the authorized roots

Production guidance: keep roots narrow; prefer off-peak windows; do not authorize entire data volumes. Prefer `--config-root` when only a known install directory + `conf.d` is needed.

Further roadmap items (RPM DB, richer runtime correlation): [ROADMAP.md](ROADMAP.md).

## Results vocabulary

Patch and compromise statuses retain prior meanings. Path-inferred versions are labelled in HTML and CSV (`version_evidence=path_inferred`, confidence MEDIUM). Active HTTP runtime remains unverified unless independently established.

## Building and tests

```bash
go test ./...
go vet ./...
go build -trimpath -o php2shell ./cmd/php2shell
```

Synthetic demos: `testdata/demos/` (regenerate with `PHP2SHELL_WRITE_DEMOS=1 go test ./internal/audit -run TestGenerateDemoFleetArtifacts`).

## Licensing

Apache License 2.0 — see [LICENSE](../LICENSE) and [LICENSING.md](LICENSING.md).
