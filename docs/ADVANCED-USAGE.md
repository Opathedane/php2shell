> [Back to the quick start](../README.md)

# Advanced usage — PHP2Shell Assessment (v2.4.0)

PHP2Shell does **not** certify that a host is patched or uncompromised. It performs authorized, read-only inventory and evidence-qualified patch review for CVE-2026-109618 / CVE-2026-109619.

## Download

Open [Releases](https://github.com/Opathedane/php2shell/releases), choose **v2.4.0** (or newer), and download the archive for the destination OS/CPU. Binaries are **not code-signed**. Maintainers publish via `.github/workflows/release.yml` after tagging `vX.Y.Z`. Never overwrite existing tags such as `v2.3.0` / `v2.3.1`.

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

## Signed indicators

Same Ed25519 trust/update workflow as prior releases. Empty template only in-repo. See [rules/README.md](../rules/README.md).

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

`LICENSE.proposed` is not an approved license. See [LICENSING.md](LICENSING.md).
