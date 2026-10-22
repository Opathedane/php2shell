# PHP2Shell – consultant quick start

**This tool does not certify a server as patched or uncompromised.** Use it for authorized inventory, evidence-qualified patch review, and (when using an unreleased 2.7.0 RC binary) offline compromise investigation assist. Latest public release: **v2.6.0**. This documentation tree may include unreleased **2.7.0**. Confirm `php2shell version` on the binary you run.

Download the build matching the destination server from GitHub **Releases**. No Python, Go, PHP, installer, or network access is required for the basic local inventory. The optional IOC update requires an independently authenticated rule signing key and a reviewed signed ruleset; the repository does **not** include a validated PHP2Shell-specific rulepack yet.

**Privacy:** keep HTML/CSV reports inside the engagement boundary. Do not attach customer reports, credentials, or raw logs to public GitHub issues — use the issue templates and redact paths/hostnames.

## Windows Server x64 (PowerShell)

```powershell
.\php2shell-windows-amd64.exe doctor
.\php2shell-windows-amd64.exe scan --quiet --output-dir C:\ProgramData\PHP2Shell\Reports
```

### Windows / IIS — what is automatic vs `--webroot`

**Automatic (when `applicationHost.config` is readable; read-only, bounded):**

- IIS site, nested application, and virtualDirectory `physicalPath` values (any drive, e.g. `E:\websites\prod\somewebsite`)
- Global and `<location>` PHP FastCGI/handler executables (including installs on `D:` / `E:`); `scriptProcessor` arguments are redacted
- Per-mapping `web.config` PHP handlers when that physical path is accessible (top-level file only; no deep tree walk)
- Static version inspection of those handler binaries when readable (never executed)
- Site↔handler↔version↔patch correlation where handler site context and a readable binary allow it

**Not automatic / not claimed:**

- Full IIS inheritance merge (`lockItem` / clear / remove) — see [ADVANCED-USAGE.md](ADVANCED-USAGE.md)
- Recursive `web.config` discovery under site trees beyond mapped physical roots
- Active HTTP-serving PHP runtime attestation
- A “safe/patched” conclusion when a handler is configured but its binary is inaccessible (coverage is **INCOMPLETE**)

### Apache HTTP Server vs Tomcat

**Apache HTTP Server** (when a well-known config directory is readable): VirtualHost document roots, mod_php modules, and PHP handler/proxy directives are inventoried passively. Local handler binaries may receive version inspection. Remote PHP-FPM targets are reported as configured remote backends (not local installs). Active serving runtime is still **not** attested from config.

**Apache Tomcat** is a Java Servlet/JSP container. PHP2Shell does **not** scan Tomcat/Catalina and does **not** treat Tomcat as evidence of PHP. Do not expect Java CVE coverage from this tool.

**Requires explicit `--webroot`:**

- Listing `.php` filenames under a document root (including non-`C:` sites or Apache DocumentRoots)
- Bounded file-hash IOC checks under that root

Example for a site on `E:`:

```powershell
.\php2shell-windows-amd64.exe scan `
  --webroot 'E:\websites\prod\somewebsite' `
  --access-log 'C:\inetpub\logs\LogFiles\W3SVC1\u_ex261021.log' `
  --output-dir C:\ProgramData\PHP2Shell\Reports
```

A configured site path or `.php` files under it is **not** proof of an active patched PHP runtime. Handler config is labelled as configured-only.

Windows executables are **not Authenticode signed** and may generate SmartScreen warnings. Do not bypass endpoint protection. Prefer least privilege.

### When to use Deep Discovery (`--deep-root`)

| Situation | Recommendation |
| --- | --- |
| Standard PATH / Programs\\PHP / IIS / Apache layouts | Default `scan` only |
| Known shallow custom install + `php.ini` / `conf.d` | `--config-root` and/or `--php-ini` |
| Custom trees that may nest multiple PHP versions (e.g. `C:\Temp\PHP`, `E:\Apps\PHP`) | `--deep-root` on those directories only |

```powershell
.\php2shell-windows-amd64.exe scan `
  --deep-root 'C:\Temp\PHP' `
  --deep-root 'E:\websites' `
  --output-dir C:\ProgramData\PHP2Shell\Reports
```

Do **not** pass volume roots or UNC shares. Truncated deep scans exit `2` and must be treated as incomplete.

### Compromise investigation (unreleased 2.7.0 RC)

Requires a binary built from this tree (`php2shell version` → `2.7.0`). Keep raw logs, EDR exports, and HTML/CSV reports inside the engagement boundary.

```powershell
.\php2shell-windows-amd64.exe scan `
  --webroot 'E:\websites\prod\site' `
  --access-log 'C:\inetpub\logs\LogFiles\W3SVC1\u_ex261018.log' `
  --error-log 'C:\PHP\logs\php_errors.log' `
  --process-telemetry 'C:\Engagement\exports\DeviceProcessEvents.csv' `
  --process-telemetry 'C:\Engagement\exports\sysmon-eid1.csv' `
  --investigate-from 2026-10-17 `
  --quiet --output-dir C:\ProgramData\PHP2Shell\Reports
```

See [COMPROMISE-INVESTIGATION.md](COMPROMISE-INVESTIGATION.md) and [FIELD-VALIDATION-2.7.0.md](FIELD-VALIDATION-2.7.0.md).

## Linux x86-64

```bash
tar xzf php2shell-linux-amd64.tar.gz
chmod +x php2shell-linux-amd64
./php2shell-linux-amd64 doctor
./php2shell-linux-amd64 scan --quiet --output-dir "$HOME/.php2shell/reports"
# Optional Deep Discovery:
# ./php2shell-linux-amd64 scan --deep-root /opt --deep-root /usr/local --output-dir "$HOME/.php2shell/reports"
# Optional IR (unreleased 2.7.0 RC binary):
# ./php2shell-linux-amd64 scan \
#   --webroot /var/www/html \
#   --access-log /var/log/nginx/access.log \
#   --error-log /var/log/php8.3-fpm.log \
#   --process-telemetry ./exports/auditd-execve.log \
#   --investigate-from 2026-10-17 \
#   --quiet --output-dir "$HOME/.php2shell/reports"
```

## Reports

Each scan writes **two** files with the same basename:

- HTML — human-readable single-server assessment
- CSV — fleet schema for Excel / Power BI / rollup ([CSV-SCHEMA.md](CSV-SCHEMA.md))

Defaults: `C:\ProgramData\PHP2Shell\Reports` or `$HOME/.php2shell/reports`. Use `--output-dir` or `--out path.html` (CSV → `path.csv`). Never overwrites existing files.

**Customer-wide overview** (one customer’s servers only):

```powershell
php2shell rollup --input-dir C:\ProgramData\PHP2Shell\Reports --out C:\ProgramData\PHP2Shell\customer-summary.csv
```

```bash
php2shell rollup --input-dir ./server-reports --out ./customer-summary.csv
```

Exit codes: `0` pair written, `1` fatal, `2` pair written but incomplete.

Verify downloads with `SHA256SUMS` from a trusted release. Checksums do not replace code signing.

## Official PHP2Shell patch assessment (21 October 2026)

Upstream minima: **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**. Vendor backports need separate verification. Operator-reported runtime flags are available; they are not automatic attestation. See [official patch guidance](OFFICIAL-PHP2SHELL-PATCH-GUIDANCE.md).
