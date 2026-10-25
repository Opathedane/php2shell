# PHP2Shell – consultant quick start

**This tool does not certify a server as patched or uncompromised.** Use it for authorized inventory, evidence-qualified patch review, and offline compromise investigation assist. Latest public release: **v2.8.1**. Confirm `php2shell version` on the binary you run matches the release you downloaded. Platform matrix and honesty limits: [SUPPORTED-COVERAGE.md](SUPPORTED-COVERAGE.md).

Download the build matching the destination OS/CPU from GitHub **Releases** (Windows, Linux, or macOS darwin archives). No Python, Go, PHP, installer, or network access is required for the basic local inventory. The optional IOC update requires an independently authenticated rule signing key and a reviewed signed ruleset; the repository does **not** include a validated PHP2Shell-specific rulepack yet.

On Linux hosts with well-known nginx/PHP-FPM paths, v2.8.0 may report configuration candidates. That evidence does **not** attest the active HTTP-serving runtime or patch state.

**Privacy:** keep HTML/CSV reports inside the engagement boundary. Do not attach customer reports, credentials, or raw logs to public GitHub issues — use the issue templates and redact paths/hostnames.

## Windows Server x64 (PowerShell)

**Windows 10 / Server 2016+:** use `php2shell-windows-amd64.exe` (standard build).

**Windows Server 2012 R2 x64:** use `php2shell-windows-legacy-amd64.exe` (Go 1.20 legacy build). The standard EXE refuses NT &lt; 10 with an actionable error. See [WINDOWS-LEGACY-2012R2.md](WINDOWS-LEGACY-2012R2.md) for security implications and PSAppDeployToolkit notes.

```powershell
.\php2shell-windows-amd64.exe doctor
.\php2shell-windows-amd64.exe scan --quiet --output-dir C:\ProgramData\PHP2Shell\Reports
```

```powershell
# Server 2012 R2 only
.\php2shell-windows-legacy-amd64.exe doctor
.\php2shell-windows-legacy-amd64.exe scan --quiet --output-dir C:\ProgramData\PHP2Shell\Reports
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

### Compromise investigation (v2.7.0+)

Requires a **v2.7.1** (or later) binary for WAF + status JSON; core IR ships from **v2.7.0**. Keep raw logs, EDR exports, and HTML/CSV/status reports inside the engagement boundary.

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
# Optional IR (v2.7.0+):
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

Defaults: `C:\ProgramData\PHP2Shell\Reports` or `$HOME/.php2shell/reports`. Use `--output-dir` or `--out path.html` (a `.csv` `--out` remaps to `.html`+`.csv`). Also writes `*.status.json`. Never overwrites existing files.

**Exit codes / Intune / PSADT:** `0` = reports written; `2` = reports written but incomplete coverage (still upload); `1` = fatal. See [EXIT-CODES-AND-DEPLOYMENT.md](EXIT-CODES-AND-DEPLOYMENT.md). Optional `--accept-incomplete` maps exit 2→0 when wrappers cannot tolerate non-zero.

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
