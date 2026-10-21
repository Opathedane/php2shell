> [Back to the quick start](../README.md)

# Advanced usage — PHP2Shell Assessment (v2.3.0)

PHP2Shell does **not** certify that a host is patched or uncompromised. It performs authorized, read-only inventory and evidence-qualified patch review for CVE-2026-109618 / CVE-2026-109619.

One standalone executable for Windows and Linux: no Python, Go compiler or PHP installed on the customer server. It does **not** execute discovered PHP programs, launch shell commands, use PoCs or send exploit requests. Default scanning is local-only, with no network connectivity or telemetry. Optional GitHub indicator updates are **Ed25519-signed** and opt-in.

## Download compiled builds from GitHub Releases

Open [Releases](https://github.com/Opathedane/php2shell/releases), choose the latest **official release**, and download the archive for the destination OS and CPU. See [consultant quick start](INSTALL-FOR-CONSULTANTS.md). Binaries are **not code-signed**; comply with organizational approval. Maintainers publish via **GitHub Actions → Publish standalone release** (`.github/workflows/release.yml`) after tagging `vX.Y.Z`. Historical alpha tags remain available via `release-alpha.yml`.

## Customer: two commands

Linux:

```bash
chmod +x php2shell-linux-amd64
./php2shell-linux-amd64 scan
```

Windows Server (PowerShell):

```powershell
.\php2shell-windows-amd64.exe scan
```

Writes a single HTML report under the platform default directory (`C:\ProgramData\PHP2Shell\Reports` or `$HOME/.php2shell/reports`) with a unique `php2shell-<hostname>-<timestamp>.html` name. Existing reports are not overwritten. Use `--output-dir` / `--out` / `--quiet` / `--timeout` for automation. **Always read the coverage table**. No PHP installation found is not a clean bill of health. Process exit `0` is not a security clearance.

## Consultant: examine the authorized evidence

```bash
./php2shell-linux-amd64 scan --webroot /var/www --access-log /var/log/nginx/access.log --repo /srv/source --out reports/customer-check.html
```

```powershell
.\php2shell-windows-amd64.exe scan --webroot C:\inetpub\wwwroot --access-log C:\inetpub\logs\LogFiles\W3SVC1\u_ex261021.log --output-dir C:\ProgramData\PHP2Shell\Reports
```

Enterprise / scheduled example (no console progress; HTML only):

```powershell
.\php2shell-windows-amd64.exe scan --quiet --output-dir \\fileserver\php2shell$\fleet --timeout 30m
```

UNC writes use the process identity (user or `DOMAIN\MACHINE$` under SYSTEM). Configure share ACLs explicitly; the scanner does not transfer reports by itself.

IIS uses static `applicationHost.config` PHP FastCGI/handler references and a limited live Windows process list. Linux has partial dpkg/apk, PHP binary/config paths and /proc data. Neither platform establishes the actual HTTP-serving PHP SAPI or validates vendor security backports. Windows W3C and Apache/nginx combined logs can be summarized and checked against signed indicators. No logs are read unless explicitly requested.

## Live indicators from your approved GitHub repository

**Step 1: trust the signing public key from an independently authenticated maintainer** (ONCE):

```bash
php2shell rules trust --key ./rule-signing-public.hex
```

**Step 2: download an approved signed bundle** (operator opt-in):

```bash
php2shell rules update --url https://raw.githubusercontent.com/Opathedane/php2shell/main/rules/signed.json
```

**Step 3: run with cached verified indicators**:

```bash
php2shell scan --webroot /var/www --access-log /var/log/nginx/access.log
```

You can combine update+scan using `scan --update-rules --rules-url HTTPS_URL ...`, or use a previously downloaded signed envelope via `scan --rules ./signed.json ...`. Internet access is not needed after updating. Rule bundles are data only: no scripts, regex execution, arbitrary programs, or PHP execution. A failed signature or expired rule pack is **not accepted**. A repo owner cannot silently change the trust key; explicit key setup is required. Use `php2shell rules status` for version/expiry. The repository currently contains only an empty **unsigned** template: there are no official PHP2Shell IOCs bundled yet.

For maintainer key generation and signing, see [rules/README.md](../rules/README.md). **Never upload private signing keys.** This design does not automatically trust the GitHub domain or a key fetched from the same unverified location.

## Results explained

- `Vulnerability` now reports an **evidence-qualified upstream patch comparison**. `BELOW_UPSTREAM_FIX_OBSERVED_PATCH_REVIEW_REQUIRED` does not override a verified vendor backport. `UPSTREAM_FIX_LEVEL_OBSERVED_ACTIVE_RUNTIME_UNVERIFIED` does not certify the web server as patched. See [official patch guidance](OFFICIAL-PHP2SHELL-PATCH-GUIDANCE.md).
- `Compromise: NOT_ASSESSED`: no usable IOC analysis was possible. `INDICATORS_MATCHED_REVIEW_REQUIRED`: one or more signed rule matches need investigation. `NO_MATCHES_SCOPE_LIMITED`: only a limited scan was conducted; **not a clean verdict**.
- `Signed rules: VERIFIED`: integrity and publisher-key authentication of the downloaded data passed, **not** proof each detector is accurate or specific to PHP2Shell.
- Reports preserve file names and server metadata and require confidential handling. Raw HTTP request target and client IP are not written to reports.

## MSSP report aggregation

`php2shell scan` writes HTML only. The legacy `rollup` command still expects operator-supplied JSON report files (for example from an older scan or an external export):

```bash
php2shell rollup --tenant-map /secure/trusted-map.json --out reports/fleet.csv reports/*.json
```

Tenant identities require an analyst-maintained exact SHA-256 report hash mapping. Input customer labels are never trusted for tenancy. An unsigned report can be forged and is not an attested chain of custody. Prefer collecting HTML reports via a pre-configured `--output-dir` (local or UNC) rather than automatic upload.

## What is not finished

- Official minimum patch levels from the PHP **21 October 2026** release are integrated into the scanner. Unverified PoCs and guessed IOC signatures are deliberately **not** imported. Compare `Patch assessments` and `Recommended follow-up` in the HTML report with the official advisories. Static observations still cannot certify the live web handler or vendor security backports.
- Windows Server/IIS real-world validation, PHP-FPM/Apache/LSAPI integration, RPM/Windows package inventory, code signing, validated incident indicators, and active-runtime/vendor-backport verification are release gates, not completed capabilities.
- Windows/IIS static parsing and W3C log fixtures, signature and rollback checks have unit tests. Cross-compilation is not a substitute for Windows Server or enterprise production validation.
- Filesystem reads may have TOCTOU race limits. Very large or rotated logs, nested symlinks and cloud hosting are not comprehensively checked.

Read [security policy](../SECURITY.md), [review](SECURITY-REVIEW-2026-10-21.md), [release checklist](RELEASE-CHECKLIST.md), and [IOC limitations](IOC-RULE-LIMITATIONS.md). **Do not use PHP2Shell alone to certify systems as patched or uncompromised.**

No outbound customer data transfer is implemented. `--docker` accesses a privileged local Docker socket when requested; never grant Docker daemon permissions just for scanning.

## Building and running tests

```bash
go test ./...
go vet ./...
go build -trimpath -o php2shell ./cmd/php2shell
```

CI runs on GitHub-hosted Linux, Windows and macOS Intel runners for pull requests and pushes to `main`. Release artifacts are unsigned.

## Ownership and licensing

`LICENSE.proposed` is a draft only. Open-source licensing and third-party branding must be authorized before making the repo public. Go module: `github.com/Opathedane/php2shell`.

## Additional official-patch assessment option (operator-reported runtime)

```bash
php2shell scan --runtime-version 8.4.26 --runtime-sapi fpm --runtime-source "approved production FPM evidence"
```

The three runtime options are all required together. They add a separately observed version to the report; the scanner labels it as **OPERATOR_REPORTED_NOT_ATTESTED**, never silently attests a serving PHP version. The report provides per-component patch instructions.
