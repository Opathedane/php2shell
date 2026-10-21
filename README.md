# PHP2Shell Assessment – standalone preview

**Status: internal developer preview, NOT a production-approved vulnerability scanner or a compromise detector.**

One self-contained executable (written in Go) for local PHP evidence inventory, repository declarations, bounded HTTP access-log coverage, and analyst-controlled MSSP report rollups. No Python, PHP, Docker, Node, administrative web page or outbound internet connection is required by default. No PHP code is executed and no exploit requests are sent. Requires normal OS rights to read the artifacts inspected; missing rights mean missing coverage.

**CVE-2026-109618 / CVE-2026-109619:** the tool currently reports `NOT_VERIFIED` for vulnerability and `NOT_ASSESSED` for compromise. This is intentional: passive metadata, HTTP headers and general-purpose web logs cannot establish whether either vulnerability is exploitable, fixed or exploited. Official CVE-specific vendor rules, deployed SAPI attestation, backport verification, and validated incident indicators have not been added. Do not distribute this preview as an accurate PHP2Shell detection product.

## Installation: none

Choose the correct [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository) asset (once approved and published): `php2shell-linux-amd64`, `php2shell-linux-arm64`, `php2shell-windows-amd64.exe`, `php2shell-darwin-arm64`, or `php2shell-darwin-amd64`. Verify the SHA-256 checksum from an independently trusted release page; project binaries are not yet signed or notarized. **Mac/Linux:** `chmod +x php2shell-<platform>` then run `./php2shell-<platform> ...`. **Windows:** use PowerShell `./php2shell-windows-amd64.exe ...`.

No need to install a compiler or Go on the customer's server. Go is required **only** if building or modifying source code.

## Customer – basic scan

**Linux (x86-64):**

```bash
chmod +x php2shell-linux-amd64
./php2shell-linux-amd64 doctor
./php2shell-linux-amd64 scan --out reports/my-server
```

**Windows (x86-64), PowerShell:**

```powershell
.\php2shell-windows-amd64.exe doctor
.\php2shell-windows-amd64.exe scan --out reports\my-server
```

The simplest command is just `./php2shell-linux-amd64 scan` (or `php2shell-windows-amd64.exe scan` on Windows): a fresh time-stamped output prefix is generated automatically. With an explicit `--out`, it creates exactly three **local** files: `reports/my-server.json`, `.csv`, `.html`. Existing files are never overwritten. Open `.html` locally in a browser. Reports may contain private hostnames, package information and filesystem paths; keep them out of public repositories. The `reports/` directory is excluded in `.gitignore`.

## Consultant – additional authorized evidence

```bash
./php2shell-linux-amd64 scan --webroot /var/www --repo /srv/application \
  --access-log /var/log/nginx/access.log --out reports/customer-20261021
```

* `--webroot`: searches filenames only, capped at 25,000 entries. Does not run PHP or read PHP application source code.
* `--repo`: scans static Docker PHP image references, Composer constraints, CI versions and `.php-version` (repeat as needed). Repository declarations are not deployed PHP versions.
* `--access-log`: **statistics and timestamp coverage only** for an explicitly provided regular Apache/nginx-style access log, max 32 MiB per file (repeat). No raw IPs, URLs, query parameters, or requests are saved. **No attack-pattern detection** is implemented. Rotated `.gz` logs are not supported. Large/unavailable logs are reported as incomplete/unavailable.
* `--docker`: optional **local Unix Docker socket** read-only API metadata (`GET /containers/json?all=0`); Docker socket may grant root-equivalent access. No `docker exec`. Does not verify image contents or PHP runtimes.
* `--customer`: optional untrusted descriptive label, **not** a customer identifier for SOC ingestion.

There is no network/remote HTTP scan, no VirusTotal API connection, no vulnerability exploitation, no auto-update, and no telemetry. Never grant extra privileges or open firewalls solely for the scanner. Preserve incident evidence before investigating.

## MSSP – offline rollup

```bash
./php2shell-linux-amd64 rollup --tenant-map /secure/trusted-map.json \
  --out reports/fleet-rollup.csv reports/my-server.json reports/customer-20261021.json
```

A mapping is a JSON object whose keys are SHA-256 hashes of **exact report files** and values are analyst-controlled tenant labels, e.g. `{"<64-char-sha256>":"customer-123"}`. Unmapped reports stay `UNMAPPED`, and the scanner refuses to substitute the `customer_label` supplied in input data. File hashing is **not** proof of report authenticity; maintain an approved transfer and chain-of-custody process. Rollup is for a trusted, analyst-controlled offline workspace, **not** a SOC ingestion service or a verified multi-tenant platform.

## What VirusTotal's exposure analysis changes

[**VirusTotal, 21 October 2026: Sizing the PHP exposure window**](https://blog.virustotal.com/2026/10/sizing-php-exposure-window-for-cve-2026.html) notes that a large majority of identified PHP hosts do not advertise a version banner. Therefore, `X-Powered-By` is not a reliable basis for a 'not affected' verdict. Reports must distinguish inventoried installed components, package provenance, active HTTP-serving PHP SAPI, internet exposure and evidence from historical logs. This preview records only some of these categories; missing categories are explicitly flagged.

Prioritise identifying external PHP origins exposed outside a WAF, unsupported/EOL PHP branches, internet-facing applications and outdated deployed runtimes. PHP configuration such as `session.upload_progress.enabled=Off` or `expose_php=Off` is not verified patching. WAF rules and app-level changes are not evidence that PHP itself is fixed. Differentiate risk reduction from remediation. **Re-run after patching**, but do not interpret a changed inventory as proof of remediation without confirming the actual serving runtime and vendor advisory.

A VirusTotal Internet Scanning integration could later be made a separately enabled MSSP enrichment step with tenant authorization, rate controls and data minimization; it is **not** needed for or included in this on-host binary. Do not send server contents or customer logs to third parties.

## Platform coverage, known limitations

| Check | Linux | Windows | macOS |
|---|---|---|---|
| Common PHP binary paths (presence only) | Partial | Partial | Partial |
| Native installed package metadata | dpkg/apk partial only | Not implemented | Not implemented |
| Live PHP process names | `/proc` partial only | Not implemented | Not implemented |
| Static PHP ini/pool observations | Common paths only | Not implemented | Common paths only |
| Local repository audit | Yes | Yes | Yes |
| Local Apache/nginx access log summary | Yes | Yes | Yes |
| Docker metadata | Optional local Unix socket | Not supported | Optional Unix socket |
| Verify actual serving SAPI, vendor backports, PHP2Shell fixed state | **No** | **No** | **No** |
| Verified PHP2Shell exploit indicators, successful compromise, negative compromise conclusions | **No** | **No** | **No** |

The scanner never returns `SAFE`, `NOT_VULNERABLE`, `PATCHED` or `CLEAN` based on its current evidence. Missing or inaccessible data do not count as absence of vulnerability. Time boundaries in access-log reports depend on timestamps present in the original logs, whose authenticity the program does not verify.

## Build from source (maintainers)

```bash
go test ./...
go vet ./...
go build -trimpath -o php2shell ./cmd/php2shell
```

The release workflow should be reviewed, tested and approved by maintainers. Run integration tests on actual IIS, Apache/mod_php, nginx/PHP-FPM, LiteSpeed, containers, unsupported/managed PHP and locked-down production-like hosts **before** customer distribution. Also see [Security policy](SECURITY.md), [Release checklist](docs/RELEASE-CHECKLIST.md), and [Threat intelligence policy](docs/THREAT-INTELLIGENCE.md).

## License / branding

No public OSS license has been authorized yet. `LICENSE.proposed` is a draft placeholder; review ownership, branding and third-party rights before making the repository public. This project currently contains **original Go code**, not source copied from the referenced GitHub repo or an unverified exploit PoC. Proposed GitHub organization paths in build metadata are not claims of official affiliation or release approval.
