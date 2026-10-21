# PHP2Shell — official patch and remediation guidance

**Source of truth:** PHP security release of **21 October 2026**:

- https://www.php.net/archive/2026.php
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w — CVE-2026-109618, OOM corruption
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp — CVE-2026-109619, stale global state

These advisories address **critical unauthenticated RCE**. Prioritize internet-reachable PHP, especially **Apache mod_php**, but also review **PHP-FPM, PHP-CGI, FrankenPHP and LiteSpeed**. Do not infer safety from absence of a public URL or an `X-Powered-By` header.

## Official upstream patch levels

| Branch | Minimum upstream fixed release | Guidance |
|---|---|---|
| PHP 8.5 | **8.5.12** | Update immediately if lower |
| PHP 8.4 | **8.4.27** | Update immediately if lower |
| PHP 8.3 | **8.3.36** | Update immediately if lower |
| PHP 8.2 | **8.2.35** | Update immediately; plan migration before PHP 8.2 EOL 31 Dec 2026 |
| PHP 8.1 and older | No routine PHP upstream supported release | Move to supported branch or verify an explicit distribution/LTS security backport; PHP published minimal source backports for 7.4/8.0/8.1 |

**Distribution-packaged PHP:** Debian, Ubuntu, Red Hat and commercial vendors may ship a fixed patch under an older-looking upstream version (backported security fix). The version *alone* does not attest vulnerability or patch state. Use vendor advisory, exact installed package build and package provenance. This tool deliberately does not assert that a distro package is unpatched solely because its upstream version is below the table.

**Source builds/containers/Windows:** apply the upstream fixes or rebuild with validated source patches. Verify the running web-handler binary after restart/redeploy. A version in `php -v`, composer.json, Dockerfile, CI, or dpkg/apk is not evidence of the active HTTP-serving binary.

## Required response procedure

1. **Identify actual exposure:** locate the PHP handler serving the relevant virtual host (Apache/mod_php, FPM pool, CGI, LiteSpeed, FrankenPHP, Windows/IIS FastCGI and container image). Record the *active* patch version, build, configuration, and reachable endpoints. Multiple versions can coexist.
2. **Patch immediately:** use at least the upstream versions above or an *explicitly verified* vendor patched build, with evidence for **both** CVEs. Avoid assuming a remote WAF protects an origin that can still be reached directly.
3. **Deploy and verify:** restart/recycle all workers (Apache, FPM, IIS FastCGI pools, etc.), roll containers and validate the live web-served version/loaded module and logs after the change. Re-run the scanner and attach change evidence. The scanner does not execute PHP or perform active exploitation tests.
4. **Preserve incident evidence:** retain historical HTTP access/error logs and EDR/SIEM data covering the period *before* patch deployment, review suspicious web worker activity and unexpected file/process changes. The scanner's IOC rules cannot establish that exploitation did not occur.
5. **If patching is delayed:** time-box the exception, reduce exposure and document the risk. **None** of the settings below is a complete fix.

### Incomplete short-term mitigations

- **CVE-2026-109618 (OOM):** PHP recommends administratively enforced `memory_limit=-1` (e.g. `php_admin_value`) plus conservative `post_max_size` and web edge/body/header/multipart limits. An underlying memory allocation failure can still expose the vulnerable path. Avoid using `RLIMIT_AS`/`RLIMIT_DATA` as a substitute. Apply memory/container limits with appropriate worker isolation and availability planning.
- **CVE-2026-109619 (stale state):** administratively set `session.upload_progress.enabled=0` and **restart all workers**. For PHP 8.5 additionally consider `fatal_error_backtraces=0` until patched. Both only block specific confirmed paths, **not all variants**. `ini_set()` and late `.user.ini` changes do not adequately establish pre-request protection.
- **Other:** restrict public access where practical, monitor web worker child processes and errors, resolve attacker-reachable fatal paths; do not mistake WAF controls for patches.

## Reading the scanner report

`BELOW_UPSTREAM_FIX` = observed version is lower than PHP's upstream threshold. **Not proof of an unpatched vendor-backport or an active web-facing runtime**. Urgent triage required.

`AT_OR_ABOVE_UPSTREAM_FIX` = reported upstream version passes the threshold. **Not proof of patched running SAPI or absence of compromise**.

`LEGACY_VENDOR_VERIFICATION_REQUIRED` = PHP 8.1 and earlier. Vendor attestations or migration are required.

`UNDETERMINED_VERSION` = incomplete version (`8.4`), version range (`^8.4`), unparseable version or no version found. **Never green.**

`REPOSITORY_DECLARATION_BELOW_FIX_DEPLOYMENT_UNKNOWN` = static repo declaration below threshold, not necessarily a deployed workload.

`--runtime-version` with `--runtime-sapi` and `--runtime-source` allows a consultant to **record** a separately checked web-serving version, but it remains operator-supplied and **not attested by the scanner**.

**Scoping limits:** no native RPM package database parsing, no automated Windows PHP runtime version extraction, and no active HTTP-to-PHP worker binding. These limitations must be addressed before the scanner is used to certify customer patch compliance.
