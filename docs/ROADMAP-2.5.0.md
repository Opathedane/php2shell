# PHP2Shell v2.5.0 roadmap (working notes)

Public **v2.4.0** remains unchanged. This document guides the next release branch. Do not tag or publish until the maintainer approves.

## Verified gaps after v2.4.0

| Area | v2.4.0 state | v2.5.0 direction |
| --- | --- | --- |
| Windows php.ini | `configuration` = NOT_SUPPORTED | Bounded discovery (shipped on this branch) |
| Linux php.ini | Glob-only under common `/etc` / Plesk paths | Sidecars, Remi/cPanel, PHPRC / PHP_INI_SCAN_DIR, web-server refs |
| php.ini authority | Settings observed with OBSERVED≠EFFECTIVE | Unchanged; also emit `php_ini_candidate` without inventing versions |
| Optional deep scan | Absent | **Proposed below — not implemented yet** |
| RPM package DB | Absent (dpkg/apk only) | **Deferred** — plan below |
| Webserver↔runtime | IIS/Apache config correlation | Incremental; still no active-SAPI attestation |
| Docs / governance | Some HTML-only / pre-2.4 wording | Clean up on this branch |

## Priority 2 — Optional Deep Discovery (proposal only)

**Do not implement a full-disk walker in v2.5.0 without explicit approval of these limits.**

### Interface (proposed)

```text
php2shell scan --deep-root DIR   # repeatable; off by default
```

- Requires at least one `--deep-root` (no implicit `C:\` or `/`).
- Mutually documented with `--webroot` (webroot = filenames under a site; deep-root = PHP install artifact hunt).

### Safety limits (proposed defaults)

| Limit | Default | Notes |
| --- | --- | --- |
| Max roots | 8 | Explicit list only |
| Max depth | 6 | From each root |
| Max directory entries visited | 25 000 | Same order as `--webroot` |
| Max PHP-like binaries recorded | 400 | Align with Windows discover cap |
| Max ini candidates | 200 | Align with configuration cap |
| Symlinks / Windows junctions | Skip | No follow |
| UNC / `\\?\` network prefixes | Reject unless later explicitly allowlisted | Avoid uncontrolled shares |
| Execution | Never | ReadRegular / Lstat only |
| Timeout | Existing `--timeout` | Mark coverage TRUNCATED/INCOMPLETE |

### Evidence types (proposed)

- `deep_scan_binary_candidate` — weaker than well-known binary evidence  
- `deep_scan_ini_candidate` — weaker than `php_ini_candidate` from trusted roots  
- Interpretations must say **DISCOVERED_ARTIFACT_NOT_VERIFIED_INSTALL**  
- Never alone drive “host is patched/safe”

### Coverage

Always emit `deep_discovery` check: `NOT_REQUESTED` | `PARTIAL` | `TRUNCATED` | `INCOMPLETE`.

## Priority 3 — RPM-based distributions (deferred plan)

**Recommendation: do not ship a half-parsed RPM reader in the first 2.5.0 cut unless fixtures prove NEVRA handling.**

### Approach (when implemented)

1. Prefer **read-only** open of the on-disk RPM DB (`/var/lib/rpm/` SQLite on modern RHEL; older BDB only if a trusted pure-Go reader exists).  
2. **No** `rpm` / `dnf` / `yum` subprocesses (preserve no-external-command posture).  
3. Record `installed_package` with Name/Epoch/Version/Release/Arch in Detail; `ObservedVersion` = upstream-comparable version only when parse is unambiguous.  
4. Keep interpretation `PACKAGE_VERSION_ONLY_VENDOR_BACKPORT_AND_ACTIVE_SAPI_UNVERIFIED`.  
5. Remi / SCL / `php84-*` names: map to branch carefully; never treat `.el9` / `remi` release tags as upstream CVE clearance.  
6. Fixtures: synthetic NEVRA rows for stock AppStream vs Remi below/at threshold.

Until then: binary globs + php.ini under `/opt/remi` / `/opt/cpanel` reduce false negatives without claiming package patch status.

## Priority 4 — Webserver correlation (incremental)

Preserve the ladder:

1. PHP installed on the host  
2. PHP configured for an application  
3. PHP actively serving HTTP (never from config alone)

Near-term increments (optional in 2.5.0): follow `PHPIniDir` / IIS `-c` into php.ini inventory (done); richer FPM pool `listen=` ↔ ProxyPassMatch matching can wait for a focused PR.

## Priority 5 — Repository / docs

- Fix stale “HTML-only” CI/governance wording for post-2.4.0 CSV pairs.  
- Keep historical `v2.4.0` release notes intact.  
- GitHub About suggestion: `Read-only PHP discovery and upstream patch review with HTML+CSV fleet reports (Windows/Linux)`.  
- Topics: `php`, `security`, `iis`, `apache`, `vulnerability-assessment`, `csv`, `golang`.  
- Licensing: keep `LICENSE.proposed` visible; no SPDX claim without owner approval.

## Regression fixture library (recommended)

Grow `testdata/` layouts (no customer data):

- Windows AppData `Programs\PHP\8.4.x\…` + sidecar php.ini  
- IIS E: site + FastCGI `-c`  
- Apache Debian sites-enabled + remote FPM  
- Remi-style `/opt/remi/php84/…` binary + ini (paths only)
