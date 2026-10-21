# PHP2Shell v2.7.0 proposal — inventory accuracy (post–Deep Discovery)

**Status:** proposal / early implementation on `feat/wellknown-discovery-2.7.0`.  
**Latest public release:** [v2.5.1](https://github.com/Opathedane/php2shell/releases/tag/v2.5.1).  
**Do not disrupt** `feat/deep-discovery-2.6.0` / in-tree 2.6.0 Deep Discovery.  
**Reference PowerShell/Bash inventory scripts are not in this repository** and must not be copied.

This document is the gap analysis and prioritized plan requested for v2.7.0.

---

## 1. Existing PHP2Shell vs reference-script ideas

### Already implemented correctly (category 1)

| Capability | Where |
| --- | --- |
| Multi-install retention + content-corroborated alias merge | `install_alias.go`, `runtime_correlate.go`, v2.5.1 tests |
| PATH / Programs\\PHP junctions (bounded) | `path_resolve.go`, `windows_php_discover.go` |
| XAMPP, Program Files PHP, inetpub CGI, php.net AppData installer | `windowsWellKnownPHPGlobs` |
| IIS FastCGI + site physicalPath correlation | `iis*.go` |
| Apache HTTP (not Tomcat) bounded inventory | `apache.go` |
| Linux Plesk / Remi / cPanel **bin** globs + dpkg/apk packages | `host.go`, `linuxWellKnownPHPGlobs` |
| php.ini inventory; WAMP/Laragon **ini** globs | `php_ini.go` |
| Evidence: verified binary / PE `.rsrc` / path-inferred / package / config-only | `binary_version.go`, `pe_version.go`, `path_version.go` |
| PE COFF used only for PE structure offsets — **not** as PHP build date | `pe_version.go` |
| Patch assessment separate from “PHP is present” | `patch.go` |
| `NO_PHP_OBSERVED_IN_SCOPE` / `NO_PHP_EVIDENCE_FOUND_COVERAGE_LIMITED` (not “PHP absent”) | `fleet_csv.go`, `summary.go` |
| Optional `--deep-root` (v2.6.0) for authorized recursive trees | `deep_discover.go` |
| Offline, no binary execution, no telemetry | product invariants |

### Worth implementing as small improvements (category 2)

| Item | Rationale |
| --- | --- |
| WAMP / Wamp64 / Laragon / `C:\tools\php` **binary** globs | Ini globs already exist; binaries were missing → false negatives on common stacks |
| Remi / cPanel **php-fpm sbin** + `/usr/local/php*` + `/opt/php/*` binary globs | Complements existing bin globs; still non-recursive |
| Install-card clarity in HTML (lifecycle placeholder later) | Reporting polish without new engine |
| Document “use `--deep-root` for odd trees” vs expanding default globs | Operator guidance |

### Requires larger architectural change (category 3)

| Item | Why larger |
| --- | --- |
| Read-only **RPM** DB (NEVRA, epoch, Remi parallel installs) | New parser + fixtures + backport semantics; already on long-term roadmap |
| Binary ↔ package file-list ownership (dpkg/rpm “owns this path”) | Needs package file indexes; conflict handling |
| Structured **PHP support lifecycle** (Active / Security-only / EOL / Unknown) | Versioned UTC calendar, CSV schema bump (likely **v3**), dual assessment UI |
| Richer evidence conflict resolution UI when package ≠ binary version | Report model + tests |
| nginx / LiteSpeed full config inventory | New scanners; out of scope unless scheduled |

---

## 2. Newly identified discovery gaps

1. **Windows stacks with ini but no binary globs:** WAMP, Laragon, Chocolatey-style `C:\tools\php`.
2. **Linux FPM under Remi/cPanel:** `sbin/php-fpm` trees not listed beside `bin/php`.
3. **Manual `/usr/local/php*` and `/opt/php/*`:** common; previously relied on PATH or `--deep-root`.
4. **No RPM ownership** on RHEL-family hosts (packages check = NOT_SUPPORTED).
5. **No first-class lifecycle status** in HTML/CSV (only advisory prose + legacy patch bucket for ≤8.1).
6. **Package↔binary correlation** is host-level package evidence today, not per-install ownership.

Plesk Windows PHP under Program Files may still need a validated layout sample before adding a dedicated glob.

---

## 3. Proposed additional installation paths (bounded defaults)

### Windows (implemented on this branch)

```
C:\wamp\bin\php\*\php.exe|php-cgi.exe
C:\wamp64\bin\php\*\php.exe|php-cgi.exe
C:\laragon\bin\php\*\php.exe|php-cgi.exe
C:\tools\php\php.exe|php-cgi.exe
C:\tools\php\*\php.exe|php-cgi.exe
```

Still **not** proposed for default: Herd/Scoop/Bitnami drive-wide trees (prefer `--deep-root`).

### Linux (implemented on this branch)

```
/usr/local/php*/bin/php*
/usr/local/php*/sbin/php-fpm*
/opt/remi/php*/root/usr/sbin/php-fpm*
/opt/cpanel/ea-php*/root/usr/sbin/php-fpm*
/opt/php/*/bin/php*
/opt/php/*/sbin/php-fpm*
```

---

## 4. Package ownership & RPM recommendation

**Recommendation for v2.7.0 (stretch) / v2.8.0 (likely):**

1. **Passive RPM DB reader** under `/var/lib/rpm` (or documented BDB/sqlite variants), **no** `rpm`/`dnf` subprocess.
2. Emit `installed_package` with NEVRA fields in `Detail` (`epoch=`, `version=`, `release=`, `arch=`).
3. Optional **ownership map**: if package file list names a discovered binary path, add `package_owns_binary` evidence linking install key ↔ package — confidence MEDIUM; never override HIGH binary metadata.
4. Always qualify: **vendor backport ≠ upstream fix clearance**.
5. Keep dpkg/apk path; extend similarly with `/var/lib/dpkg/info/*.list` for ownership (Debian) as a follow-on.

**Do not** run `dpkg -S` / `rpm -qf` as subprocesses.

---

## 5. PHP lifecycle assessment design

Independent of patch assessment:

| Field | Values |
| --- | --- |
| `php_lifecycle_status` | `ACTIVE_SUPPORT` \| `SECURITY_FIXES_ONLY` \| `END_OF_LIFE` \| `UNKNOWN` |
| `php_lifecycle_as_of_utc` | Date of embedded calendar |
| `php_lifecycle_source` | URL/citation of php.net supported versions page snapshot |

Rules:

- Embed a **versioned** calendar file (e.g. `internal/audit/lifecycle_calendar.go` or JSON) with UTC boundaries.
- Compare install major.minor only; unknown/future branches → `UNKNOWN`.
- Patch assessment unchanged (`BELOW_UPSTREAM_FIX`, etc.).
- CSV: introduce **`php2shell-fleet-csv/v3`** with new columns; rollup accepts v1–v3.
- No network fetch at scan time; refresh calendar via PR + release notes.

---

## 6. Explicitly rejected (do not copy from reference scripts)

- Executing `php -n -v` (or any discovered binary)
- HTTP POST / telemetry / API keys / env-based customer upload
- Manual JSON string concatenation for reports
- Unbounded filesystem walks as default discovery
- Treating “not found” as “PHP absent”
- Treating PE COFF timestamp as PHP build date
- Filename-alone as SAPI proof
- Equating package version with definitive CVE clearance when backports exist

---

## 7. Low-risk changes on this branch (if present)

- Expand Windows/Linux well-known **binary** globs (above)
- Extract `linuxWellKnownPHPGlobs()` for clarity/tests
- Fixture tests for stack layouts + PE guardrail
- This proposal document + ROADMAP pointer

**Not** in this low-risk slice: RPM parser, lifecycle calendar, CSV v3, HTML install cards.

---

## 8–10. Tests, reporting impact, prioritized roadmap

### Tests (planned / partial)

- [x] Glob list contains WAMP/Laragon/tools + Remi/cPanel/local patterns  
- [x] Temp fixtures match those glob shapes  
- [x] PE source does not treat COFF as build date  
- [ ] RPM NEVRA fixtures (later)  
- [ ] Lifecycle date boundary table (later)  
- [ ] Preserve v2.5.1 / v2.6.0 regressions (run full `go test ./...`)

### Reporting impact

- Low-risk glob work: **no schema change**; more installs appear in existing HTML/CSV rows.  
- Lifecycle + package ownership columns: **CSV v3** + HTML install overview section.

### Prioritized v2.7.0 roadmap

| Priority | Item | Effort | Schema |
| --- | --- | --- | --- |
| P0 | Well-known stack binary globs + tests | S | none |
| P1 | Debian package file-list ↔ binary ownership (read-only) | M | detail fields / optional v3 |
| P1 | Lifecycle calendar + HTML/CSV v3 columns | M | **v3** |
| P2 | RPM DB inventory + NEVRA + ownership | L | v3+ |
| P2 | Install-level HTML summary card | S–M | none/v3 |
| P3 | nginx/LSWS bounded inventory | L | TBD |

---

## Affected files (P0)

- `internal/audit/windows_php_discover.go`
- `internal/audit/linux_php_discover.go` (new)
- `internal/audit/host.go`
- `internal/audit/wellknown_stacks_test.go` (new)
- `docs/ROADMAP.md`, `docs/ROADMAP-2.7.0.md`
