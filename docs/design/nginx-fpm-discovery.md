# Design: Bounded nginx / PHP-FPM discovery (toward v2.8.0)

**Branch:** `feat/nginx-fpm-discovery`  
**Status:** Implementation draft — not published  
**PR:** #34

## Goal

Identify PHP FastCGI wiring from nginx and local PHP-FPM pool configs with the same honesty rules as Apache/IIS: configuration is a **candidate**, never a verified active HTTP runtime, and never a reason to treat a remote backend as patched from a local binary.

## Evidence confidence ladder (must preserve)

| Level | Meaning | How this feature contributes |
| --- | --- | --- |
| PHP installed | Binary/package/process inventory | Unchanged; FPM may note nearby binaries only via existing inspectors |
| PHP configured as candidate web handler | Static nginx `fastcgi_pass` / FPM `listen` | New `nginx_*` / `php_fpm_*` evidence |
| PHP process observed | Process inventory | Unchanged |
| Effective HTTP-serving runtime verified | Independent attestation | **Never** set from nginx/FPM config alone (`EffectiveWebRuntime` stays `NOT_VERIFIED`) |
| Runtime version / patch unknown | Candidate without inspectable version | Unresolved local socket/TCP without matching inventory; remote backends; variable `fastcgi_pass` |

## Bounds

| Cap | Value |
| --- | --- |
| nginx config files | 64 |
| nginx file size | 2 MiB |
| nginx include depth | 3 (within allowlisted roots only) |
| nginx handler / upstream rows | 128 / 64 |
| FPM pool files | 64 |
| FPM file size | 1 MiB |
| Symlinks (directories) | Rejected as discovery roots |
| Symlinks (config files) | One hop to a regular file **inside** the same allowlisted root (Debian `sites-enabled` → target); otherwise `nginx_config_skip` |
| Network | None (no connect, no DNS) |
| Execution | None |

## Well-known roots (no Homebrew expansion in this PR)

**nginx:** `/etc/nginx`, `/usr/local/etc/nginx`, `/usr/local/nginx/conf`  
**PHP-FPM pools:** `/etc/php/*/fpm/pool.d`, `/etc/php-fpm.d`, `/usr/local/etc/php-fpm.d`, plus seed `php-fpm.conf` under parent fpm dirs

**Explicit roots** means allowlisted well-known directories plus `ApplyNginxRootsInventory` / `ApplyFPMPoolRootsInventory` for hermetic tests. Operator `--config-root` remains PHP binary/ini discovery only.

## Backend classification

| Backend | Evidence | Coverage effect |
| --- | --- | --- |
| `unix:/path.sock` (no `$`) | `nginx_php_handler_config` (local) | Correlate to FPM `listen` when identical |
| `127.0.0.1:N` / `localhost:N` / `[::1]:N` | local handler | Same |
| Non-loopback host:port | `nginx_remote_php_backend` | `nginx_configuration=INCOMPLETE` |
| Named `upstream` with only remote servers | remote | INCOMPLETE |
| Named upstream mixed / unresolved name | ambiguous | INCOMPLETE |
| Arbitrarily named upstream referenced by PHP `fastcgi_pass` (e.g. `backend`) | Handler + `nginx_php_upstream_config` with `referenced_by_php_fastcgi_pass` | Classification preserved; runtime unverified |
| Unrelated proxy upstream (never referenced by PHP FastCGI) | Not emitted as PHP upstream evidence | No false PHP |
| `fastcgi_pass` containing `$…` | variable_unresolved (not local) | INCOMPLETE |
| Broken/cyclic include | Skip / bounded | No hang |
| PHP-relevant include blocked (allowlist / depth / `..`) | `nginx_include_unresolved` | Coverage `INCOMPLETE`; blocks soft “no PHP within coverage” |
| Irrelevant include blocked (e.g. out-of-root `mime.types`) | Silent | No incomplete noise |
| Unreadable / rejected config file | `nginx_config_skip` / `php_fpm_config_skip` | Coverage `INCOMPLETE`; blocks soft “no PHP within coverage” |

## Test classification

| Kind | Where | Notes |
| --- | --- | --- |
| **SYNTHETIC_UNIT** | `nginx_fpm_test.go`, `nginx_fpm_review_test.go` | Focused parser/honesty cases |
| **REALISTIC_LAYOUT** | `nginx_fpm_layout_integration_test.go` | Debian-style `sites-enabled` symlinks, versioned `pool.d`, mixed backends — **no live nginx/php-fpm process** |
| **CONFIG_TREE_OFFLINE** | `nginx_fpm_lab_offline_test.go` + `testdata/nginx-fpm-labs/scenarios/*/ground-truth.json` | Lab config trees vs ground truth without daemons |
| **LIVE_DOCKER** | `testdata/nginx-fpm-labs/` + `scripts/run-all.sh` | Real images when Docker is available; see `docs/design/nginx-fpm-integration-validation.md` |

Fixture/offline success is **not** equivalent to a live Docker pass.

## Acceptance-test matrix

| # | Scenario | Expect | Coverage |
| --- | --- | --- | --- |
| 1 | nginx + local FPM Unix socket | Handler + pool + correlation; runtime **not** verified | SYNTHETIC + REALISTIC_LAYOUT |
| 2 | nginx + local FPM TCP loopback | Same | SYNTHETIC + REALISTIC_LAYOUT |
| 3 | nginx + remote FPM | remote evidence; INCOMPLETE; no local install | SYNTHETIC + REALISTIC_LAYOUT |
| 4 | Multiple pools / mixed versions | Distinct pools; no cross-version inheritance | SYNTHETIC + REALISTIC_LAYOUT |
| 5 | Missing / inaccessible configs | skip evidence + INCOMPLETE; no false PHP | SYNTHETIC + REALISTIC_LAYOUT |
| 6 | Unresolved includes / cycles | Bounded; no hang | SYNTHETIC |
| 7 | Variable `fastcgi_pass` | Not local; INCOMPLETE | SYNTHETIC |
| 8 | PHP installed, not referenced by nginx | Inventory yes; no fake handler | SYNTHETIC + REALISTIC_LAYOUT |
| 9 | Configured but inactive backend | Candidate + correlation; NOT_VERIFIED | SYNTHETIC |
| 10 | Patched CLI ≠ remote/FPM patch | No version on remote/pool; runtime unverified | SYNTHETIC |
| 11 | Apache + IIS regressions | Existing tests still pass | existing suite |

## Out of scope (this PR)

Homebrew path expansion, RPM inventory, Docker live stacks, LiteSpeed, OpenResty-only layouts, UI polish, CVE threshold changes, merging into a release tag.
