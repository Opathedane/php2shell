# Design: Bounded nginx / PHP-FPM discovery (toward v2.8.0)

**Branch:** `feat/nginx-fpm-discovery`  
**Status:** Implementation draft — not published

## Goal

Identify PHP FastCGI wiring from nginx and local PHP-FPM pool configs with the same honesty rules as Apache/IIS: configuration is a **candidate**, never a verified active HTTP runtime, and never a reason to treat a remote backend as patched from a local binary.

## Evidence confidence ladder (must preserve)

| Level | Meaning | How this feature contributes |
| --- | --- | --- |
| PHP installed | Binary/package/process inventory | Unchanged; FPM may note nearby binaries only via existing inspectors |
| PHP configured as candidate web handler | Static nginx `fastcgi_pass` / FPM `listen` | New `nginx_*` / `php_fpm_*` evidence |
| PHP process observed | Process inventory | Unchanged |
| Effective HTTP-serving runtime verified | Independent attestation | **Never** set from nginx/FPM config alone (`EffectiveWebRuntime` stays `NOT_VERIFIED`) |
| Runtime version / patch unknown | Candidate without inspectable version | Unresolved local socket/TCP without matching inventory; remote backends |

## Bounds

| Cap | Value |
| --- | --- |
| nginx config files | 64 |
| nginx file size | 2 MiB (`ReadRegular`) |
| nginx include depth | 3 (within allowlisted roots only) |
| nginx handler / upstream rows | 128 / 64 |
| FPM pool files | 64 |
| FPM file size | 1 MiB |
| Symlinks | Rejected by `ReadRegular` / directory Lstat (no tree walks through links) |
| Network | None (no connect, no DNS) |
| Execution | None |

## Well-known roots (no Homebrew expansion in this PR)

**nginx:** `/etc/nginx`, `/usr/local/etc/nginx`, `/usr/local/nginx/conf`  
**PHP-FPM pools:** `/etc/php/*/fpm/pool.d`, `/etc/php-fpm.d`, `/usr/local/etc/php-fpm.d`, plus seed `php-fpm.conf` under `/etc/php/*/fpm` and `/etc`

**Explicit roots** in this milestone means the allowlisted well-known directories above, plus `ApplyNginxRootsInventory` / `ApplyFPMPoolRootsInventory` for hermetic tests. Operator `--config-root` remains PHP binary/ini discovery only (parity with Apache well-known-only web configs). A dedicated nginx/FPM config-root flag is future work.

## Backend classification

| Backend | Evidence | Coverage effect |
| --- | --- | --- |
| `unix:/path.sock` | `nginx_php_handler_config` (local) | Correlate to FPM `listen` when identical |
| `127.0.0.1:N` / `localhost:N` / `[::1]:N` | local handler | Same |
| Non-loopback host:port | `nginx_remote_php_backend` | `nginx_configuration=INCOMPLETE` (like Apache remote) |
| Named `upstream` with only remote servers | remote | INCOMPLETE |
| Named upstream mixed/unknown | ambiguous detail; not a local install | Warning only if PHP-related location |
| Broken/cyclic/out-of-root include | Skip silently | No incomplete noise |
| Unreadable php-named path | Skip / existing unresolved binary path rules | No soft “no PHP” from silence when a binary path was relevant |

## Acceptance-test matrix

| # | Scenario | Expect |
| --- | --- | --- |
| 1 | nginx + local FPM Unix socket | Handler + pool + correlation detail; runtime **not** verified |
| 2 | nginx + local FPM TCP loopback | Same |
| 3 | nginx + remote FPM | `nginx_remote_php_backend`; coverage INCOMPLETE; no local install invented |
| 4 | Multiple pools / mixed versions | Distinct pool rows; independent installs retained |
| 5 | Missing / inaccessible configs | `NOT_APPLICABLE` or silent skip; no false PHP |
| 6 | Unresolved includes / cycles | Bounded; no hang; no crash |
| 7 | PHP detected, runtime version unknown | Existing binary/path rules; nginx does not invent version |
| 8 | PHP installed, not referenced by nginx | Inventory yes; no fake handler |
| 9 | No PHP within coverage | Soft none-within-coverage still honest |
| 10 | Apache + IIS regressions | Existing tests still pass |

## Out of scope (this PR)

Homebrew path expansion, RPM inventory, Docker, LiteSpeed, openresty-only layouts, UI polish, CVE threshold changes, merging into a release tag.
