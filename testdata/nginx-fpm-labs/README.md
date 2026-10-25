# nginx / PHP-FPM live integration labs (v2.8.0 validation)

**Purpose:** Prove PHP2SHELL nginx/PHP-FPM discovery against isolated, reproducible environments with independently known ground truth.

**This is not equivalent to synthetic fixture tests.** Fixture and realistic-layout unit tests remain valuable; live labs exercise well-known path discovery inside a host-like filesystem with real nginx/PHP-FPM packages where Docker is available.

## Coverage classes

| Class | Meaning | Location |
| --- | --- | --- |
| `LIVE_DOCKER` | Real nginx and/or php-fpm containers; PHP2SHELL run inside a scan container seeing ordinary well-known paths | this directory + `scripts/run-all.sh` |
| `CONFIG_TREE_OFFLINE` | Same scenario config trees asserted via `ApplyNginxRootsInventory` / FPM parsers without live services | `internal/audit/nginx_fpm_lab_offline_test.go` |
| `SYNTHETIC_UNIT` / `REALISTIC_LAYOUT` | Existing unit tests | `internal/audit/nginx_fpm_*.go` |

## Prerequisites

- Docker Engine + Compose v2
- Ability to build a Linux `php2shell` binary (`GOOS=linux GOARCH=amd64`)

If Docker is unavailable, `scripts/run-all.sh` exits with status **0** and writes `results/SKIPPED-NO-DOCKER.txt`. That skip must be reported honestly in readiness docs — it is **not** a pass.

## Scenarios

| ID | Ground truth intent |
| --- | --- |
| `01-unix-socket` | Local unix FastCGI + matching FPM `listen` |
| `02-tcp-local` | Local TCP `127.0.0.1:9000` |
| `03-remote-fpm` | nginx-only view of remote FPM hostname |
| `04-multi-pool` | Two pools / two versioned trees; no version cross-inheritance |
| `05-php-not-configured` | PHP packages present; nginx has no PHP handler |
| `06-fpm-stopped` | Configs present; FPM process not running |
| `07-unreadable-config` | Mode-000 pool file → skip / incomplete, not soft none |
| `08-php-free` | nginx only; no PHP packages or handlers |

## Safety

- Labs never ask PHP2SHELL to execute PHP/nginx/php-fpm or open FastCGI sockets.
- Scan containers mount configs read-only where possible.
- No extra `--config-root` / `--deep-root` / planted synthetic PHP binaries beyond what the scenario’s packages install (see each `ground-truth.json`).

## Quick start

```bash
# from repo root (local: honest SKIP exit 0 if Docker missing)
bash testdata/nginx-fpm-labs/scripts/run-all.sh

# CI / required live (SKIP is a failure)
PHP2SHELL_LABS_REQUIRE_LIVE=1 bash testdata/nginx-fpm-labs/scripts/run-all.sh
```

Results land in `testdata/nginx-fpm-labs/results/<scenario>/`.

GitHub Actions workflow: `.github/workflows/nginx-fpm-labs.yml` (Ubuntu 24.04). See `SCAN-CONTEXT.md` for why php2shell runs **inside** scan containers rather than against the Actions host.
