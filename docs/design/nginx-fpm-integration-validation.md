# nginx / PHP-FPM integration validation (v2.8.0 readiness)

**Branch:** `validate/nginx-fpm-v2.8.0-readiness`  
**Base:** `main` @ post–PR #34 merge  

## Separation of test classes

| Class | What it proves | What it does **not** prove |
| --- | --- | --- |
| `SYNTHETIC_UNIT` | Parser honesty, bounds, correlation rules | Production package layouts, live processes |
| `REALISTIC_LAYOUT` | Debian-style directory shapes in-process | Running nginx/php-fpm daemons |
| `CONFIG_TREE_OFFLINE` | Lab scenario config trees match ground-truth contracts via the same parsers ScanHost uses | Live package installs, process presence, Docker networking |
| `LIVE_DOCKER` | PHP2SHELL against ordinary well-known paths inside isolated Compose labs | Field diversity (Homebrew, custom prefixes, SELinux, etc.) |

**Fixture/offline passes are not equivalent to live Docker passes.**

## Lab inventory

Reproducible Compose scenarios live under `testdata/nginx-fpm-labs/scenarios/`:

1. Unix socket local FPM  
2. Local TCP FPM  
3. Remote FPM (nginx-only scan FS)  
4. Multi-pool / mixed endpoints  
5. PHP/FPM present but not referenced by nginx  
6. Configured FPM with service not started (profile/runtime optional)  
7. Unreadable pool file  
8. PHP-free nginx  

Harness: `testdata/nginx-fpm-labs/scripts/run-all.sh`  
Offline contracts: `go test ./internal/audit/ -run TestNginxFPMLabConfigTreesMatchGroundTruth`

## Extra-evidence discipline

Scan containers mount **only** scenario nginx/FPM config trees at well-known paths and the php2shell binary. Labs do **not** pass `--config-root`, `--deep-root`, or plant synthetic PHP ELF decoys unless a scenario explicitly documents package presence. Remote scenario intentionally omits local pool.d from the scan filesystem.

## Agent limitation (this validation run)

Docker Engine was **not installed** on the validation host. `run-all.sh` recorded `results/SKIPPED-NO-DOCKER.txt`. Offline ground-truth contracts for all eight scenario trees **passed**. Live daemon confirmation remains a **release blocker recommendation** until executed on a Docker-capable runner.
