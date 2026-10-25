# How LIVE_DOCKER scans relate to real hosts

## Problem

Docker isolates filesystems and process namespaces. Scanning the GitHub Actions **host** would not observe PHP/nginx installed **inside** lab containers.

## Approach used by these labs

Each scenario’s `scan` service runs the `php2shell` binary **inside a container** whose filesystem presents ordinary well-known paths:

| Path in scan container | Source |
| --- | --- |
| `/etc/nginx/**` | Bind-mount of scenario `nginx/` tree |
| `/usr/local/etc/php-fpm.d/**` or `/etc/php/*/fpm/pool.d/**` | Bind-mount of scenario pool trees |
| `/usr/local/bin/php` (scenario 05 only) | Comes from the `php:8.3-cli-bookworm` image — a real package layout, not a planted decoy ELF |

No `--config-root`, `--deep-root`, or test-only CLI flags are passed.

## What this is equivalent to

A consultant copying a host’s `/etc/nginx` and FPM `pool.d` onto a forensic review system, **or** running php2shell on a host where those paths are the live configs. Config discovery and backend classification do not require opening FastCGI sockets or sharing `/proc` with php-fpm.

## Process / runtime ground truth (separate from php2shell)

Where a scenario cares whether php-fpm is running, the harness starts or withholds the `fpm` service and records independent observations under `results/<id>/ground-truth-runtime.json` using Docker/`pgrep` diagnostics. **php2shell itself never starts services or dials backends.**

## Non-goals

- Sidecar mounts that invent PHP binaries except scenario 05’s real CLI image  
- Privileged containers  
- Host-namespace `pid: host` tricks to make container processes look local to an unrelated scan  
