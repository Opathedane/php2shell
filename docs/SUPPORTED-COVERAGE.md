# Supported platforms and scan coverage

**Latest public release: [v2.8.0](https://github.com/Opathedane/php2shell/releases/tag/v2.8.0).**

This page is the short coverage contract. Details and flags: [ADVANCED-USAGE.md](ADVANCED-USAGE.md). Report reading: [UNDERSTANDING-REPORTS.md](UNDERSTANDING-REPORTS.md).

## Supported runtimes for the scanner binary

| Platform | Artifact | Notes |
| --- | --- | --- |
| Windows 10 / 11 / Server 2016+ | `php2shell-windows-amd64.zip` | Primary Windows build |
| Windows Server 2012 R2 | `php2shell-windows-legacy-amd64.zip` | Go **1.20.14** legacy; see [WINDOWS-LEGACY-2012R2.md](WINDOWS-LEGACY-2012R2.md) |
| Linux amd64 / arm64 | `php2shell-linux-*.tar.gz` | Primary field target |
| macOS amd64 / arm64 | `php2shell-darwin-*.tar.gz` | Developer convenience |

## What the scanner inventories (bounded)

- PHP packages via **dpkg/apk** where available (not RPM in v2.8.0)
- PHP binaries via PATH and well-known paths; optional `--config-root` / `--deep-root`
- Windows IIS / Linux Apache configuration hints
- **nginx and PHP-FPM configuration** on well-known Unix paths (v2.8.0)
- Optional operator-supplied IR inputs (`--access-log`, `--error-log`, `--process-telemetry`, `--webroot`, `--waf-log`)

## Explicit honesty limits

| Claim you might want | What PHP2Shell actually does |
| --- | --- |
| “All PHP on the host was found” | **No** — coverage is bounded; missing evidence ≠ PHP-free |
| “This is the active HTTP-serving PHP” | **No** — `EffectiveWebRuntime` stays unverified from config/binary inventory alone |
| “nginx/FPM correlation proves patch state” | **No** — configuration correlation is never proof of active runtime or patch posture |
| “Exit 0 means patched / clean” | **No** — exit codes only describe report write / coverage completeness |
| “Vendor backport is OK” | **Only** if you verify separately |

## Out of scope in v2.8.0

- Homebrew / arbitrary custom prefixes for nginx or FPM  
- RPM/yum/dnf package-DB inventory  
- Docker/container runtime inventory as a product feature  
- Windows nginx  
- CTI / validated PHP2Shell-specific IOC packs as a default ship item  

Design notes for nginx/FPM: [design/nginx-fpm-discovery.md](design/nginx-fpm-discovery.md).
