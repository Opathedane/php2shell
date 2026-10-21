# PHP2Shell roadmap

**Prepared release: [v2.6.0](releases/v2.6.0.md)** (documentation finalized; GitHub Release pending maintainer tag). Until `v2.6.0` is published, the latest published tag remains [v2.5.1](https://github.com/Opathedane/php2shell/releases/tag/v2.5.1). This document tracks work **not** yet shipped after that release. See [ROADMAP-2.7.0.md](ROADMAP-2.7.0.md) for the next inventory-accuracy proposal.

## Shipped recently

### v2.6.0

- Optional `--deep-root` Deep Discovery (off by default; bounded recursive roots)  
- Expanded well-known binary globs (WAMP/Laragon/tools; Remi/cPanel FPM; `/usr/local/php*`; `/opt/php/*`)  
- Preserved v2.5.1 multi-install, PATH/junction, `--php-ini` / `--config-root`  

### v2.5.1

- Bounded PATH / Programs\PHP junction resolve for names like `current`  
- Multi-install retention (PATH + IIS/Apache + `--config-root`); independent patch thresholds  
- `--php-ini` / `--config-root`; config-only and skip coverage in HTML+CSV  

### v2.5.0

- Bounded Windows/Linux `php.ini` discovery (sidecars, env, web-server path refs)  
- Fleet CSV `php2shell-fleet-csv/v2` configuration columns  
- Preserved HTML+CSV pairs, rollup, IIS/Apache inventory, Windows version inference  

## Planned for a later release (not scheduled)

### v2.7.0 — Inventory accuracy (proposal)

Gap analysis and priorities: [ROADMAP-2.7.0.md](ROADMAP-2.7.0.md).

- Package ownership correlation (dpkg file lists; later RPM)  
- PHP support lifecycle calendar + fleet CSV schema evolution  
- Install-level HTML summary cards  

### RPM-based distributions

Read-only RPM DB inventory (no `rpm`/`dnf` subprocess) with careful NEVRA handling. Never treat vendor release/epoch tags as upstream CVE clearance.

### Advanced webserver ↔ runtime correlation

Richer FPM `listen` ↔ ProxyPassMatch / multi-install binding. Preserve: installed ≠ configured ≠ actively serving. No active-SAPI attestation from config alone.

## Repository / supply chain (process)

- Pin GitHub Actions to full commit SHAs  
- Detached signature over `SHA256SUMS`; Authenticode / notarization decisions  
- Approved open-source license **only** with explicit owner approval (`LICENSE.proposed` remains a placeholder)  

Historical filename: [ROADMAP-2.5.0.md](ROADMAP-2.5.0.md) (redirect stub).
