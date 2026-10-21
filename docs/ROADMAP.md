# PHP2Shell roadmap (after v2.5.1)

**Latest public release: [v2.5.1](https://github.com/Opathedane/php2shell/releases/tag/v2.5.1).** This document tracks work **not** yet shipped. Older “unreleased 2.5.0 / 2.5.1” planning notes are superseded.

## Shipped recently

### v2.5.1

- Bounded PATH / Programs\PHP junction resolve for names like `current`  
- Multi-install retention (PATH + IIS/Apache + `--config-root`); independent patch thresholds  
- `--php-ini` / `--config-root`; config-only and skip coverage in HTML+CSV  

### v2.5.0

- Bounded Windows/Linux `php.ini` discovery (sidecars, env, web-server path refs)  
- Fleet CSV `php2shell-fleet-csv/v2` configuration columns  
- Preserved HTML+CSV pairs, rollup, IIS/Apache inventory, Windows version inference  

## Planned for a later release (not scheduled)

### Optional Deep Discovery

Proposed CLI: `php2shell scan --deep-root DIR` (repeatable, **off by default**).

Suggested safety limits: max 8 roots, depth ≤ 6, ≤ 25 000 entries, ≤ 400 PHP-like binaries, ≤ 200 ini candidates; skip uncontrolled symlink walks; never execute binaries; weaker evidence types than well-known discovery; explicit TRUNCATED/INCOMPLETE coverage.

### RPM-based distributions

Read-only RPM DB inventory (no `rpm`/`dnf` subprocess) with careful NEVRA handling. Never treat vendor release/epoch tags as upstream CVE clearance.

### Advanced webserver ↔ runtime correlation

Richer FPM `listen` ↔ ProxyPassMatch / multi-install binding. Preserve: installed ≠ configured ≠ actively serving. No active-SAPI attestation from config alone.

## Repository / supply chain (process)

- Pin GitHub Actions to full commit SHAs  
- Detached signature over `SHA256SUMS`; Authenticode / notarization decisions  
- Approved open-source license **only** with explicit owner approval (`LICENSE.proposed` remains a placeholder)  

Historical filename: [ROADMAP-2.5.0.md](ROADMAP-2.5.0.md) (redirect stub).
