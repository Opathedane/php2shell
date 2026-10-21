# PHP2Shell roadmap

**Latest public release: [v2.5.1](https://github.com/Opathedane/php2shell/releases/tag/v2.5.1).** In-tree development may include **2.6.0 (unreleased)** Deep Discovery. Planned follow-on: **v2.7.0** inventory accuracy — see [ROADMAP-2.7.0.md](ROADMAP-2.7.0.md).

## In progress / draft

### v2.6.0 — Optional Deep Discovery

See draft notes: [releases/v2.6.0.md](releases/v2.6.0.md).

- CLI: `php2shell scan --deep-root DIR` (repeatable, **off by default**)
- Limits: max 8 roots, depth ≤ 6, ≤ 25 000 entries, ≤ 400 PHP-like binaries, ≤ 200 ini candidates, 90s budget
- Skip uncontrolled symlink escapes; never execute binaries; weaker evidence types; explicit TRUNCATED/INCOMPLETE coverage

### v2.7.0 — Inventory accuracy (proposal)

Full gap analysis and priorities: [ROADMAP-2.7.0.md](ROADMAP-2.7.0.md).

- Expand bounded well-known binary globs (WAMP/Laragon/tools; Remi/cPanel FPM; `/usr/local/php*`)
- Later: package ownership correlation, read-only RPM DB, PHP support lifecycle (CSV v3)

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

### RPM-based distributions

Read-only RPM DB inventory (no `rpm`/`dnf` subprocess) with careful NEVRA handling. Never treat vendor release/epoch tags as upstream CVE clearance. Tracked under v2.7.0+ in [ROADMAP-2.7.0.md](ROADMAP-2.7.0.md).

### Advanced webserver ↔ runtime correlation

Richer FPM `listen` ↔ ProxyPassMatch / multi-install binding. Preserve: installed ≠ configured ≠ actively serving. No active-SAPI attestation from config alone.

## Repository / supply chain (process)

- Pin GitHub Actions to full commit SHAs  
- Detached signature over `SHA256SUMS`; Authenticode / notarization decisions  
- Approved open-source license **only** with explicit owner approval (`LICENSE.proposed` remains a placeholder)  

Historical filename: [ROADMAP-2.5.0.md](ROADMAP-2.5.0.md) (redirect stub).
