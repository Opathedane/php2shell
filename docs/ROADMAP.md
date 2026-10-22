# PHP2Shell roadmap

**Latest public release: [v2.6.0](https://github.com/Opathedane/php2shell/releases/tag/v2.6.0).** Unreleased **2.7.0** release candidate (compromise investigation) is documented in [releases/v2.7.0.md](releases/v2.7.0.md) (UNRELEASED DRAFT) and [COMPROMISE-INVESTIGATION.md](COMPROMISE-INVESTIGATION.md). Inventory follow-ups that remain after IR: [ROADMAP-2.7.0.md](ROADMAP-2.7.0.md) (rename/clarify after publish).

## Shipped recently

### v2.7.0 (release candidate — not published)

- Offline access/error-log investigation  
- Offline MDE / Sysmon / auditd / Elastic ECS process telemetry  
- Passive webroot metadata investigation  
- Cross-source ±15m correlation (proximity ≠ causality)  
- Independent exploitation / possible-compromise / coverage statuses  
- Fleet CSV `php2shell-fleet-csv/v3` + v1–v3 rollup  

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

### Inventory accuracy (was “ROADMAP-2.7.0 proposal”)

Gap analysis: [ROADMAP-2.7.0.md](ROADMAP-2.7.0.md). Remaining after IR ships:

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
