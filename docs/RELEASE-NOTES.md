# PHP2Shell release notes

**Latest public release: [v2.7.4](https://github.com/Opathedane/php2shell/releases/tag/v2.7.4)** (25 October 2026).

Version-specific GitHub Release bodies live under [`docs/releases/`](releases/). The publish workflow uses **only** the matching `docs/releases/vX.Y.Z.md` file — never this index.

| Version | Notes |
| --- | --- |
| [v2.7.4](releases/v2.7.4.md) | Console UX / reliability polish (patch; no new CTI/IOC) |
| [v2.7.3](releases/v2.7.3.md) | OS-aware no-PHP reporting & HTML usability (patch; no new CTI/IOC) |
| [v2.7.2](releases/v2.7.2.md) | Enterprise QA + CVE-2026-115560 advisory assessment + Apache-2.0 |
| [v2.7.1](releases/v2.7.1.md) | IR accuracy + Cloudflare WAF + Win2012 R2 legacy artifact + deployment diagnostics |
| [v2.7.0](releases/v2.7.0.md) | Compromise investigation assist; fleet CSV v3 |
| [v2.6.0](releases/v2.6.0.md) | Optional `--deep-root` Deep Discovery; expanded well-known install paths |
| [v2.5.1](releases/v2.5.1.md) | PATH/junction discovery; multi-install; `--php-ini` / `--config-root` |
| [v2.5.0](releases/v2.5.0.md) | php.ini discovery; fleet CSV v2 |
| [v2.4.0](releases/v2.4.0.md) | HTML+CSV pairs; IIS/Apache inventory; fleet rollup |
| [v2.3.1](https://github.com/Opathedane/php2shell/releases/tag/v2.3.1) | Windows path/PE version inference |
| [v2.3.0](https://github.com/Opathedane/php2shell/releases/tag/v2.3.0) | First public HTML assessment release |

Historical alpha notes: [ALPHA-RELEASE-NOTES.md](ALPHA-RELEASE-NOTES.md) (not current product status).

## Ongoing product limitations (all releases)

- Does **not** attest the PHP runtime that actively serves HTTP  
- Does **not** verify distribution/vendor security backports  
- Does **not** prove absence of compromise when no indicators match  
- Does **not** upload customer data or apply remediation  
- Does **not** execute discovered PHP binaries  
- `customer_label` is not authenticated tenancy  
- Binaries are **not** Authenticode-signed; verify `SHA256SUMS`  
- Open-source license: **Apache License 2.0** (`LICENSE`)  

