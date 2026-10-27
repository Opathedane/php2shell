# PHP2Shell roadmap

**Latest public release: [v2.8.2](https://github.com/Opathedane/php2shell/releases/tag/v2.8.2)** (WampServer discovery maintenance). Notes: [releases/v2.8.2.md](releases/v2.8.2.md).

This file lists **open** product directions. It is not a commitment calendar. Honesty rules stay fixed: installed ≠ configured ≠ actively serving; config never attests patch posture of the live HTTP SAPI. Path-inferred directory versions remain MEDIUM-confidence inventory leads — not verified binary metadata and not active-runtime proof.

**Maintenance mode:** after v2.8.2, no additional development is planned without new security intelligence, confirmed defects, or demonstrated user demand.

## Shipped recently

### v2.8.2

- WampServer-style `phpX.Y.Z` path inference (path_inferred / MEDIUM)  
- Bounded Wamp Apache / wamp64 php.ini discovery; multi-source binary dedup  
- Clearer verified vs path-inferred vs unknown coverage messaging  
- No threshold / telemetry / active-runtime attestation / schema changes  

### v2.8.1

- ReliaQuest-aligned error patterns (`zend_mm_heap`, AH00052 Abort) + multi-signal correlation  
- Conservative time-only confidence handling; Unit 42 agentic process markers  
- No discovery / threshold / telemetry-source expansion  

### v2.8.0

- Bounded nginx + PHP-FPM well-known configuration discovery  
- Local / remote / ambiguous / variable FastCGI classification + pool correlation  
- LIVE_DOCKER eight-scenario validation  
- Preserved: config correlation ≠ verified active runtime / patch state  

### v2.7.5 – v2.7.3

- Unix PHP executable symlink discovery  
- Console / HTML UX reliability  
- OS-aware no-PHP reporting  

### v2.7.2 – v2.7.0

- CVE-2026-115560 informational advisory (static php.ini text)  
- Enterprise QA / Apache-2.0  
- Compromise investigation assist; fleet CSV v3  
- Windows Server 2012 R2 legacy artifact (Go 1.20.14)  

### v2.6.0 – v2.4.0

- Optional `--deep-root` Deep Discovery  
- Expanded well-known paths; php.ini discovery; HTML+CSV pairs; IIS/Apache inventory  

## Planned for a later release (not scheduled)

### Inventory accuracy

Gap analysis retained in [ROADMAP-2.7.0.md](ROADMAP-2.7.0.md):

- Package ownership correlation (dpkg file lists; later RPM)  
- PHP support lifecycle calendar + fleet CSV schema evolution  
- Install-level HTML summary cards  

### RPM-based distributions

Read-only RPM DB inventory (no `rpm`/`dnf` subprocess) with careful NEVRA handling. Never treat vendor release/epoch tags as upstream CVE clearance.

### Deeper webserver ↔ runtime correlation

Richer binding across FPM / reverse-proxy layouts **without** claiming active-SAPI attestation from configuration alone. Homebrew / custom-prefix expansion remains a separate, bounded design problem.

### Detection / investigation (deferred — not in v2.8.2)

Candidates for a **future maintenance decision only** (source-integrity and false-positive review required before any adoption):

- CISA KEV catalog awareness / documentation (CVE-2026-109618 / CVE-2026-109619 added **26 Oct 2026**)  
- Selective evaluation of CISA TLP:CLEAR Sigma hunting keywords vs existing IR patterns (PoC markers, multipart/body signals, infrastructure IOCs) — many are unsuitable for default offline scanner rules without high FP risk  
- Additional Unit 42 / public research signals not already covered in v2.8.1  

### Explicitly not near-term product goals

- Docker/container runtime inventory as a product feature  
- CTI / validated PHP2Shell-specific IOC packs as a default ship item  
- Authenticode / notarization (process tracked under deployment docs; not required for unsigned+SHA256SUMS releases)

## Repository / supply chain (process)

- Broader SHA-pinning of GitHub Actions beyond release workflows  
- Detached signature over `SHA256SUMS`; Authenticode / notarization decisions  
- Open-source license: **Apache-2.0** (`LICENSE`) — done  
- Branch protection / Dependabot / docs archive hygiene — see professionalization audit follow-ups  

Historical stubs: [ROADMAP-2.5.0.md](ROADMAP-2.5.0.md), [ROADMAP-2.7.0.md](ROADMAP-2.7.0.md).
