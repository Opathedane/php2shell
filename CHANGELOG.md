# Changelog

## 2.1.0-alpha.2 — 2026-10-21 (developer-only)

- Implemented pinned Ed25519 signed, data-only indicator rule packs (one-time trust key, HTTPS GitHub download, fail closed signature/expiry checks, sequence rollback prevention, cached-only scanning without network).
- Added optional `--update-rules` and `--rules` scanner modes; maintainer `rules keygen/sign/verify` commands; deliberately no PHP2Shell-specific speculative indicators.
- Added matching of exact SHA-256 file hashes within bounded authorized webroots and fixed-string request-target indicators in bounded access logs, without saving raw client IP/query data.
- IIS W3C access-log format and timestamp parsing; passive IIS FastCGI handler and Windows process snapshots.
- Added tests for corrupted signatures, untrusted keys, expiration, rollback, HTTP/IIS privacy and hashes; CI test matrix includes Windows/macOS runners.
- Kept vulnerability status `NOT_VERIFIED`. Reports never treat no matches as compromise clearance. Real Windows Server/IIS, SAPI/vendor patch attestation and validated CVE-specific IOCs remain release blockers.

## 2.0.0-alpha.1

- Standalone Go proof of concept with local host/repo inventory, basic log coverage, HTML/CSV/JSON reports and analyst-controlled rollups.
