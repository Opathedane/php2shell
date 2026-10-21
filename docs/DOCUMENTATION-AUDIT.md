# Documentation audit (historical)

Originally performed after the public v2.3.0 release. Current prepared release is **v2.6.0** — see [RELEASE-NOTES.md](RELEASE-NOTES.md). Separates **documentation fixes** from **implementation / product gaps** (not bugs in the docs).

## Documentation inconsistencies corrected on this branch

| Topic | Finding | Resolution |
| --- | --- | --- |
| Alpha / preview status | `RELEASE-CHECKLIST.md` and some advanced docs still framed the product as alpha-only | Checklist rewritten for post-2.3.0; README/SECURITY updated |
| JSON / CSV reporting | Early docs implied scan-time JSON exports | Clarified: `scan` writes HTML+CSV pairs (since v2.4.0); legacy JSON remains for some rollup inputs |
| Release checklist age | Gates still listed “never run on Windows” / alpha publish steps | Replaced with field-validation and next-release gates; preserve history in CHANGELOG |
| Alpha release notes | Could be read as current product status | Marked historical in `ALPHA-RELEASE-NOTES.md` |
| Admin audience | README was short but light on verification and platform matrix | Expanded getting started, matrix, limitations, verification |

## Not documentation bugs (known product / process limitations)

These reflect intentional or unfinished product behavior — do **not** “fix” by softening docs:

- No Authenticode / notarization on release binaries.
- No bundled validated PHP2Shell-specific IOC pack (`rules/template.json` empty by design).
- No automatic attestation of the live HTTP-serving SAPI.
- No automatic verification of vendor security backports.
- Default `rollup` consolidates fleet CSV; legacy `--format json` remains for older inputs.
- Windows Server / IIS / enterprise package layouts need continued field validation.
- `LICENSE.proposed` is not an approved license (ownership decision pending).
- Actions are pinned to major tags (`@v5` / `@v6`), not immutable commit SHAs yet (see `GOVERNANCE.md`).

## CLI arguments verified against v2.3.0 help

Documented commands match current `php2shell` / `scan` help: `doctor`, `scan` with `--webroot`, `--php-ini`, `--config-root`, `--deep-root` (optional Deep Discovery; off by default), `--repo`, `--access-log`, `--docker`, `--output-dir`, `--out`, `--quiet`, `--timeout`, `--customer`, `--runtime-version` / `--runtime-sapi` / `--runtime-source`, `--rules`, `--update-rules`, `--rules-url`, plus `rules` subcommands and legacy `rollup`.

## Preserved historical material

- `CHANGELOG.md` alpha entries retained.  
- `docs/ALPHA-RELEASE-NOTES.md` retained as historical.  
- Review memos under `docs/*-2026-10-21.md` retained as point-in-time reviews.
