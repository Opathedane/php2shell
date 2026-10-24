# Release checklist

Do not overwrite assets for an existing tag (`v2.3.0`–`v2.7.1`, …). Ship fixes under a new tag only.

## v2.7.1 publish prep

- [x] Embedded `Version` = `2.7.1`
- [x] Finalize `docs/releases/v2.7.1.md` (Published; no draft language; 2012 R2 marked field-unverified)
- [x] README / CHANGELOG / IR / deployment docs flipped to latest public **v2.7.1**
- [ ] Real Server 2012 R2 runtime field checklist signed off (legacy EXE shipped for testing only)
- [x] `scripts/check-release-docs.sh --for-tag v2.7.1` (on publish branch)
- [ ] GitHub Release `v2.7.1` via release workflow

## v2.7.0 publish prep

- [x] Embedded `Version` = `2.7.0`
- [x] Finalize `docs/releases/v2.7.0.md` (Published; no draft language)
- [x] README / CHANGELOG / IR docs flipped to latest public **v2.7.0**
- [x] Field validation guide: [FIELD-VALIDATION-2.7.0.md](FIELD-VALIDATION-2.7.0.md)
- [ ] Real-host field validation completed and recorded (not synthetic-only)
- [x] `scripts/check-release-docs.sh --for-tag v2.7.0` passes (on publish branch)
- [x] GitHub Release `v2.7.0` published

## Achieved in v2.6.0 (published)

- [x] Optional `--deep-root` Deep Discovery (off by default; bounded roots; TRUNCATED/INCOMPLETE signalling)
- [x] Expanded well-known binary globs (WAMP/Laragon/tools; Remi/cPanel FPM; `/usr/local/php*`; `/opt/php/*`)
- [x] Version-specific `docs/releases/v2.6.0.md` finalized for `check-release-docs.sh --for-tag v2.6.0`
- [x] GitHub Release `v2.6.0` published

## Achieved in v2.5.1 (published)

- [x] PATH / Programs\PHP bounded junction resolve for `current`-style aliases
- [x] Multi-install discovery (all PATH entries, IIS/Apache, `--config-root`); separate records + independent patch thresholds
- [x] `--php-ini` / `--config-root`; config-only + skip coverage in HTML+CSV
- [x] Version-specific `docs/releases/vX.Y.Z.md` + `scripts/check-release-docs.sh` publish gate

## Achieved in v2.5.0 (published)

- [x] Bounded Windows/Linux `php.ini` discovery; fleet CSV `php2shell-fleet-csv/v2`

## Achieved in v2.4.0 (published)

- [x] Automatic HTML + CSV report pair from every `scan`
- [x] Fleet CSV schema `php2shell-fleet-csv/v1` documented
- [x] Offline `rollup --input-dir` / CSV file consolidation with customer-label conflict checks
- [x] Preserve v2.3.1 Windows PHP version detection + TestVM regression
- [x] CI expects CSV beside HTML smoke output
- [x] Docs / CONTRIBUTING / licensing notes updated (Apache-2.0 still pending owner approval)

## Achieved in v2.3.0 / v2.3.1

- [x] Native Go builds; no Python or PHP interpreter required on the scanning host.
- [x] HTML assessment report (executive summary, grouped installations, next steps, collapsible evidence).
- [x] Non-execution of customer PHP / shell code; default scan is local bounded read-only.
- [x] Independent coverage states; no false `SAFE`, `PATCHED`, `NOT_VULNERABLE`, or `CLEAN` result.
- [x] Official upstream fix thresholds for the 21 October 2026 advisories integrated into patch review.
- [x] Opt-in Ed25519-signed indicator packs (empty unsigned template only in-repo; fail-closed verify).
- [x] CI tests on Linux (`ubuntu-24.04`), Windows (`windows-latest`), and macOS Intel (`macos-15-intel`).
- [x] Official release workflow refuses prerelease tags and refuses silently overwriting an existing release.

## Field validation (in progress — track before claiming broader assurance)

- [ ] Collect authorized real-world feedback via issue templates (detection misses, assessment disputes, crashes).
- [ ] Windows Server 2019/2022/2025 + IIS 10: handler inheritance, URL Rewrite, restricted accounts, app pools, log rotation.
- [ ] Linux: Apache/mod_php, nginx/PHP-FPM, LiteSpeed/LSAPI, containers, dpkg/apk/RPM and vendor backport packages.
- [ ] Confirm Tomcat-only hosts produce no false PHP web-server evidence.
- [ ] Confirm AppData / PATH / junction / package discovery against representative PHP layouts.
- [ ] Confirm `--quiet` / `--output-dir` (including UNC) under GPO / scheduled task / SYSTEM identities.

## MUST complete before the next customer-facing minor/major release

- [ ] Patch matrix spot-checks: below-fix and fixed upstream versions on Windows and Linux; document vendor-backport qualification wording.
- [ ] Publish a reviewed IOC bundle only when indicators are independently validated; sign with an org-controlled Ed25519 key (private key offline/HSM); distribute the public key out of band.
- [ ] Independent security review focus areas: symlink/TOCTOU, Windows ACLs, input caps, release workflow permissions.
- [ ] Decide Authenticode (Windows) and optional notarization (macOS) strategy; until then keep “unsigned + SHA256SUMS” messaging consistent.
- [ ] Pin GitHub Actions to reviewed immutable digests; enable branch/tag protection and required status checks on `main`.
- [x] Open-source license in force: Apache-2.0 (`LICENSE`).
- [ ] Add `docs/releases/vX.Y.Z.md` (concise GitHub Release body); update CHANGELOG dated section; clear Unreleased targeting that version; run `bash scripts/check-release-docs.sh --for-tag vX.Y.Z`.
- [ ] Tag `vX.Y.Z` only after CI is green; confirm embedded `version` matches the tag; confirm `gh release` creates a **new** release (no asset overwrite). Never use `docs/RELEASE-NOTES.md` as `--notes-file`.

## Prerelease / preview workflows (optional)

- `release-alpha.yml` remains for `v*-alpha.*` prereleases; keep assets marked prerelease.
- `build-preview.yml` may upload unsigned workflow artifacts for maintainer testing — not a substitute for a GitHub Release.

## Non-negotiable product claims

**Do not present PHP2Shell as establishing absence of PHP2Shell-class compromise, successful patch deployment of the live HTTP SAPI, or lack of compromise from empty IOC results.**

## Historical alpha gates (archived)

Earlier checklists for `2.1.0-alpha.2` / `2.2.0-alpha.*` are superseded by this document for current planning. Preserve alpha release notes under `docs/ALPHA-RELEASE-NOTES.md` and `CHANGELOG.md` for history only.
