# Release checklist — post v2.4.0 preparation

Do not overwrite assets for an existing tag (`v2.3.0`, `v2.3.1`, …). Ship fixes under a new tag only.

## Achieved in v2.4.0 (this tree; tag pending approval)

- [x] Automatic HTML + CSV report pair from every `scan`
- [x] Fleet CSV schema `php2shell-fleet-csv/v1` documented
- [x] Offline `rollup --input-dir` / CSV file consolidation with customer-label conflict checks
- [x] Preserve v2.3.1 Windows PHP version detection + TestVM regression
- [x] CI expects CSV beside HTML smoke output
- [x] Docs / CONTRIBUTING / licensing notes updated (Apache-2.0 still pending owner approval)

## Achieved in v2.3.0 / v2.3.1

- [x] Native Go builds; no Python or PHP interpreter required on the scanning host.
- [x] HTML-only assessment report (executive summary, grouped installations, next steps, collapsible evidence).
- [x] Non-execution of customer PHP / shell code; default scan is local bounded read-only.
- [x] Independent coverage states; no false `SAFE`, `PATCHED`, `NOT_VULNERABLE`, or `CLEAN` result.
- [x] Official upstream fix thresholds for the 21 October 2026 advisories integrated into patch review.
- [x] Opt-in Ed25519-signed indicator packs (empty unsigned template only in-repo; fail-closed verify).
- [x] CI tests on Linux (`ubuntu-24.04`), Windows (`windows-latest`), and macOS Intel (`macos-15-intel`).
- [x] Official release workflow refuses prerelease tags and refuses silently overwriting an existing release.
- [x] Public documentation for consultants, limitations, and contact / disclosure path.

## Field validation (in progress — track before claiming broader assurance)

- [ ] Collect authorized real-world feedback via issue templates (detection misses, assessment disputes, crashes).
- [ ] Windows Server 2019/2022/2025 + IIS 10: handler inheritance, URL Rewrite, restricted accounts, app pools, log rotation.
- [ ] Linux: Apache/mod_php (bounded config inventory in v2.4.0 — validate on real hosts), nginx/PHP-FPM, LiteSpeed/LSAPI, containers, dpkg/apk/RPM and vendor backport packages.
- [ ] Confirm Tomcat-only hosts produce no false PHP web-server evidence.
- [ ] Confirm AppData / PATH / package discovery against representative PHP layouts (no timeout or hang regressions).
- [ ] Confirm `--quiet` / `--output-dir` (including UNC) under GPO / scheduled task / SYSTEM identities.

## MUST complete before the next customer-facing minor/major release

- [ ] Patch matrix spot-checks: below-fix and fixed upstream versions on Windows and Linux; document vendor-backport qualification wording.
- [ ] Publish a reviewed IOC bundle only when indicators are independently validated; sign with an org-controlled Ed25519 key (private key offline/HSM); distribute the public key out of band.
- [ ] Independent security review focus areas: symlink/TOCTOU, Windows ACLs, input caps, release workflow permissions.
- [ ] Decide Authenticode (Windows) and optional notarization (macOS) strategy; until then keep “unsigned + SHA256SUMS” messaging consistent.
- [ ] Pin GitHub Actions to reviewed immutable digests; enable branch/tag protection and required status checks on `main`.
- [ ] Obtain approved open-source license / ownership attribution **only with explicit owner approval** (do not treat `LICENSE.proposed` as a license).
- [ ] Update `docs/RELEASE-NOTES.md` for the new version; never reuse or rewrite historical alpha notes as current product status.
- [ ] Tag `vX.Y.Z` only after CI is green; confirm embedded `version` matches the tag; confirm `gh release` creates a **new** release (no asset overwrite).

## Prerelease / preview workflows (optional)

- `release-alpha.yml` remains for `v*-alpha.*` prereleases; keep assets marked prerelease.
- `build-preview.yml` may upload unsigned workflow artifacts for maintainer testing — not a substitute for a GitHub Release.

## Non-negotiable product claims

**Do not present PHP2Shell as establishing absence of PHP2Shell-class compromise, successful patch deployment of the live HTTP SAPI, or lack of compromise from empty IOC results.**

## Historical alpha gates (archived)

Earlier checklists for `2.1.0-alpha.2` / `2.2.0-alpha.*` are superseded by this document for current planning. Preserve alpha release notes under `docs/ALPHA-RELEASE-NOTES.md` and `CHANGELOG.md` for history only.
