# v2.7.3 release finalize checklist

**Branch:** `release/v2.7.3-finalize` (docs-only finalization)  
**Code tip to tag (after this branch merges):** merge commit of this PR onto `main` (or squash tip) — must include `065b9fe` no-PHP reporting **and** this finalize docs commit.  
**Do not** merge / tag / publish until Windows field PASS + explicit GO.

## Scope lock

- [x] Reporting/usability only (no new CTI findings, IOC packs, or detection capabilities in this release)
- [x] CVE thresholds unchanged (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35)
- [x] `v2.7.2` tag/assets remain untouched

## Pre-merge (this branch)

- [x] `docs/releases/v2.7.3.md` finalized (no UNRELEASED DRAFT banner)
- [x] `CHANGELOG.md` has `## v2.7.3 — 2026-10-25`; Unreleased cleared of toward-v2.7.3
- [x] README / RELEASE-NOTES / INSTALL / ADVANCED claim **latest public = v2.7.3**
- [x] `bash scripts/check-release-docs.sh --for-tag v2.7.3` passes on this branch
- [x] Public `main` still documents latest public as **v2.7.2** until this branch merges

## Field gate

- [x] Maintainer GO to publish **without** waiting for Windows field retest (2026-10-25)
- [ ] Windows retest on the original no-PHP host — status: **NOT TESTED** (outstanding; must not be recorded as PASS)  
  Follow [FIELD-TEST-V2.7.3-NO-PHP.md](FIELD-TEST-V2.7.3-NO-PHP.md) when convenient

## After explicit GO (maintainer)

1. Merge `release/v2.7.3-finalize` → `main` (docs only; no force)
2. Confirm tip: `grep 'const Version' internal/audit/model.go` → `2.7.3`
3. Confirm: `bash scripts/check-release-docs.sh --for-tag v2.7.3`
4. Tag annotated tip only (never rewrite `v2.7.2`):

```bash
git checkout main && git pull
git tag -a v2.7.3 -m "PHP2Shell v2.7.3"
git push origin v2.7.3
```

5. Confirm release workflow publishes **new** assets; verify `SHA256SUMS`; confirm `php2shell version` → `2.7.3`
6. Optional: close/delete draft field-test release `test-build-2.7.3-field` so it is not confused with stable

## Non-goals at publish time

- No Authenticode / notarization requirement for this patch
- No new signed IOC bundle
- No asset overwrite of any existing tag
