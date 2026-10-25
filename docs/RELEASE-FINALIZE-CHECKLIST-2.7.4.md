# v2.7.4 release finalize checklist

**Branch:** `release/v2.7.4-finalize` (docs-only finalization)  
**Code tip to tag (after this branch merges):** merge commit of this PR onto `main` — must include merge of PR #30 UX polish (`c7eae9c` / descendants) **and** this finalize docs commit.  
**Do not** merge / tag / publish until explicit GO.

## Scope lock

- [x] Usability/reliability only (no new CTI findings, IOC packs, discovery features, or CVE threshold changes)
- [x] CVE thresholds unchanged (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35)
- [x] Exit codes, status JSON, CSV, fleet rollup, and `--quiet` contracts unchanged
- [x] `v2.7.3` tag/assets remain untouched

## Pre-merge (this branch)

- [x] `docs/releases/v2.7.4.md` finalized (no UNRELEASED DRAFT banner)
- [x] `CHANGELOG.md` has `## v2.7.4 — 2026-10-25`; Unreleased cleared of toward-v2.7.4
- [x] README / RELEASE-NOTES / INSTALL / ADVANCED claim **latest public = v2.7.4** (on this branch only)
- [x] `bash scripts/check-release-docs.sh --for-tag v2.7.4` passes on this branch
- [x] Public `main` still documents latest public as **v2.7.3** until this branch merges

## Field / console validation

- [x] Automated CI green on UX PR #30 (ubuntu / windows-latest / macos + Windows legacy Go 1.20 cross-build)
- [ ] Interactive Windows PowerShell 5.1 ANSI/colour — status: **NOT TESTED** (not a publish blocker for this patch; must not be recorded as PASS)
- [ ] Interactive Windows Terminal ANSI/colour — status: **NOT TESTED** (same)

## After explicit GO (maintainer)

1. Merge `release/v2.7.4-finalize` → `main` (docs only; no force)
2. Confirm tip: `grep 'const Version' internal/audit/model.go` → `2.7.4`
3. Confirm: `bash scripts/check-release-docs.sh --for-tag v2.7.4`
4. Tag annotated tip only (never rewrite `v2.7.3`):

```bash
git checkout main && git pull
git tag -a v2.7.4 -m "PHP2Shell v2.7.4"
git push origin v2.7.4
```

5. Confirm release workflow publishes **new** assets; verify `SHA256SUMS`; confirm `php2shell version` → `2.7.4`
6. Do not overwrite any existing release tag assets

## Non-goals at publish time

- No Authenticode / notarization requirement for this patch
- No new signed IOC bundle
- No asset overwrite of any existing tag
- No claim that PowerShell 5.1 / Windows Terminal interactive ANSI was field-tested
