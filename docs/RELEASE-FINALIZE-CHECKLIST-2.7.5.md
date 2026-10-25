# v2.7.5 release finalize checklist

**Branch:** `release/v2.7.5-prep` (docs finalize after Version bump + PR #32 discovery)  
**Code tip to tag (after this branch merges):** merge commit of this PR onto `main` — must include merge of PR #32 symlink discovery (`04151cb` / descendants) **and** this finalize docs commit.  
**Explicit GO received** for finalize → merge → tag → publish.

## Scope lock

- [x] Unix symlink PHP executable discovery only (PR #32) — no nginx, PHP-FPM config, RPM, Docker, or broader audit roadmap items
- [x] CVE thresholds unchanged (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35)
- [x] Exit codes, status JSON, CSV, fleet rollup, and `--quiet` contracts unchanged
- [x] `v2.7.4` tag/assets remain untouched

## Pre-merge (this branch)

- [x] `docs/releases/v2.7.5.md` finalized (no UNRELEASED DRAFT banner)
- [x] `CHANGELOG.md` has `## v2.7.5 — 2026-10-25`; Unreleased cleared of toward-v2.7.5
- [x] README / RELEASE-NOTES / INSTALL / ADVANCED claim **latest public = v2.7.5** (on this branch)
- [x] `bash scripts/check-release-docs.sh --for-tag v2.7.5` passes on this branch
- [x] Notes state absence of findings is not proof a host is PHP-free; coverage remains bounded

## Field / CI validation

- [x] Automated CI green on PR #32 and finalize tip (ubuntu / windows-latest / macos + Windows legacy Go 1.20 cross-build)
- [ ] Interactive Windows PowerShell 5.1 ANSI/colour — status: **NOT TESTED** (not a publish blocker for this patch; must not be recorded as PASS)
- [ ] Interactive Windows Terminal ANSI/colour — status: **NOT TESTED** (same)

## After merge (maintainer / agent with GO)

1. Merge `release/v2.7.5-prep` → `main` (no force)
2. Confirm tip: `grep 'const Version' internal/audit/model.go` → `2.7.5`
3. Confirm: `bash scripts/check-release-docs.sh --for-tag v2.7.5`
4. Tag annotated tip only (never rewrite `v2.7.4`):

```bash
git checkout main && git pull
git tag -a v2.7.5 -m "PHP2Shell v2.7.5"
git push origin v2.7.5
```

5. Confirm release workflow publishes **new** assets; verify `SHA256SUMS`; confirm `php2shell version` → `2.7.5`
6. Do not overwrite any existing release tag assets

## Non-goals at publish time

- No Authenticode / notarization requirement for this patch
- No nginx / RPM / Docker / PHP-FPM pool discovery
- No asset overwrite of any existing tag
- No claim that PowerShell 5.1 / Windows Terminal interactive ANSI was field-tested
