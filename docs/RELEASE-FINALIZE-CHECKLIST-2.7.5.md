# v2.7.5 release finalize checklist

**Prep branch:** `release/v2.7.5-prep` (Version bumped; notes remain **unreleased draft**)  
**Code tip to tag (after explicit GO):** merge of this prep (or a follow-up finalize) onto `main` — must include merge of PR #32 symlink discovery (`04151cb` / descendants) **and** finalized docs.  
**Do not** merge finalize / tag / publish until explicit GO.

## Scope lock

- [x] Unix symlink PHP executable discovery only (PR #32) — no nginx, PHP-FPM config, RPM, Docker, or broader audit roadmap items
- [x] CVE thresholds unchanged (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35)
- [x] Exit codes, status JSON, CSV, fleet rollup, and `--quiet` contracts unchanged
- [x] `v2.7.4` tag/assets remain untouched
- [x] Latest public release documents remain **v2.7.4** while notes are draft

## Pre-publish (this prep / later finalize)

- [x] `docs/releases/v2.7.5.md` present with **Unreleased draft** banner (this prep)
- [ ] Remove draft banner and finalize `docs/releases/v2.7.5.md` (no UNRELEASED DRAFT language)
- [ ] `CHANGELOG.md` has `## v2.7.5 — YYYY-MM-DD`; Unreleased cleared of toward-v2.7.5
- [ ] README / RELEASE-NOTES / INSTALL / ADVANCED claim **latest public = v2.7.5** (finalize branch only)
- [ ] `bash scripts/check-release-docs.sh --for-tag v2.7.5` passes on finalize tip
- [x] Public `main` / this prep still document latest public as **v2.7.4** until finalize merges

## Field / CI validation

- [x] Automated CI green on PR #32 (ubuntu / windows-latest / macos + Windows legacy Go 1.20 cross-build)
- [x] Post-merge `go test ./...`, `go vet ./...`, `check-release-docs.sh` on `04151cb`
- [ ] Interactive Windows PowerShell 5.1 ANSI/colour — status: **NOT TESTED** (not a publish blocker for this patch; must not be recorded as PASS)
- [ ] Interactive Windows Terminal ANSI/colour — status: **NOT TESTED** (same)

## After explicit GO (maintainer)

1. Finalize notes (remove draft banner); bump latest-public docs to v2.7.5; merge finalize → `main` (no force)
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
