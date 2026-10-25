# v2.8.0 release finalize checklist

**Branch:** `release/v2.8.0-prep`  
**Code tip prerequisites:** nginx/FPM discovery on `main` (PR #34) **and** LIVE_DOCKER validation merge (PR #35, merge `ceeb424…`).  
**Explicit GO for finalize → merge → tag → publish:** **NOT YET** — Draft PR only until maintainer approval.

## Scope lock

- [x] Bounded nginx / PHP-FPM configuration discovery only — no Homebrew expansion, RPM/dnf, Docker runtime product features, or CTI
- [x] CVE thresholds unchanged (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35)
- [x] Exit codes, status JSON, CSV, fleet rollup, and `--quiet` contracts unchanged
- [x] `v2.7.5` tag/assets remain untouched; latest public stays **v2.7.5** until publish
- [x] Release notes state config correlation ≠ verified active HTTP runtime / patch state

## Pre-merge (this branch — draft state)

- [ ] `docs/releases/v2.8.0.md` finalized (remove UNRELEASED DRAFT banner) — **blocked on publish GO**
- [ ] `CHANGELOG.md` has `## v2.8.0 — YYYY-MM-DD`; Unreleased cleared of toward-v2.8.0 — **blocked on publish GO**
- [ ] README / RELEASE-NOTES / INSTALL / ADVANCED claim **latest public = v2.8.0** — **blocked on publish GO** (currently correctly claim **v2.7.5** + unreleased tree)
- [x] `bash scripts/check-release-docs.sh` passes on this branch (unreleased development tree mode)
- [x] Notes state absence of findings is not proof a host is PHP-free; coverage remains bounded

## Field / CI validation

- [x] LIVE_DOCKER 8/8 PASS — Actions run [40211792925](https://github.com/Opathedane/php2shell/actions/runs/40211792925) @ `87468994956db5fae7ce12aa645b6591e0e4a1bc`; preserved in `docs/pr-assets/v2.8.0-nginx-fpm-live/`
- [x] Post-validation merge CI green on `main` (`ceeb424…`)
- [ ] Interactive Windows PowerShell 5.1 ANSI/colour — status: **NOT TESTED** (not a publish blocker; must not be recorded as PASS)
- [ ] Interactive Windows Terminal ANSI/colour — status: **NOT TESTED** (same)
- [ ] Optional: Node.js 24 Actions baseline PR #36 — merge only with separate approval (CI hygiene; not a product blocker)

## After merge (maintainer / agent with **publish** GO only)

1. Finalize draft language → merge `release/v2.8.0-prep` → `main` (no force)
2. Confirm tip: `grep 'const Version' internal/audit/model.go` → `2.8.0`
3. Confirm: `bash scripts/check-release-docs.sh --for-tag v2.8.0`
4. Tag annotated tip only (never rewrite `v2.7.5`):

```bash
git checkout main && git pull
git tag -a v2.8.0 -m "PHP2Shell v2.8.0"
git push origin v2.8.0
```

5. Confirm release workflow publishes **new** assets; verify `SHA256SUMS`; confirm `php2shell version` → `2.8.0`
6. Do not overwrite any existing release tag assets

## Non-goals at publish time

- No Authenticode / notarization requirement for this release
- No Homebrew / RPM / Docker-runtime / CTI expansion
- No asset overwrite of any existing tag
- No claim that PowerShell 5.1 / Windows Terminal interactive ANSI was field-tested
- No claim that nginx/FPM config proves active HTTP-serving PHP or patch posture
