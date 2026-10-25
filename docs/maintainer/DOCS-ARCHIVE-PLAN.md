# Documentation archive plan (proposal only — Phase 2+)

**Status:** Implemented on branch `docs/archive-historical-memos` (Draft PR). Stubs remain at original paths.

## Goal

Separate **living user/maintainer docs** from **historical release/QA/PR artifacts** without breaking inbound links. Preferred pattern: `git mv` into `docs/archive/…` plus a one-line stub at the old path that links to the new location (or keep stubs forever for GitHub Release note URLs that must not break).

## Recommended destinations

| Destination | Contents |
| --- | --- |
| `docs/archive/releases/` | Per-version finalize checklists, readiness gates tied to a shipped tag |
| `docs/archive/qa/` | Enterprise QA / field acceptance / stabilization memos |
| `docs/archive/pr-drafts/` | `pr-draft-*.md` authoring scratch |
| `docs/archive/reviews/` | Point-in-time audits (`*-2026-10-21.md`, DOCUMENTATION-AUDIT) |
| `docs/archive/presentation/` | GITHUB-PRESENTATION / PROJECT-PRESENTATION (superseded by maintainer proposals below) |
| **Keep in place** | `docs/releases/vX.Y.Z.md` (GitHub Release bodies), `docs/design/`, `docs/pr-assets/` (evidence), living guides |

## Exact inventory → recommendation

| File | Inbound links (repo grep, Phase 1) | Recommendation |
| --- | --- | --- |
| `docs/RELEASE-FINALIZE-CHECKLIST-2.8.0.md` | checklist self / release process | Archive → `archive/releases/` after stub |
| `docs/RELEASE-FINALIZE-CHECKLIST-2.7.5.md` | same | Archive |
| `docs/RELEASE-FINALIZE-CHECKLIST-2.7.4.md` | same | Archive |
| `docs/RELEASE-FINALIZE-CHECKLIST-2.7.3.md` | same | Archive |
| `docs/releases/v2.8.0-readiness.md` | design / release notes “see also” | Keep near releases **or** archive with stub; still useful evidence index |
| `docs/ENTERPRISE-QA-READINESS-2.7.2.md` | historically README | Archive → `archive/qa/` |
| `docs/FINAL-DISTRIBUTION-READINESS-2.7.2.md` | historically README | Archive |
| `docs/FINAL-RELEASE-GATE-2.7.2.md` | process | Archive |
| `docs/RELEASE-ACCEPTANCE-CHECKLIST-2.7.2.md` | historically README | Archive |
| `docs/FIELD-ACCEPTANCE-TESTS-2.7.2.md` | historically README | Archive |
| `docs/FIELD-TEST-V2.7.3-NO-PHP.md` | process | Archive |
| `docs/FIELD-VALIDATION-2.7.0.md` | process | Archive |
| `docs/V2.7.2-STABILIZATION.md` | process | Archive |
| `docs/AUDIT-PRODUCTION-READINESS-2.7.1.md` | process | Archive |
| `docs/pr-draft-v2.7.2-acceptance.md` | none critical | Archive → `archive/pr-drafts/` |
| `docs/pr-draft-v2.7.3-no-php.md` | none critical | Archive |
| `docs/DOCUMENTATION-AUDIT.md` | historical | Archive → `archive/reviews/` |
| `docs/REVIEW-2026-10-21.md` | historical | Archive |
| `docs/SECURITY-REVIEW-2026-10-21.md` | historical | Archive |
| `docs/GITHUB-PRESENTATION.md` | maintainer | Archive → `archive/presentation/`; use `maintainer/GITHUB-PRESENTATION-PROPOSAL.md` |
| `docs/PROJECT-PRESENTATION.md` | maintainer | Archive |
| `docs/ROADMAP-2.5.0.md` | ROADMAP stub link | Keep as stub or archive with stub |
| `docs/ROADMAP-2.7.0.md` | ROADMAP link | Keep until open items folded; then archive |
| `docs/ALPHA-RELEASE-NOTES.md` | RELEASE-NOTES | Keep (historical alpha) |
| `docs/LICENSING-DECISION.md` | licensing history | Archive optional; `LICENSING.md` remains authority |
| `docs/pr-assets/**` | evidence | **Keep** (not user-facing; evidence) |

## Link hygiene before any move

1. `rg -n 'FILENAME' --glob '*.md' --glob '*.yml'` across the repo (and GitHub issue bodies if needed).  
2. Prefer stubs at old paths for anything linked from published release notes or external bookmarks.  
3. Do **not** move `docs/releases/vX.Y.Z.md` — release workflow and published GitHub Releases depend on those paths.

## Out of scope for archive moves

- Scanner code, workflows, schemas  
- Deleting Git history or published release assets  
- Changing GitHub About/topics (separate maintainer checklist)
