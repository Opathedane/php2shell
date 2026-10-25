# Remaining cleanup after Phase 1 (needs separate GO)

Phase 1 Draft PR covers README/docs only. Do **not** execute the items below without explicit approval.

| # | Action | Class |
| --- | --- | --- |
| 1 | Merge Phase 1 Draft PR after review | Human |
| 2 | Apply About description, topics, docs URL from [GITHUB-PRESENTATION-PROPOSAL.md](GITHUB-PRESENTATION-PROPOSAL.md); remove `cvs` | Human (UI) |
| 3 | Enable branch protection / ruleset per [PHASE1-GOVERNANCE-CHECKLIST.md](PHASE1-GOVERNANCE-CHECKLIST.md) | Human (UI) |
| 4 | Turn on “Automatically delete head branches” | Human (UI) |
| 5 | Delete 33 fully merged remote branches (ahead=0 vs `main`) | Human |
| 6 | Close/delete draft release `test-build-2.7.3-field` if unused | Human |
| 7 | Execute [DOCS-ARCHIVE-PLAN.md](DOCS-ARCHIVE-PLAN.md) moves + stubs | Separate docs PR |
| 8 | Add `.github/PULL_REQUEST_TEMPLATE.md` | Small chore PR |
| 9 | Optional: Dependabot for GitHub Actions; SHA-pin remaining CI actions | CI PR |
| 10 | Optional: CODE_OF_CONDUCT / CODEOWNERS / private vulnerability reporting | Human |

**Stable release remains v2.8.0** until a future publish GO.
