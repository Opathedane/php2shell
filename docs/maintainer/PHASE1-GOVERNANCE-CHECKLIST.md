# Maintainer governance checklist (Phase 1 — settings not changed)

Practical checklist for a **solo maintainer**. Apply in the GitHub UI only with separate approval. Avoid self-review deadlocks.

## Protect `main` without locking yourself out

Recommended **branch protection** / ruleset for `main`:

| Setting | Recommendation | Solo-maintainer note |
| --- | --- | --- |
| Require status checks | Yes — `Go tests` jobs (ubuntu, windows, macos, Windows legacy) | Use “require branches to be up to date” only if CI is fast enough |
| Require pull request before merge | Yes | Prefer PRs even for docs |
| Required approvals | **0 or optional** for solo; or 1 with “allow specified actors to bypass” = you | **Do not** set required reviewers = only yourself with no bypass — that creates a deadlock |
| Dismiss stale reviews | Optional | Fine if you later add a co-maintainer |
| Block force pushes | Yes | Always |
| Block deletions | Yes | Always |
| Restrict who can push | Optional | Your account / release bot only |

**Self-review deadlock avoidance:** either (a) required approvals = 0 while checks are required, or (b) ruleset bypass for the owner on `main`. Prefer (a) until a second human reviewer exists.

## Automatically delete merged branches

GitHub → Settings → General → **Automatically delete head branches** = On.

This replaces manual cleanup of `feat/*` / `release/*` after merge. Does **not** delete local clones or tags.

Existing already-merged remotes still need a one-time delete (separate GO; see professionalization audit).

## Dependabot

Start minimal:

1. Enable **Dependabot alerts** (if not already via org).  
2. Add `.github/dependabot.yml` later (Phase 2 PR) for:
   - `package-ecosystem: github-actions` (weekly)
   - optionally `gomod` if module deps grow beyond stdlib-adjacent
3. Keep **Dependabot security updates** optional until review capacity exists — Actions pins on release workflows already reduce surprise.

Do **not** auto-merge Dependabot without CI.

## Security advisories

- Keep [SECURITY.md](../../SECURITY.md) as the disclosure path (`jesma@itm8.com`).  
- Prefer GitHub **Private vulnerability reporting** (Settings → Code security) so reporters get a private channel without public issues.  
- Publish advisories only for defects in the **scanner / release pipeline**, not for the PHP CVEs PHP2Shell assesses.

## PR template

Add `.github/PULL_REQUEST_TEMPLATE.md` in a later docs/chore PR (suggested sections):

- Summary  
- Risk / honesty impact (discovery, assessments, exit codes, docs-only)  
- Test plan (`go test`, docs check, LIVE_DOCKER if nginx/FPM touched)  
- Checklist: no customer data; no tag/publish in the PR  

Issue templates already exist under `.github/ISSUE_TEMPLATE/`.

## CODEOWNERS / Code of Conduct

- **CODEOWNERS:** optional for solo; useful once a second maintainer exists.  
- **CODE_OF_CONDUCT:** optional Contributor Covenant if you expect external PRs; otherwise defer.

## Release discipline (already implemented)

- Tag `vX.Y.Z` only on verified `main`  
- `scripts/check-release-docs.sh --for-tag`  
- Never overwrite existing release assets  
- Latest public remains **v2.8.0** until a future GO  

## Explicitly deferred (need separate GO)

- Deleting the 33 merged remote branches  
- Closing draft release `test-build-2.7.3-field`  
- Applying About/topics from [GITHUB-PRESENTATION-PROPOSAL.md](GITHUB-PRESENTATION-PROPOSAL.md)  
- Moving files per [DOCS-ARCHIVE-PLAN.md](DOCS-ARCHIVE-PLAN.md)  
- Enabling/disabling Wiki or Projects  
