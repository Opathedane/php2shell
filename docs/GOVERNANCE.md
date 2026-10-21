# Security and release governance

Post-v2.6.0 notes for maintainers and reviewers. This document does **not** change scanner behavior or published release assets.

## Licensing and ownership

- `LICENSE.proposed` is a **draft placeholder**, not an approved open-source license.
- Do **not** add a `LICENSE` file or assert SPDX / open-source rights without explicit owner approval.
- Until licensed, treat redistribution and derivative use as unapproved; keep README and release notes explicit about this.

## Repository permissions and branch protection (recommended)

Configure on GitHub (Settings → Branches / Rulesets):

| Control | Recommendation |
| --- | --- |
| Default branch | `main` |
| Required PR reviews | ≥1 (owner or designated maintainer) |
| Required status checks | CI job matrix (Linux, Windows, macOS) must pass |
| Restrict who can push | No direct pushes to `main` for contributors |
| Tag protection | Restrict creation of `v*` tags to maintainers |
| Force push / deletion | Disabled on `main` and release tags |
| Actions permissions | Read for PR workflows; `contents: write` only on release publish job |
| Secrets | No rule-signing private keys in GitHub Secrets or the repo |

Also enable Dependabot or equivalent for Go modules and Actions, and require signed commits if organizational policy demands it.

## Release workflow security (current)

| Workflow | Purpose | Notes |
| --- | --- | --- |
| `ci.yml` | Test on push/PR to `main` | Asserts HTML+CSV smoke pair from `scan` (no `.json`) |
| `release.yml` | Official `vX.Y.Z` publish | Tag must match embedded version; refuses prerelease suffixes; refuses overwrite of existing release |
| `release-alpha.yml` | `v*-alpha.*` prerelease | Historical / optional; keep `--prerelease` |
| `build-preview.yml` | Manual unsigned artifacts | Not a release; do not distribute as production |

**Do not** re-run publish against an existing tag to replace binaries (e.g. do not modify `v2.3.0`–`v2.6.0` assets). Ship fixes under a new tag only. GitHub Release bodies must come from `docs/releases/vX.Y.Z.md` via `scripts/check-release-docs.sh --for-tag`.

## Artifact integrity (current and future)

**Today**

- Consumers verify `SHA256SUMS` from the GitHub Release page.
- Binaries are not Authenticode-signed or notarized.

**Next improvements (priority order)**

1. Pin `actions/checkout`, `actions/setup-go`, and `actions/upload-artifact` to full commit SHAs (immutable digests).
2. Publish a detached signature over `SHA256SUMS` (maintainer key) in addition to checksums.
3. Windows Authenticode signing with an org code-signing certificate; document SmartScreen reputation ramp-up.
4. Optional macOS notarization for darwin convenience builds if those remain distributed.
5. Provenance attestation (e.g. SLSA / `gh attestation`) once signing identity is decided.

## Rules / IOC signing

- Indicator private keys must stay offline; never commit private material.
- Public key distribution must be out-of-band from the same GitHub raw path used for updates (see `rules/README.md`).
- Empty or missing rule packs must never be described as “clean.”

## Contact

Maintainer / disclosure: **jesma@itm8.com** (see `SECURITY.md`).
