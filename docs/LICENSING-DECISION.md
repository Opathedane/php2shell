# Licensing decision required (maintainer)

**Status:** No approved open-source license is in force. The tree contains `LICENSE.proposed` only.  
**Agents must not create `LICENSE` or set GitHub license metadata without your written approval.**

This short note explains the choice you must make before unrestricted public redistribution.

---

## 1. Why this blocks public distribution

Without a clear copyright grant, downloaders (and you) lack legal certainty to copy, modify, or redistribute binaries and source. Enterprise customers often cannot adopt tools that have no declared license.

Technical QA can finish without a license. **Public GitHub “open download for everyone” cannot.**

---

## 2. Ownership questions only you can answer

| Question | Why it matters |
| --- | --- |
| Who is the copyright owner — you personally, your employer (e.g. ITM8), or joint? | Wrong licensor invalidates the grant |
| If employment / work-for-hire applies, has the employer **authorized** public release under the chosen license? | Employment agreements often assign IP to the company |
| Are all past contributors covered (sole author, CLA, DCO, or email permission)? | History of PRs / patches |
| Is any third-party code embedded under an incompatible license? | Must attribute or remove |
| May the name “PHP2Shell” / branding be used under the chosen license and trademark policy? | Trademark ≠ copyright |
| Are signing keys, private customer reports, and secrets excluded from the public tree? | Avoid accidental publication |

Write answers somewhere durable (internal ticket or email). Do not rely on chat alone.

---

## 3. Practical options (you choose — not applied automatically)

| Option | Typical use | Notes |
| --- | --- | --- |
| **A. Apache License 2.0** (stated intent in `docs/LICENSING.md`) | Permissive OSS; patent grant; enterprise-friendly | Requires replacing `LICENSE.proposed` with official Apache-2.0 text as `LICENSE`, optional `NOTICE` |
| **B. MIT** | Maximal simplicity | No patent grant language; still need ownership clarity |
| **C. Proprietary / source-available** | Keep redistribution restricted | Publish a custom license; may still distribute binaries to customers under contract |
| **D. Delay public release** | Continue pilots under NDA / private release | Valid while ownership is unresolved |

**Recommendation for PHP2Shell’s stated goal:** Option **A** once employer/owner approval is written; until then Option **D** for public GitHub, with private pilot builds allowed under contract.

---

## 4. Steps after you decide (human-only)

1. Confirm answers in §2 in writing.
2. Approve the exact SPDX identifier (e.g. `Apache-2.0`).
3. Replace `LICENSE.proposed` → `LICENSE` with the official license text.
4. Add `NOTICE` if employer attribution is required.
5. Update README “Licensing” and GitHub repository license metadata.
6. Re-run `scripts/check-release-docs.sh` and cut the public milestone (likely **v2.8.0**).

Until then, documentation must continue to say: **no approved open-source license is in force.**
