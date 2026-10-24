# Licensing status (pending maintainer approval)

**Decision worksheet for the copyright owner:** [LICENSING-DECISION.md](LICENSING-DECISION.md).

## Intent

The maintainer intends PHP2Shell to be released under the **Apache License 2.0**.

## Current repository state

- `LICENSE.proposed` remains a **placeholder**, not an approved open-source license.
- No SPDX license assertion should be added to `README` or GitHub “License” metadata until ownership and contributor rights are confirmed.

## Maintainer decision required (do not auto-apply)

Unrestricted public distribution is **blocked** until a human copyright owner confirms:

| Question | Why it matters |
| --- | --- |
| Who owns the copyright (individual vs employer such as ITM8)? | Wrong licensor invalidates the grant |
| Does the employer authorize Apache-2.0 publication of **all** tree contents? | Employment / work-for-hire |
| Are all contributors covered (CLA/DCO or explicit agreement)? | PR history |
| Is any third-party code present with an incompatible license? | Clean-room / attribution |
| May the name “PHP2Shell” be used under trademark policy once Apache-2.0 is declared? | Branding |
| Are signing keys / customer artifacts excluded from the licensed public tree? | Secrets |

**Agents and automation must not create `LICENSE` or change GitHub license metadata without explicit written approval answering the table above.**

## Before committing `LICENSE`

Confirm all of the following:

1. The copyright holder (individual and/or employer such as ITM8) authorizes Apache-2.0 publication of **all** repository contents.
2. No third-party code with an incompatible license is embedded without attribution and permission.
3. Contributor submissions (PRs) are covered by the chosen license or a CLA / DCO if required by policy.
4. Rule-signing keys and any customer artifacts are **not** redistributed in the licensed tree.
5. Trademark / product naming (“PHP2Shell”) use is acceptable under the chosen license and branding policy.

## Proposed action (not applied without approval)

1. Replace `LICENSE.proposed` with the official Apache License 2.0 text as `LICENSE`.
2. Add a short copyright notice in `NOTICE` if employer attribution is required.
3. Update README “Licensing” to state Apache-2.0.
4. Set GitHub repository license metadata to Apache-2.0.

Until then, documentation must continue to state that **no approved open-source license is in force**.
