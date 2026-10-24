# Release Acceptance Checklist — v2.7.2 (stabilization)

**Reviewed commit (local tip at acceptance writing):** see §13 after commit.  
**Feature freeze:** no new PHP discovery, WAF providers, DFIR, or advisory features.  
**Version plan:** ship technical+docs as **v2.7.2**; reserve **v2.8.0** for public distribution after LICENSE + Authenticode + field pilots.

Do **not** merge, tag, or publish until the maintainer explicitly approves.

Legend: **PASS** · **FAIL** · **NOT TESTED** (with environment note)

---

## 1. Current functionality and readiness

| Item | Result | Notes |
| --- | --- | --- |
| Primary CVE assessment (109618/109619) | **PASS** | Upstream thresholds 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 |
| CVE-2026-115560 informational, no invented fixes | **PASS** | Conservative config assessment |
| Exit 0 / 1 / 2 + status JSON contract | **PASS** | Unit + prior QA |
| Console human summary | **PASS** | Prior QA `12b6777` |
| HTML patch-first executive summary | **PASS** | Hierarchy fix: next steps before optional IR |
| README first-time onboarding (no `--quiet` in primary Quick Start) | **PASS** | |
| Intune / GPO / PSADT / collection docs | **PASS** | Reference designs; field pilots still required |
| Approved redistribution LICENSE | **FAIL** (P0 blocker for public) | `LICENSE.proposed` only — [LICENSING-DECISION.md](LICENSING-DECISION.md) |
| Windows Authenticode | **FAIL** (P0 for broad Win public) | SHA256 published; [AUTHENTICODE-IMPLEMENTATION.md](deployment/AUTHENTICODE-IMPLEMENTATION.md) |
| RPM package inventory | **NOT TESTED** / disclosed | Binary discovery still runs; not silent “no PHP” |

**Stabilization readiness (pilots):** **CONDITIONAL GO**  
**Unrestricted public distribution:** **NO-GO** until LICENSE (+ recommended signing)

---

## 2. Confirmed bugs / fixes in this acceptance pass

| Fix | Result |
| --- | --- |
| HTML: optional IR cards appeared before Recommended next steps | **PASS** (fixed) |
| Primary IR card text exposed `FPM_EXIT_SOFTWARE` jargon | **PASS** (humanized) |
| Example reports regenerated under `testdata/examples/v2.7.2-qa/` | **PASS** |

---

## 3. Vulnerability assessment accuracy

| Scenario | Result | Evidence class |
| --- | --- | --- |
| Below upstream threshold | **PASS** | Unit + synthetic HTML `01` |
| At/above upstream (runtime unverified) | **PASS** | Unit + `02` |
| Vendor / EOL verification language | **PASS** | Unit + `03` |
| No PHP / inconclusive inventory | **PASS** | Unit + `04` |
| Multiple installations | **PASS** | Unit + `05` |
| Incomplete coverage → exit 2 semantics | **PASS** | Unit + docs |
| Prerelease / glued RC not auto-approved | **PASS** | Prior QA |
| php.net advisory freshness display | **PASS** | Rules reviewed date in HTML |
| Live production host verification | **NOT TESTED** | Customer field |

---

## 4. Console usability

| Check | Result |
| --- | --- |
| First-time admin path documented without `--quiet` | **PASS** |
| `--quiet` still documented for automation | **PASS** |
| Live Windows console walkthrough | **NOT TESTED** | Needs Windows host |

---

## 5. HTML report usability

| Check | Result |
| --- | --- |
| First screen: patch / installs / runtime / gaps / next steps | **PASS** |
| IR secondary (after next steps) | **PASS** |
| Offline CSP (`default-src 'none'; style-src 'unsafe-inline'`) | **PASS** |
| `lang`, viewport, single `h1`, no missing alts | **PASS** (static) |
| Pixel browser review of all 7 examples | **PASS** (structure + layout probe); full-file `file://` blocked in agent browser — open `testdata/examples/v2.7.2-qa/*.html` locally to confirm pixels |
| Responsive / print CSS present | **PASS** |

---

## 6. README and documentation

| Check | Result |
| --- | --- |
| Relative doc links in primary docs | **PASS** (54 OK, 0 missing) |
| Documented scan flags match `php2shell` help | **PASS** |
| Release artifact names + SHA256 instructions | **PASS** |
| `scripts/check-release-docs.sh` | **PASS** |

---

## 7. Intune

| Check | Result |
| --- | --- |
| Guide exists; Win32 ≠ Server stated | **PASS** |
| Live Intune tenant packaging / detection rules | **NOT TESTED** | Customer tenant |

---

## 8. GPO

| Check | Result |
| --- | --- |
| Startup + scheduled-task patterns documented | **PASS** |
| Example PowerShell brace/PS5.1-safe static check | **PASS** |
| Live domain GPO + `gpresult` | **NOT TESTED** | Domain lab |

---

## 9. PSADT and collection

| Check | Result |
| --- | --- |
| Reference script preserves scanner exit; stale guard | **PASS** (code review) |
| PowerShell AST/`pwsh` parse on this Mac agent | **NOT TESTED** | `pwsh` fails to start (runtime); static brace check **PASS** |
| Live PSADT + SMB collection | **NOT TESTED** | Customer |

---

## 10. Security and distribution blockers

| Item | Severity | Result |
| --- | --- | --- |
| Approved LICENSE | **P0** public | **FAIL** until maintainer decision |
| Authenticode | **P0** broad Windows public / **P1** pilots | **FAIL** (plan ready) |
| SHA256SUMS process | — | **PASS** (documented + release workflow) |
| Unsigned SmartScreen | — | Disclosed |
| Legacy Go 1.20.14 2012 R2 build limits | — | Disclosed |
| Draft PR pushed | — | See §14 |

---

## 11. Automated tests (this machine)

| Suite | Result |
| --- | --- |
| `go test ./internal/audit/ ./cmd/php2shell/` | **PASS** |
| `go vet ./...` | **PASS** (prior full `./...` on tip; re-run on final commit) |
| Race tests | **PASS** (prior acceptance) |
| `scripts/check-release-docs.sh` | **PASS** |
| PowerShell static syntax (PSADT + GPO/Intune blocks) | **PASS** |
| `pwsh` / Windows PowerShell 5.1 execution | **NOT TESTED** |
| Live Intune / GPO / 2012 R2 / collection | **NOT TESTED** |

---

## 12. Field-testing required (customer / lab)

See [FIELD-ACCEPTANCE-TESTS-2.7.2.md](FIELD-ACCEPTANCE-TESTS-2.7.2.md).

| Scenario | Status |
| --- | --- |
| Manual Windows scan | **NOT TESTED** |
| Server 2012 R2 legacy EXE | **NOT TESTED** (prior single customer smoke ≠ full pilot) |
| PSADT + collection | **NOT TESTED** |
| Intune Win32 (supported clients only) | **NOT TESTED** |
| GPO scheduled task | **NOT TESTED** |
| Incomplete scan exit 2 | **NOT TESTED** on Windows fleet |
| Collection failure paths | **NOT TESTED** |

---

## 13. Release artifacts from reviewed commit

| Gate | Requirement |
| --- | --- |
| Tag target | Exact reviewed commit SHA (Draft PR head after push) |
| Workflow | `.github/workflows/release.yml` builds from `${{ github.sha }}` / `--target "${GITHUB_SHA}"` |
| Version string | Embedded `Version` must equal tag without `v` |
| Notes | `docs/releases/v2.7.2.md` must drop draft language before tag |
| Do not | Retag, overwrite release assets, or ship unreviewed commits |

---

## 14. Push / Draft PR

| Step | Result |
| --- | --- |
| `git push origin stab/v2.7.2-enterprise-qa` | **FAIL** on agent host — no `gh`/HTTPS credentials (`Device not configured`) |
| Draft PR vs `main` | **NOT TESTED** — blocked on push |

**Maintainer one-liner (after `gh auth login`):**

```bash
git push -u origin stab/v2.7.2-enterprise-qa
gh pr create --draft --base main --head stab/v2.7.2-enterprise-qa \
  --title "stab/v2.7.2: enterprise QA + distribution readiness (do not merge yet)" \
  --body-file docs/pr-draft-v2.7.2-acceptance.md
```

---

## 15. GO / CONDITIONAL GO / NO-GO

| Audience | Verdict |
| --- | --- |
| Controlled enterprise pilots (SHA256 verified) | **CONDITIONAL GO** |
| Unrestricted public GitHub distribution | **NO-GO** — P0 LICENSE; recommended Authenticode |
| Merge / tag / publish now | **NO-GO** without explicit maintainer approval |

**Recommended tag when approved:** **v2.7.2** (stabilization).  
**Reserve v2.8.0** for public milestone after licensing, signing, and field acceptance.
