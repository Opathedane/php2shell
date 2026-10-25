# Final distribution readiness — PHP2Shell 2.7.2 line

**Date:** 24 Oct 2026  
**Branch:** `stab/v2.7.2-enterprise-qa`  
**Base QA commit:** `12b6777` · **This docs/contract pass:** see `git log -1` after commit  
**Do not merge / tag / publish without explicit maintainer approval.**

---

## 1. Current functionality and readiness

PHP2Shell is a focused **PHP inventory + upstream patch assessment** tool with optional IR/WAF. Primary user outcome: whether observed PHP may need updating for CVE-2026-109618 / CVE-2026-109619, with conservative CVE-2026-115560 config review.

| Capability | Ready for pilots? |
| --- | --- |
| Patch assessment vs php.net | Yes |
| Console + HTML for ordinary admins | Yes (post-QA) |
| Exit / status JSON automation | Yes |
| Intune/GPO/PSADT **documentation** | Yes (field pilot still required) |
| Unrestricted public redistribution | **Conditional** — Apache-2.0 in force; Authenticode still recommended |

---

## 2. Confirmed bugs and implemented fixes

Preserved from prior QA (`12b6777` / `ddc9f89`): glued RC rejection, 115560 sample/primary fix, advisory freshness, console/HTML usability, WAF incomplete coverage, RuleID casings, status JSON fallbacks.

**This pass (docs/contract):**

- Interactive README Quick Start **without** `--quiet`
- [UNDERSTANDING-REPORTS.md](UNDERSTANDING-REPORTS.md)
- [deployment/INTUNE.md](deployment/INTUNE.md) — clarifies Win32 ≠ Server management
- [deployment/GPO.md](deployment/GPO.md)
- [deployment/REPORT-COLLECTION.md](deployment/REPORT-COLLECTION.md)
- [deployment/DISTRIBUTION-SIGNING.md](deployment/DISTRIBUTION-SIGNING.md)
- PSADT reference: **preserves scanner exit code** by default; stale HTML guard; `-NormalizeSuccessExit` opt-in
- Licensing resolved: Apache-2.0 (`LICENSE`)

---

## 3. Vulnerability assessment accuracy

| Check | Result |
| --- | --- |
| Upstream fixes 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 | Confirmed vs php.net 24 Oct 2026 |
| Newer critical advisory since 23 Oct? | **None** on php.net archive |
| 115560 invented fixed versions? | **No** |
| Vendor backport auto-green? | **No** (verification language only) |
| RC / glued RC | `PRERELEASE_NOT_APPROVED` |
| Successful scan ≠ secure host | Disclaimed in console, HTML, docs |

---

## 4–5. Console and HTML usability

| Surface | Status |
| --- | --- |
| Console | Human labels; thresholds; lifecycle; DFIR phases only when used |
| HTML | Patch-first cards; IR optional; examples in `testdata/examples/v2.7.2-qa/` |
| Visual review | Text extraction of seven synthetic reports — hierarchy matches intent (file:// browser automation blocked in agent; open HTMLs locally for pixel review) |

---

## 6. README and documentation completeness

README is the entry point with documentation map, Quick Start (interactive), feature overview, limitations, enterprise links. CLI flags cross-checked against `php2shell help` (24 Oct 2026 tree).

---

## 7–9. Intune / GPO / PSADT / collection

| Deliverable | Status |
| --- | --- |
| INTUNE.md | Written; **Win32 client** scope explicit; Server → GPO |
| GPO.md | Startup + Scheduled Task patterns; example scripts marked untested |
| PSADT reference | Exit code preserved; collection ≠ upload |
| REPORT-COLLECTION.md | Validation, SMB example, multi-tenant, retention |

**Field-unverified:** real Intune tenant, domain GPO lab, SYSTEM SMB ACL designs.

---

## 10. Security and distribution blockers (P0)

| Issue | Classification | Notes |
| --- | --- | --- |
| Approved `LICENSE` | **PASS** | Apache-2.0 |
| Unsigned Windows EXEs | **P0** for public Win download | SHA256 OK for pilots; signing guide written |
| RPM package DB | **P1** | Documented; not silent “no PHP”; postpone reader |
| 2012 R2 / Intune full pilot | **P1** | Legacy build exists; one prior customer run ≠ full matrix |

---

## 11. Actual test results (this pass)

```text
go test ./... -count=1
go vet ./...
go test ./internal/audit/ ./cmd/php2shell/ -race -count=1
bash scripts/check-release-docs.sh
go test ./internal/audit/ -run 'OfficialPHP2Shell|CVE115560|WAFAllowlisted|PersistExecution'
```

(See commit CI / local log — must be green before approval.)

PowerShell: reference script syntax not executed on Windows in this environment — **unverified on Windows host**; review with `PSScriptAnalyzer` / dry-run in pilot.

Legacy artifact: `bash scripts/build-windows-legacy.sh` previously succeeded on this line; re-run before release tag.

---

## 12. Remaining field-testing checklist

1. Win10/11 Intune Win32 install + scheduled scan + collect HTML/CSV/status  
2. Domain GPO scheduled task on Server 2016/2019/2022  
3. Server 2012 R2 legacy EXE under SYSTEM + report collection  
4. RHEL/Rocky host: confirm binary discovery + clear RPM limitation messaging  
5. SmartScreen behavior once signing is enabled  
6. ~~Maintainer license approval~~ — done (Apache-2.0)

---

## 13. Recommended release version

| Option | Recommendation |
| --- | --- |
| **v2.7.2** | **Preferred for this milestone** — advisory 115560 + correctness/UX/docs/stabilization; no new major detection surface |
| **v2.8.0** | Reserve for **after** remaining public gates (Windows signing) and/or RPM inventory — market as “public distribution” release |

Do **not** bump to 2.8.0 in-tree until those gates are intentionally scoped.

---

## 14. Final GO / CONDITIONAL GO / NO-GO

| Audience | Verdict |
| --- | --- |
| Controlled enterprise pilots (SHA256, internal catalog) | **CONDITIONAL GO** after CI green on tip |
| Unrestricted public GitHub distribution | **CONDITIONAL GO** — license OK; Authenticode recommended; field pilots |
| Tag/publish now | **NO-GO** — await maintainer approval + CI |

### Outstanding by priority

- **P0:** (for public Win) signing; CI green on final tip  
- **P1:** RPM reader or sustained clear messaging; live Intune/GPO/2012R2 pilots; fleet CSV 115560 column  
- **P2:** Longer binary alias hash; broader HTML polish; Trusted Signing automation
