# Final release gate — v2.7.2

**Gate date:** 2026-10-24  
**Branch:** `stab/v2.7.2-enterprise-qa`  
**Includes:** `6fe5bae` and later (`e13f67f` Apache-2.0 + this gate’s integrity fixes)  
**Do not merge / tag / publish** until the maintainer explicitly approves.

---

## PASS / FAIL / NOT TESTED

| Area | Result | Notes |
| --- | --- | --- |
| Tip includes `6fe5bae` | **PASS** | Ancestor of current tip |
| Embedded `Version` = 2.7.2 | **PASS** | `internal/audit/model.go` |
| `check-release-docs.sh` | **PASS** | Unreleased tree OK |
| Tag↔commit↔artifact binding (tag push) | **PASS** | Builds `github.ref`; `--target` = checked-out HEAD |
| `workflow_dispatch` mismatch hardening | **PASS** | Checks out existing `inputs.tag`; refuses HEAD≠tag SHA; `--target` = `git rev-parse HEAD` (not dispatch branch tip) |
| Release notes publishable | **FAIL** (process) | `docs/releases/v2.7.2.md` still has **UNRELEASED DRAFT** banner — workflow correctly refuses publish until removed |
| Legacy Go 1.20.14 pinned SHA-256 | **PASS** | Official digests; cache re-verified; corrupt archive rejected |
| Legacy EXE rebuild this host | **PASS** | PE32+ legacy EXE built after verified download |
| Modern Go for standard builds | **PASS** | `build-release.sh` / CI `go-version: 1.27.3` unchanged |
| CVE-2026-109618/109619 thresholds | **PASS** | 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; matches php.net 21 Oct 2026 |
| CVE-2026-115560 informational | **PASS** | No invented fixes; php.net 23 Oct still mitigation-only |
| False “safe” / runtime uncertainty | **PASS** | Prior QA + unit tests retained |
| HTML examples (7) hierarchy/a11y static | **PASS** | Next steps before optional IR |
| Console/HTML/CSV/status consistency | **PASS** | Unit/integration; no new drift found |
| PSADT/GPO/Intune PowerShell static | **PASS** | Brace balance; no PS7-only `?.`/`??` |
| `pwsh` / WinPS live parse | **NOT TESTED** | No Windows/`pwsh` on agent host |
| Exit 0/1/2 + stale report guard | **PASS** | Code review + PSADT contract |
| Live Intune / GPO / 2012 R2 fleet | **NOT TESTED** | Field required |
| Apache-2.0 `LICENSE` | **PASS** | `LICENSE.proposed` removed |
| Windows Authenticode | **FAIL** (public Win) | Unsigned; SHA256SUMS OK |
| Secrets in tree | **PASS** | No token/key patterns found |
| GHA permissions / Go pin | **PASS** | Default `contents: read`; publish `write`; `setup-go` 1.27.3 pinned |
| `go test ./...` / vet / race (audit+cmd) | **PASS** | This tip |

---

## Blockers

### Publishing v2.7.2 for **controlled use**
1. **Maintainer explicit GO** (no auto tag/publish).  
2. Remove **UNRELEASED DRAFT** language from `docs/releases/v2.7.2.md` immediately before tag.  
3. Tag the **exact reviewed tip** (prefer `git tag v2.7.2 <sha>` then push tag — preferred over dispatch). If using `workflow_dispatch`, create the tag first; workflow now builds that tag only.  
4. CI green on the commit you tag.

### **Unrestricted public** distribution (esp. anonymous Windows download)
1. **Authenticode** still recommended (SmartScreen / enterprise allowlisting).  
2. Field pilots for Intune/GPO/2012 R2 as needed for your audience.  
3. License is **no longer** a blocker (Apache-2.0).

### Optional **v2.8.0**
- Authenticode in release workflow  
- RPM inventory (or sustained disclosure)  
- Broader field-validated deployment packs  

---

## Recommended publish procedure (when you approve)

```bash
# On reviewed tip after draft banner removed and CI green:
git tag -a v2.7.2 -m "PHP2Shell v2.7.2"
git push origin v2.7.2
# Official workflow builds from the tagged commit and refuses draft notes / version mismatch.
```

**Verdict:** Technical gate **CONDITIONAL GO** for controlled v2.7.2 after draft-notes cleanup + your GO.  
**Unrestricted public Windows:** **CONDITIONAL** — license OK; signing still the main remaining trust gap.
