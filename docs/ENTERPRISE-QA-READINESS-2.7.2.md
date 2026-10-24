# PHP2Shell enterprise QA & public distribution readiness

**Baseline:** 24 Oct 2026 · Branch: `stab/v2.7.2-enterprise-qa`  
**Do not tag/publish without explicit maintainer approval.**

## 1. Executive readiness

PHP2Shell’s primary job — upstream patch assessment for CVE-2026-109618 / CVE-2026-109619, with conservative CVE-2026-115560 config review — is **technically sound and now clearer for ordinary administrators**. Remaining blockers for *broad public distribution* are **licensing**, **unsigned binaries**, **RPM inventory gap**, and **field validation** (especially Windows Server 2012 R2).

| Area | Verdict |
| --- | --- |
| Patch assessment accuracy vs php.net (24 Oct 2026) | **GO** — thresholds 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; 115560 still no fixed versions |
| Console / HTML understandability | **GO** after this branch (P1) |
| Execution integrity (exit / status JSON / WAF) | **GO** (prior + this branch regression) |
| Intune/PSADT contract | **CONDITIONAL GO** — reference script ready; live tenant pilot open |
| Supply chain / license | **NO-GO for redistribution** until approved `LICENSE` + signing policy |
| Overall broad distribution | **CONDITIONAL GO** for controlled enterprise pilots; **NO-GO** for unrestricted public redistribution until license + CI green + field notes |

## 2. PHP.net / industry gap analysis (24 Oct 2026)

| Source | Finding |
| --- | --- |
| php.net archive | No newer advisory than 23 Oct 2026 informational 115560; 21 Oct critical 109618/109619 unchanged |
| supported-versions.php | 8.2 security-only → 31 Dec 2026; 8.3 security → 2027; 8.4 active → 2026 / security 2028; 8.5 active → 2027 |
| Rapid7 / Plesk / distro advisories | Vendors may backport under older version strings — PHP2Shell keeps `VENDOR` verification language; no automatic “vendor-patched” green path (correct) |
| Velociraptor PHPInventory | We observe packages/binaries/config/process hints; we still **do not** attest HTTP-serving runtime (intentional) |
| RPM | Still **not** inventoried (zero-deps; no rpm CLI). Coverage text improved |

**Embedded intelligence freshness:** `AdvisoryDate=2026-10-21`, `AdvisoryRulesReviewedUTC=2026-10-24`, doctor/banner expose assessed CVEs and that this is **not** a live feed.

## 3. Prioritized findings

### P0 — fixed on this branch (or already fixed in v2.7.2 merge)

| ID | Finding | Fix |
| --- | --- | --- |
| P0-1 | WAF truncated/oversized/partial marked complete | `TRUNCATED` / `UNAVAILABLE` + tests |
| P0-2 | `RuleID`/`ruleId`/`rule_id` miss | Casing merge + table tests |
| P0-3 | Status JSON failure only on stderr | Fallbacks + `status_json_written` + on-disk `OUTPUT_WRITE_FAILED` |
| P0-4 | 115560 sample handlers poison primary Off | Mitigation demotion only when Off is sample-only |
| P0-5 | Glued RC `8.6.0RC3` not prerelease | Normalize → `PRERELEASE_NOT_APPROVED` |
| P0-6 | Bare-scan 115560 noise / host php.ini test pollution | Emission gate + hermetic fixtures |

### P1 — fixed on this branch

| ID | Finding | Fix |
| --- | --- | --- |
| P1-1 | Console raw enums / unrequested DFIR phases | Human labels; phases only when work runs |
| P1-2 | HTML IR cards before patch outcome | Executive: patch → installs → runtime → gaps; IR optional |
| P1-3 | “Confirmed host evidence versions” overclaim | Softened wording |
| P1-4 | Lifecycle awareness | Informational column / console notes (separate from CVE status) |
| P1-5 | PSADT contract incomplete | Expanded reference + EXIT-CODES |
| P1-6 | README DFIR-first | Ordinary-admin README |
| P1-7 | RPM gap invisible | Stronger `packages` NOT_SUPPORTED detail + console note |

### P2 / postponed

| ID | Item | Why wait |
| --- | --- | --- |
| P2-1 | Read-only RPM DB inventory | Needs careful zero-dep design or approved dependency |
| P2-2 | Fleet CSV columns for 115560 | Useful; not blocking pilot |
| P2-3 | Authenticode signing | Policy + cert ownership |
| P2-4 | Approved LICENSE | Maintainer/employer authorization required — **do not invent** |
| P2-5 | Full-file alias hash | Low probability false-merge via 64KiB prefix |
| P2-6 | Live Intune tenant pilot | Field checklist below |

## 4. Exact fixes implemented (this initiative)

- `internal/audit/patch.go` — glued RC normalize; `AdvisoryRulesReviewedUTC`
- `internal/audit/advisory_session_upload.go` — sample/primary mitigation correctness
- `internal/console/console.go` — administrator-facing summary
- `cmd/php2shell/main.go` — gated phases; doctor freshness/CVE list
- `internal/audit/report.go` / `report_view.go` — HTML hierarchy, lifecycle, human advisory labels
- `deploy/PSADT-PHP2Shell-Reference.ps1` + `docs/EXIT-CODES-AND-DEPLOYMENT.md` (prior commit)
- `README.md` — first-time admin path
- Example reports: `testdata/examples/v2.7.2-qa/*.html`

## 5. Test results (commands)

```text
go test ./... -count=1
go vet ./...
go test ./internal/audit/ ./cmd/php2shell/ -race -count=1
bash scripts/check-release-docs.sh
PHP2SHELL_GEN_EXAMPLES=1 go test ./internal/audit/ -run TestGenerateExampleReports
```

All green at commit time on this branch (darwin/arm64 developer host).

## 6. Console before / after (illustrative)

**Before:** raw `VulnerabilityStatus` enums; always announced “Offline WAF event investigation” even when unused.

**After (sample):**

```text
PHP2Shell Assessment 2.7.2
Host: …  OS: darwin/arm64
· Upstream fix thresholds: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 …
· Advisory rules reviewed: 2026-10-24 …

==> Host and PHP inventory
==> Patch assessment
…

Scan summary
  Patch assessment:  …
  Serving runtime:   Not verified — …
  Additional advisories:
    - CVE-2026-115560: Manual verification required
```

## 7. HTML before / after

**Before:** eight executive cards including exploitation/compromise/IOC on every inventory scan; “Confirmed host evidence versions”.

**After:** four primary cards (Patch assessment, PHP installations, Active web runtime, What could not be verified); optional IR strip only when investigation requested or findings exist; examples under `testdata/examples/v2.7.2-qa/`.

## 8. Intune / PSADT

Contract documented in script header + EXIT-CODES. Validates exit 0/1/2, HTML+CSV presence, status JSON / `failed-*` fallbacks, incomplete, stale naming. Customer upload remains external. **Not** exercised under SYSTEM on real Intune in this audit.

## 9. Platform / field matrix

| Platform | Automated | Field |
| --- | --- | --- |
| Linux dpkg/apk | Unit + CI | Recommended pilot |
| Linux RPM | Coverage messaging only | **Pilot required** — binary discovery only |
| Windows 10/11/Server 2016+ | Cross-build + CI windows-latest | Pilot |
| Windows Server 2012 R2 legacy EXE | Cross-build (Go 1.20.14) | **Runtime unverified** |
| IIS / Apache / nginx+FPM | Unit/fixtures | Pilot on customer images |

## 10. Security & distribution risks

| Risk | Status |
| --- | --- |
| Only `LICENSE.proposed` | **Blocker** for external redistribution |
| Unsigned release assets | Documented; signing strategy needed |
| Legacy Go 1.20.14 | Documented EOS risk |
| SHA256SUMS in release workflow | Present |
| GH Actions contents permissions | Least-privilege pattern in release.yml |
| No PHP binary execution | Preserved |
| HTML escaping | Preserved CSP + EscapeString |

## 11. Release gate recommendation

**CONDITIONAL GO** for:

- Merging this stabilization branch after CI green
- Controlled enterprise pilots with SHA256 verification

**NO-GO** for:

- Tagging/publishing v2.7.2 as a *broad public* distribution until: approved LICENSE, CI green on this tip, release notes draft banner removed, and maintainer explicit GO
- Claiming RPM package parity or 2012 R2 field certification

Await maintainer approval before merge/tag/publish.
