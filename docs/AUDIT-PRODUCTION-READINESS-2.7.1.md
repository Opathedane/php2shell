# PHP2Shell production-readiness audit (toward v2.7.1)

**Branch:** `feat/enterprise-production-readiness` (includes `feat/windows-2012r2-legacy`)  
**Version left at:** `2.7.1` (unreleased; no tag/publish)  
**Date:** 2026-10-22  

## A. Functionality status

| Area | Status |
| --- | --- |
| CLI scan/doctor/version/rollup/rules | **Works** |
| HTML + fleet CSV pair, no overwrite | **Works** |
| Execution status JSON + quiet stderr status | **Works** (this change) |
| Windows 10 / Server 2016+ standard EXE | **Expected** (CI windows-latest; not re-field-tested here) |
| Windows Server 2012 R2 legacy EXE | **Built** with Go 1.20.14; **runtime unverified** on real 2012 R2 |
| Linux inventory (dpkg/apk) | **Works**; RPM/pacman still **unsupported** (now `NOT_SUPPORTED`, not exit 2) |
| IIS inventory | **Works** when config readable; absent IIS = `NOT_APPLICABLE` (no longer exit 2) |
| Compromise investigation + WAF Cloudflare | **Works**; WAF alone ≠ possible-compromise (tests) |
| Assessment JSON scan output | **Removed/not written** by design (fleet CSV replaces); legacy rollup `--format json` remains |
| PSAppDeployToolkit in-repo package | **Reference only** (`deploy/PSADT-PHP2Shell-Reference.ps1`) |

## B. Confirmed bugs (fixed)

| Severity | Finding | Root cause | Resolution |
| --- | --- | --- | --- |
| P0 | Standard EXE will not start on Server 2012 R2 (“not a valid application…”) | Go ≥1.21 PE/runtime requires Win10/Server 2016+ | Legacy artifact via Go **1.20.14** + OS gate (`docs/WINDOWS-LEGACY-2012R2.md`) |
| P0 | PSADT treats exit 2 as failure after valid HTML/CSV | Exit 2 = incomplete coverage; common Windows IIS-absent and Linux no-dpkg paths used `UNAVAILABLE` → always incomplete | IIS absent → `NOT_APPLICABLE`; packages no dpkg/apk → `NOT_SUPPORTED`; deployment docs + `--accept-incomplete` + status JSON |
| P0 | Quiet deployments hide outcome | Summary suppressed under `--quiet` | Always emit stderr status line + `.status.json` |
| P1 | `--out SERVER.csv` confusion with `--output-dir` | Documented poorly; `--out` wins | Remap already existed; documented in EXIT-CODES guide |

## C. Implemented fixes (files)

- `internal/audit/buildinfo.go`, `compat*.go` — build flavor + Windows OS gate  
- `scripts/build-windows-legacy.sh`, release/CI/preview workflows — legacy artifact  
- `internal/audit/diagnostics.go` (+ tests) — status JSON, error IDs  
- `internal/audit/report.go` — `ScanIncomplete` + WAF/ACCESS_DENIED semantics  
- `internal/audit/windows_windows.go`, `host.go` — IIS/packages status fixes  
- `cmd/php2shell/main.go` — `--status-json`, `--accept-incomplete`, finishScan  
- `docs/WINDOWS-LEGACY-2012R2.md`, `EXIT-CODES-AND-DEPLOYMENT.md`, `deploy/PSADT-*.ps1`  
- CHANGELOG / INSTALL / README / v2.7.1 draft notes  

## D. Compatibility matrix

| Target | Artifact | Tested here | Notes |
| --- | --- | --- | --- |
| Windows 10+ / Server 2016+ amd64 | `php2shell-windows-amd64.exe` | Compile/CI path only | Primary Go toolchain |
| Windows Server 2012 R2 amd64 | `php2shell-windows-legacy-amd64.exe` | **Cross-compile only** | **Unverified** on real host |
| Linux amd64/arm64 | tar.gz | Unit/integration on darwin host + CI ubuntu | |
| macOS amd64/arm64 | darwin builds | Local darwin/arm64 | Convenience |

## E. Tests executed

```text
gofmt (touched packages)
go test ./...                          → PASS
go vet ./...                           → PASS
go test -race ./internal/audit/        → PASS
bash scripts/check-release-docs.sh     → OK (Version=2.7.1)
go test ./internal/audit/ -run 'WAF|Cloudflare' → PASS
Manual: scan --quiet --out …/SERVER.csv → exit 0, HTML+CSV+status.json, stderr status line
```

**Gaps:** no live Server 2012 R2 VM; no Intune tenant upload; no authenticode.

## F. Remaining risks

- Legacy Go **1.20.14** is end-of-support (TLS/runtime freeze) — engagement exception only.  
- Exit 2 still fires for **true** incomplete requested evidence; wrappers must allow 0+2 or use `--accept-incomplete`.  
- `--accept-incomplete` can hide coverage gaps from naïve monitors — status JSON still records `SCAN_INCOMPLETE`.  
- 2012 R2 compatibility **not** field-verified.

## G. Release recommendation

**CONDITIONAL GO** for merging to a release candidate branch after:

1. Real Server 2012 R2 field checklist signed off.  
2. One Intune/PSADT pilot confirming upload on exit 0 and 2.  
3. Human review of this PR.

**NO-GO** for tagging/publishing until (1) and draft language removed from `docs/releases/v2.7.1.md`.

## H. Backlog

| Priority | Item |
| --- | --- |
| P0 | Field-verify legacy EXE on Server 2012 R2 x64 |
| P0 | Pilot PSADT SuccessCodes = 0,2 (or `--accept-incomplete`) |
| P1 | RPM/pacman package readers |
| P1 | IIS long request-target parity / FrankenPHP parents |
| P2 | Additional WAF vendors with fixtures |
