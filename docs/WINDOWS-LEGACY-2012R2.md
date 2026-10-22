# Windows Server 2012 R2 compatibility (legacy build)

**Status:** implemented in-tree; **field verification on a real Windows Server 2012 R2 x64 host is required before treating this as ship-ready.** Compilation success is not runtime proof.

## Why a separate artifact exists

| Item | Detail |
| --- | --- |
| Primary Windows build | `php2shell-windows-amd64.exe` — current release Go toolchain (CI uses Go **1.27.x**) |
| Go OS floor (1.21+) | **Windows 10** or **Windows Server 2016** or newer ([Go minimum requirements](https://go.dev/wiki/MinimumRequirements); announced in Go 1.20 notes) |
| Windows Server 2012 R2 | NT 6.3 — **not supported** by Go 1.21+ runtimes |
| Last Go that runs on 2012 R2 | **Go 1.20.x** (final patch: **1.20.14**) |
| Legacy artifact | `php2shell-windows-legacy-amd64.exe` / `.zip` |

PHP2Shell does **not** downgrade the primary toolchain. The same application source is linked twice:

1. **standard** — modern Go, modern Windows/Linux/macOS  
2. **legacy** — Go **1.20.14**, `BuildFlavor=legacy`, Windows amd64 only  

Build: `bash scripts/build-windows-legacy.sh` (also invoked from `scripts/build-release.sh`).

## Security implications of Go 1.20 (unsupported compiler)

Go 1.20 left upstream support when Go 1.22 shipped (early 2024). Using it for the legacy Windows binary means:

- **No further Go runtime/compiler security fixes** from upstream for that toolchain.
- The **application** code still tracks current PHP2Shell releases (detections, CLI, HTML/CSV, exit codes), but the **runtime** (scheduler, crypto stdlib used by TLS for optional rules download, etc.) is frozen at 1.20.14.
- Prefer **standard** builds wherever the OS allows. Treat legacy as an **engagement exception** for 2012 R2 (often under Microsoft ESU), not a general Windows SKU.
- Binaries remain **unsigned**; SmartScreen / WDAC / AppLocker policies still apply.
- Optional `--update-rules` HTTPS uses the Go 1.20 TLS stack on legacy hosts — pin reviewed rule URLs and trusted keys; prefer offline `--rules` when possible.

Document this risk in engagement notes when deploying the legacy EXE via PSAppDeployToolkit or similar.

## Functional parity and intentional differences

**Preserved (same source tree):** scan/doctor/rollup/rules CLI, investigation inputs, HTML+CSV pair semantics, exit codes `0`/`1`/`2`, IIS/access-log/WAF paths available in this release line.

**Differences:**

| Topic | Standard | Legacy |
| --- | --- | --- |
| `php2shell version` | `… (standard)` | `… (legacy)` |
| Supported Windows | Win10 / Server 2016+ | Server **2012 / 2012 R2** (product floor 6.2+); not marketed for Win7 |
| Go toolchain | Current release Go | Go **1.20.14** only |
| OS gate | Refuses NT &lt; 10 with actionable error naming the legacy EXE | Refuses hosts older than Server 2012; warns if run on Win10+ |
| Doctor | Points 2012 R2 operators to legacy EXE | States Go 1.20 EOS + prefer standard on modern OS |

No separate “reduced detection” mode: limitations are OS/toolchain, not a stripped feature set. If a future language feature requires Go &gt; 1.20, either keep the legacy tree on a compatibility subset or retire 2012 R2 support explicitly.

## Compatibility errors (actionable)

Running the **standard** EXE on Server 2012 R2 exits **1** before scan:

```text
ERROR: this standard PHP2Shell build cannot run on Windows 6.3 …
On Windows Server 2012 R2 x64, download and run php2shell-windows-legacy-amd64.exe
```

`version` / `help` still work so operators can identify the artifact.

## PSAppDeployToolkit

On 2012 R2 application collections, deploy **`php2shell-windows-legacy-amd64.exe`** (not the standard amd64 EXE). Example fragment:

See also [deploy/PSADT-PHP2Shell-Reference.ps1](../deploy/PSADT-PHP2Shell-Reference.ps1) and [EXIT-CODES-AND-DEPLOYMENT.md](EXIT-CODES-AND-DEPLOYMENT.md) (treat exit **0** and **2** as upload-eligible).

```powershell
# Deploy-Application.ps1 (illustrative)
$Php2ShellExe = Join-Path $dirFiles 'php2shell-windows-legacy-amd64.exe'
Execute-Process -Path $Php2ShellExe -Parameters 'scan --quiet --output-dir C:\ProgramData\PHP2Shell\Reports' -WindowStyle Hidden
# SuccessCodes for report collection should include 0 and 2 (or use --accept-incomplete).
```

Keep reports under the engagement boundary. Do not substitute the standard EXE on 2012 R2 — it will fail the OS gate (or fail to start under an incompatible Go runtime).

## Field verification checklist (required)

Run on a **real** Windows Server 2012 R2 x64 image (not only CI `windows-latest`):

1. Copy `php2shell-windows-legacy-amd64.exe` from a release/PR build; confirm `.\php2shell-windows-legacy-amd64.exe version` → `legacy`.
2. `.\php2shell-windows-legacy-amd64.exe doctor` — exits 0; notes Go 1.20 EOS.
3. `.\php2shell-windows-legacy-amd64.exe scan --quiet --output-dir C:\ProgramData\PHP2Shell\Reports` — HTML+CSV pair written; exit 0 or 2 per coverage (not 1 for OS reasons).
4. Optional: IIS access-log / `--webroot` smoke matching consultant docs.
5. Confirm standard `php2shell-windows-amd64.exe` on the same host prints the actionable legacy redirect (or fails to start) — do not use it for production scans on 2012 R2.
6. Record host build number, PHP2Shell version, and pass/fail in the engagement log.

Until this checklist is signed off, treat 2012 R2 support as **engineering-complete, field-unverified**.
