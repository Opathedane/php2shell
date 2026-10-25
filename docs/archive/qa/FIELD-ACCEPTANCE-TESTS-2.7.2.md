# Field acceptance tests — v2.7.2

Use this checklist on **real Windows / domain / Intune** environments. Do not mark simulated or documentation-only work as production validation.

**Record for each run:** date, operator, host OS build, EXE name + SHA256, commit/tag, exit code, report paths, pass/fail notes.

---

## A. Manual Windows scanning

**Environment:** Windows 10/11 or Server 2016+ (64-bit). Standard EXE.

1. Verify SHA256 of `php2shell-windows-amd64.exe` against `SHA256SUMS`.
2. Run `.\php2shell-windows-amd64.exe doctor` (interactive — expect readable output).
3. Run `.\php2shell-windows-amd64.exe scan --output-dir $env:ProgramData\PHP2Shell\Reports` **without** `--quiet`.
4. Confirm console shows: versions found (or not), whether update/verification is needed, missing evidence, next steps, completion, report path.
5. Open the newest HTML: Patch assessment → installs → next steps answer “what / update? / do what / how reliable?”
6. Confirm sibling `.csv` and `.status.json` exist; `execution_status` matches exit code.
7. Expect exit **0** or **2** with reports; **1** only on fatal failure.

| Distinguishes | Application installed ≠ scan ran ≠ scan complete ≠ reports collected |

---

## B. Windows Server 2012 R2 (legacy)

**Environment:** real 2012 R2. Use **legacy** EXE only.

1. Confirm OS is 6.3; refuse to use the modern EXE.
2. Verify SHA256 of `php2shell-windows-legacy-amd64.exe`.
3. Run `doctor` then `scan --output-dir ...` as above.
4. Confirm HTML/CSV/status written.
5. Document Go **1.20.14** toolchain security limitations (see [WINDOWS-LEGACY-2012R2.md](../../WINDOWS-LEGACY-2012R2.md)).
6. One prior smoke success ≠ full validation — repeat on ≥2 hosts if possible; include a host with PHP and one without.

---

## C. PSADT deployment with report collection

1. Stage standard + legacy EXEs beside [PSADT-PHP2Shell-Reference.ps1](../../../deploy/PSADT-PHP2Shell-Reference.ps1).
2. Run under SYSTEM (or deployment account) unattended.
3. Confirm wrapper exit equals scanner exit (**0 / 1 / 2**) unless `-NormalizeSuccessExit`.
4. On exit 0/2: HTML+CSV present, HTML newer than run start, collection eligible.
5. On exit 1: do **not** upload prior-run HTML as this execution.
6. Customer upload step: success of copy ≠ scan success — log both separately ([REPORT-COLLECTION.md](../../deployment/REPORT-COLLECTION.md)).

---

## D. Intune (supported Windows **clients** only)

**Do not claim Win32 app deployment supports Windows Server.**

1. Package `.intunewin` per [INTUNE.md](../../deployment/INTUNE.md).
2. Install command uses 64-bit PowerShell; runs as SYSTEM.
3. Detection rule = binary present (or catalog) — **not** “scan succeeded”.
4. Requirement rules fit OS SKUs you actually target.
5. After assignment: confirm reports under `ProgramData\PHP2Shell\Reports` with unique names.
6. Map Intune app success vs script exit 2 (incomplete) vs missing reports.

---

## E. GPO scheduled-task execution

1. Stage binaries with Domain Computers **Read & execute** only on the share.
2. Prefer GPP Scheduled Task (Pattern B) over startup for repeats ([GPO.md](../../deployment/GPO.md)).
3. Task runs as SYSTEM; unique report filenames; lock/skip if concurrent.
4. Verify with `gpresult /h`, Task Scheduler history, and `schtasks /Query`.
5. Confirm offline hosts still produce local reports when next online.

---

## F. Incomplete scans and exit code 2

1. Force incompleteness (short `--timeout`, denied path, or known TRUNCATED coverage).
2. Expect exit **2**, HTML+CSV present, status `scan_incomplete` / `COMPLETED_INCOMPLETE`.
3. Confirm collection still picks up reports; ticket/workflow does **not** close as “cleared”.

---

## G. Report generation and central collection failures

| Case | Expect |
| --- | --- |
| Output directory not writable | Exit 1 or OUTPUT_WRITE_FAILED handling; no false success |
| Status JSON missing but HTML+CSV present | Warn; still collect reports; treat as packaging defect |
| Stale HTML from prior run | Wrapper refuses; no upload as current |
| SMB share unreachable | Local buffer retained; retry later; do not delete local good reports |
| Upload fails after good scan | Record upload failure separately; scan remains success/incomplete |

---

## Evidence classes (for the acceptance checklist)

| Class | Meaning |
| --- | --- |
| **Tested** | Automated unit/integration or verified on this agent host |
| **Simulated** | Synthetic HTML/examples or static script parse |
| **Field required** | Needs customer/lab Windows, Intune, GPO, or 2012 R2 |
