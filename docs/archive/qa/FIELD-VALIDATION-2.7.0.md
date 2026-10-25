# Field validation guide — PHP2Shell v2.7.0

**Purpose:** Real-host validation of the v2.7.0 compromise-investigation features.  
**Latest public release:** [v2.7.0](https://github.com/Opathedane/php2shell/releases/tag/v2.7.0).  
**Do not fabricate completed field results.** Synthetic fixtures under `testdata/demos/` are for lab regression only (Scenario F documents expected outcomes for those fixtures; they do **not** replace Scenarios A–E).

Confirm authorization before collecting logs, EDR exports, or scanning production systems. Treat HTML/CSV reports as confidential engagement data.

---

## Obtain a v2.7.0 binary

Download from [GitHub Releases](https://github.com/Opathedane/php2shell/releases/tag/v2.7.0), or build from this tree:

```bash
go build -o php2shell ./cmd/php2shell
./php2shell version   # expect: php2shell 2.7.0 …
```

```powershell
go build -o php2shell-windows-amd64.exe .\cmd\php2shell
.\php2shell-windows-amd64.exe version
```

Optional: GitHub Actions → **Build standalone preview** (`workflow_dispatch`) → download unsigned `php2shell-native-unsigned-preview` artifact. **Not** a GitHub Release; **not** production-approved.

---

## Handling confidential reports

1. Write reports only to engagement-approved paths (`--output-dir` / `--out`).
2. Do not attach customer HTML/CSV, raw access/error logs, or EDR exports to public GitHub issues.
3. Redact hostnames/paths before any external discussion; prefer private maintainer channels.
4. Encrypt or access-control report folders per customer policy; delete when the engagement ends.
5. Never commit customer reports into this repository.

---

## Acceptance fields (record for every scenario)

| Field | What to record |
| --- | --- |
| PHP installations discovered | Count, versions, paths, confidence |
| Vulnerability assessment | Host / per-install patch status vs upstream thresholds |
| Exploitation-attempt assessment | `NOT_ASSESSED` / `NO_MATCHES_IN_SCOPE` / `SUSPECTED_ATTEMPTS_REVIEW` |
| Possible-compromise assessment | `NOT_ASSESSED` / `NO_MATCHES_IN_SCOPE` / `POSSIBLE_COMPROMISE_REVIEW` |
| Investigation coverage | `NOT_REQUESTED` / `ASSESSED_SCOPE_LIMITED` / `INCOMPLETE` / … |
| Findings and evidence confidence | Kinds + `suspected` / `unconfirmed`; note webroot-only low-confidence |
| False positives | Legitimate CMS, admin shells, deploy tools, routine OOM |
| Unexpected exclusions / missing evidence | Truncation, unsupported format, birth unavailable, rotation gaps |
| Scan duration and completeness | Wall time; exit `0` vs `2`; warnings |
| Expected vs actual | Pass / fail / needs analyst follow-up |

**Hard rule:** no observed indicators must **never** be reported or verbally described as proof of a clean host.

Pay special attention to:

- Weak **webroot-only** `POSSIBLE_COMPROMISE_REVIEW` (must stay Elevated / low-confidence, not EDR-strength)
- Ordinary legitimate parent→child process activity (e.g. admin shells)

---

## Scenario A — Normal production-like host (no known malicious activity)

**Goal:** Baseline discovery + IR with empty or benign inputs without overstating clearance.

### Windows

```powershell
$dir = 'C:\ProgramData\PHP2Shell\FieldValidation\A'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
.\php2shell-windows-amd64.exe doctor
.\php2shell-windows-amd64.exe scan `
  --quiet `
  --customer 'FieldValidation-A' `
  --output-dir $dir
```

### Linux

```bash
DIR="$HOME/.php2shell/field-validation/A"
mkdir -p "$DIR"
./php2shell version
./php2shell doctor
./php2shell scan \
  --quiet \
  --customer 'FieldValidation-A' \
  --output-dir "$DIR"
```

**Expected (typical):** installs/patch status as on host; exploitation/possible often `NOT_ASSESSED` if no IR inputs; coverage `NOT_REQUESTED`. Report must still say it is not a clearance.

---

## Scenario B — Multiple PHP installs (including older / previously vulnerable)

**Goal:** Multi-install retention and independent patch thresholds.

### Windows

```powershell
$dir = 'C:\ProgramData\PHP2Shell\FieldValidation\B'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
.\php2shell-windows-amd64.exe scan `
  --quiet `
  --deep-root 'C:\Temp\PHP' `
  --config-root 'D:\Apps\CustomPHP' `
  --customer 'FieldValidation-B' `
  --output-dir $dir
```

### Linux

```bash
DIR="$HOME/.php2shell/field-validation/B"
mkdir -p "$DIR"
./php2shell scan \
  --quiet \
  --deep-root /opt \
  --deep-root /usr/local \
  --customer 'FieldValidation-B' \
  --output-dir "$DIR"
```

**Expected:** multiple install cards/rows when present; older branches below upstream thresholds flagged independently; deep truncation → exit `2` / INCOMPLETE — not “no PHP.”

---

## Scenario C — Historical HTTP / error logs (window + coverage)

**Goal:** Investigation window, attempt status, incomplete coverage honesty.

Place authorized rotated logs under an engagement folder (examples below). Adjust paths and `--investigate-from` / `--investigate-to` to the customer window (default floor 2026-10-17 when investigating).

### Windows

```powershell
$dir = 'C:\ProgramData\PHP2Shell\FieldValidation\C'
$logs = 'C:\Engagement\Logs'   # authorized copies only
New-Item -ItemType Directory -Force -Path $dir | Out-Null
.\php2shell-windows-amd64.exe scan `
  --quiet `
  --access-log "$logs\W3SVC1\u_ex261018.log" `
  --error-log "$logs\php_errors.log" `
  --investigate-from 2026-10-17 `
  --investigate-to 2026-10-22 `
  --customer 'FieldValidation-C' `
  --output-dir $dir
```

### Linux

```bash
DIR="$HOME/.php2shell/field-validation/C"
LOGS="$HOME/engagement/logs"   # authorized copies only
mkdir -p "$DIR"
./php2shell scan \
  --quiet \
  --access-log "$LOGS/nginx/access.log" \
  --error-log "$LOGS/php8.3-fpm.log" \
  --investigate-from 2026-10-17 \
  --investigate-to 2026-10-22 \
  --customer 'FieldValidation-C' \
  --output-dir "$DIR"
```

**Expected:** exploitation status assessed when logs usable; long request-target described as URI length not body size; routine OOM alone ≠ compromise; missing/unreadable logs → INCOMPLETE / NOT_ASSESSED — not clean.

---

## Scenario D — Real authorized EDR / process telemetry

**Goal:** Format support + parent/child leads without admin FPs.

Use **customer-authorized offline exports** only (no live API). Prefer one format per run first, then combine.

### Windows (MDE and/or Sysmon)

```powershell
$dir = 'C:\ProgramData\PHP2Shell\FieldValidation\D'
$exp = 'C:\Engagement\EDR'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
.\php2shell-windows-amd64.exe scan `
  --quiet `
  --process-telemetry "$exp\DeviceProcessEvents.csv" `
  --process-telemetry "$exp\sysmon-eventid1.csv" `
  --investigate-from 2026-10-17 `
  --customer 'FieldValidation-D' `
  --output-dir $dir
```

### Linux (auditd and/or Elastic ECS JSONL)

```bash
DIR="$HOME/.php2shell/field-validation/D"
EXP="$HOME/engagement/edr"
mkdir -p "$DIR"
./php2shell scan \
  --quiet \
  --process-telemetry "$EXP/auditd-execve.log" \
  --process-telemetry "$EXP/ecs-process.jsonl" \
  --investigate-from 2026-10-17 \
  --customer 'FieldValidation-D' \
  --output-dir "$DIR"
```

**Expected:** unsupported schema → UNSUPPORTED_FORMAT / incomplete messaging; explorer→cmd style admin activity should **not** alone drive possible compromise; php/w3wp/php-fpm → shell/interpreter may yield `POSSIBLE_COMPROMISE_REVIEW` requiring analyst validation; cmdlines redacted in HTML.

If no real export is available for a platform, **record “blocked — no authorized export”**; do not invent results.

---

## Scenario E — Legitimate CMS / uploads / app deploy

**Goal:** Historical upload-tree PHP must not auto-escalate; path vs timestamp evidence.

### Windows

```powershell
$dir = 'C:\ProgramData\PHP2Shell\FieldValidation\E'
$web = 'E:\websites\prod\wordpress'   # authorized document root
New-Item -ItemType Directory -Force -Path $dir | Out-Null
.\php2shell-windows-amd64.exe scan `
  --quiet `
  --webroot $web `
  --investigate-from 2026-10-17 `
  --customer 'FieldValidation-E' `
  --output-dir $dir
```

### Linux

```bash
DIR="$HOME/.php2shell/field-validation/E"
WEB=/var/www/html   # authorized document root
mkdir -p "$DIR"
./php2shell scan \
  --quiet \
  --webroot "$WEB" \
  --investigate-from 2026-10-17 \
  --customer 'FieldValidation-E' \
  --output-dir "$DIR"
```

**Expected:** ordinary app `.php` outside upload heuristics → no webroot compromise leads; long-lived CMS files with timestamps outside the window → no leads; in-window birth under uploads may produce low-confidence possible compromise — must not read as confirmed webshell. Contents never appear in reports.

---

## Scenario F — Controlled synthetic suspicious dataset (documented lab)

**Goal:** Confirm the v2.7.0 binary still matches known fixture expectations. **Not field validation.**

From a clone of this repository:

### Windows (PowerShell)

```powershell
$dir = 'C:\ProgramData\PHP2Shell\FieldValidation\F'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$root = (Get-Location).Path   # repo root
.\php2shell-windows-amd64.exe scan --quiet `
  --process-telemetry "$root\testdata\demos\process-telemetry\mde-php-cmd.csv" `
  --investigate-from 2026-10-17 --out "$dir\mde.html"
.\php2shell-windows-amd64.exe scan --quiet `
  --process-telemetry "$root\testdata\demos\process-telemetry\sysmon-admin-negative.csv" `
  --investigate-from 2026-10-17 --out "$dir\admin.html"
.\php2shell-windows-amd64.exe scan --quiet `
  --webroot "$root\testdata\demos\webroot-investigation\positive-upload-php-tree" `
  --investigate-from 2026-10-17 --out "$dir\wr-pos.html"
.\php2shell-windows-amd64.exe scan --quiet `
  --webroot "$root\testdata\demos\webroot-investigation\negative-benign-app-tree" `
  --investigate-from 2026-10-17 --out "$dir\wr-neg.html"
```

### Linux

```bash
DIR="$HOME/.php2shell/field-validation/F"
ROOT="$(pwd)"   # repo root
mkdir -p "$DIR"
./php2shell scan --quiet \
  --process-telemetry "$ROOT/testdata/demos/process-telemetry/mde-php-cmd.csv" \
  --investigate-from 2026-10-17 --out "$DIR/mde.html"
./php2shell scan --quiet \
  --process-telemetry "$ROOT/testdata/demos/process-telemetry/sysmon-admin-negative.csv" \
  --investigate-from 2026-10-17 --out "$DIR/admin.html"
./php2shell scan --quiet \
  --process-telemetry "$ROOT/testdata/demos/process-telemetry/auditd-php-fpm-sh.log" \
  --investigate-from 2026-10-17 --out "$DIR/auditd.html"
./php2shell scan --quiet \
  --process-telemetry "$ROOT/testdata/demos/process-telemetry/ecs-php-fpm-sh.jsonl" \
  --error-log "$ROOT/testdata/demos/process-telemetry/error-correlated.log" \
  --investigate-from 2026-10-17 --out "$DIR/ecs.html"
./php2shell scan --quiet \
  --webroot "$ROOT/testdata/demos/webroot-investigation/positive-upload-php-tree" \
  --investigate-from 2026-10-17 --out "$DIR/wr-pos.html"
./php2shell scan --quiet \
  --webroot "$ROOT/testdata/demos/webroot-investigation/negative-benign-app-tree" \
  --investigate-from 2026-10-17 --out "$DIR/wr-neg.html"
```

### Documented expected outcomes (synthetic)

| Run | Expected `possible_compromise_status` | Notes |
| --- | --- | --- |
| mde / auditd / ecs (with process leads) | `POSSIBLE_COMPROMISE_REVIEW` | Behavioral; not confirmed compromise |
| admin-negative | `NO_MATCHES_IN_SCOPE` | Must not escalate ordinary admin shells |
| wr-pos | `POSSIBLE_COMPROMISE_REVIEW` | Low-confidence / Elevated priority in HTML |
| wr-neg | `NO_MATCHES_IN_SCOPE` | Benign app tree |

---

## Fleet rollup (after several hosts)

```powershell
php2shell rollup --input-dir C:\ProgramData\PHP2Shell\FieldValidation --out C:\ProgramData\PHP2Shell\FieldValidation\rollup.csv
```

```bash
./php2shell rollup --input-dir "$HOME/.php2shell/field-validation" --out "$HOME/.php2shell/field-validation/rollup.csv"
```

Use **one customer** per rollup. Schema should be `php2shell-fleet-csv/v3`. Mixing customers with conflicting `--customer` labels must fail closed.

---

## GO / NO-GO for publishing v2.7.0 (after this checklist)

**GO to publish only if all are true:**

1. Scenarios A–E executed on authorized real hosts (or explicitly waived with written rationale for unavailable EDR/logs).  
2. No critical false “clean host” wording in reports or operator messaging.  
3. Webroot-only and admin-shell FP behavior acceptable to maintainers.  
4. `go test ./...`, `go vet ./...`, `scripts/check-release-docs.sh --for-tag v2.7.0` pass on finalized notes.  
5. Release notes draft language removed; version/tag match.

**NO-GO if:** critical overstatement, systematic FPs on legitimate CMS/admin activity, CI red, or field blockers unresolved.
