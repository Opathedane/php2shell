# Understanding PHP2Shell reports

This guide is for IT administrators reading an HTML report or CSV fleet row for the first time.

PHP2Shell assesses **observed PHP inventory** against official upstream advisories. A successful scan is **not** proof that the HTTP-serving runtime is patched or that the host is uncompromised.

**Latest public release: [v2.8.1](https://github.com/Opathedane/php2shell/releases/tag/v2.8.1).**  
**Primary CVEs:** CVE-2026-109618, CVE-2026-109619  
**Upstream fix thresholds (21 Oct 2026):** PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35  
**Additional advisory:** CVE-2026-115560 (informational; no fixed versions yet)

Synthetic screenshot + HTML (no customer data): [`assets/report-example-patch-assessment.png`](assets/report-example-patch-assessment.png). Additional fixtures: [`testdata/examples/v2.7.2-qa/`](../testdata/examples/v2.7.2-qa/).

**nginx / PHP-FPM (v2.8.0):** configuration evidence may appear under technical / coverage sections. Correlation of `fastcgi_pass` with a local FPM `listen` is **never** proof of the active HTTP-serving PHP runtime or its patch state. See [SUPPORTED-COVERAGE.md](SUPPORTED-COVERAGE.md).

---

## 1. How to read the HTML (first screen)

| Section | Question it answers |
| --- | --- |
| **Patch assessment** | Do observed versions need an update or further verification? |
| **PHP installations found** | What versions/evidence were seen? |
| **Active web runtime** | Was the HTTP-serving PHP runtime verified? (Usually **not**) |
| **What could not be verified** | Package DB gaps, permissions, truncation, runtime |
| **Recommended next steps** | Practical actions (always before optional IR) |
| **Additional security advisories** | CVE-2026-115560 config review (if any) |
| **Optional investigation findings** | Only when IR inputs were used or findings exist |
| **Expandable technical evidence** | Full detail for auditors |

---

## 2. Patch assessment outcomes

### A. Observed version below upstream fix threshold

**Meaning:** Inventory shows a comparable version **lower** than the upstream fix for that branch (for example 8.3.24 when the fix is 8.3.36).

**Typical HTML language:** “Update review required”

**Do this:**

1. Identify which PHP binary/SAPI serves HTTP (FPM pool, IIS handler, Apache module, container).
2. Update to the fixed upstream release **or** apply and document an equivalent **vendor** security package.
3. Restart all PHP workers / recycle app pools.
4. Re-scan and confirm the **serving** runtime version separately (phpinfo via authorized ops, vendor tooling, etc.).

**Do not:** Treat “scan exit 0” as patched.

**Example file:** `01-below-upstream.html`

---

### B. Observed version meets upstream fix threshold

**Meaning:** Inventory shows a version at or above the upstream fix (for example 8.3.36).

**Typical HTML language:** “No below-threshold versions observed (active runtime unverified)”

**Do this:**

1. Still verify the **active web-serving** PHP matches that version.
2. Check other hosts, containers, and secondary installs.
3. Keep `session.upload_progress.enabled=0` if you applied it for CVE-2026-109619 / CVE-2026-115560 mitigation until PHP’s regular fix for 115560 ships.

**Do not:** Call the host “safe” or “clean.” Past compromise is out of scope for a version comparison.

**Example file:** `02-at-upstream-runtime-unverified.html`

---

### C. Vendor patch verification required

**Meaning:** Version is on an **EOL upstream** branch (PHP 8.1 or older), or package evidence implies a distro build that may carry backports under an older version string.

**Typical HTML language:** “Update review required” / legacy vendor verification

**Do this:**

1. Prefer upgrading to a supported fixed branch (8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+).
2. If you must stay on vendor LTS, obtain **authoritative** vendor advisory evidence that both CVEs are fixed in that exact package revision.
3. Preserve the raw package version string from the report (CSV / HTML evidence).

**Do not:** Assume “below upstream number” means unpatched on Debian/RHEL/Plesk, or that “same number as upstream” means vendor-patched without checking.

**Example file:** `03-legacy-vendor-verification.html`

---

### D. Insufficient evidence / unknown patch status

**Meaning:** Version string missing, major.minor only, unparseable, prerelease/RC, or branch not in the advisory table (for example PHP 8.6.x stable until covered).

**Typical HTML language:** “Inconclusive”

**Do this:** Locate exact patch versions for serving runtimes; do not use RC builds in production even if they claim security fixes.

---

### E. No PHP detected within scan coverage

**Meaning:** Applicable PHP inventory checks **completed** (OS-aware) and found **no** package/binary/process PHP evidence. HTML shows **“No PHP detected within scan coverage”**, **0** installations, and **no PHP-specific patch remediation**. Machine `vulnerability_status` may still say inventory incomplete for schema stability; human labels and `summary.php_discovery` use `NO_PHP_DETECTED_WITHIN_SCAN_COVERAGE`.

**Do this:** Widen authorized roots (`--config-root`, `--deep-root`, `--php-ini`) only if PHP may live elsewhere. Do **not** treat the host as PHP-free or safe. Do **not** expect Windows reports to warn about missing Linux dpkg/apk/RPM databases.

**Example file:** `04-no-php-detected.html`

---

### E2. No PHP evidence, inventory incomplete

**Meaning:** No PHP evidence, but one or more **relevant** discovery sources failed or are unavailable (permissions, truncation, or Linux packaging systems this release does not inventory). Distinct from unsupported sources that do not apply on the current OS (for example packages `NOT_SUPPORTED` on Windows).

**Typical HTML language:** “Unable to determine — inventory incomplete”

**Do this:** Fix the listed coverage gaps and re-scan before closing patch status.

---

### F. Incomplete scan

**Meaning:** Exit code **2**, or status JSON `COMPLETED_INCOMPLETE` / `SCAN_INCOMPLETE`, or coverage `TRUNCATED` / `UNAVAILABLE` / `ACCESS_DENIED`. Independent of whether PHP was detected.

**Do this:** Collect HTML+CSV anyway; fix permissions/paths; re-run. Do not close the engagement as cleared.

**Example file:** `06-incomplete-coverage.html`

---

### G. Investigation not performed

**Meaning:** No `--access-log` / `--error-log` / `--process-telemetry` / `--waf-log` / investigation webroot inputs. Exploitation-attempt and possible-compromise stay **not assessed**.

**Do this:** Treat as inventory/patch assessment only. Not assessing IR is **not** a clean IR result.

---

### H. Potential exploitation / compromise indicators

**Meaning:** Optional IR/WAF/IOC inputs produced suspected leads (blocks, patterns, signed IOC matches).

**Do this:** Analyst review. A WAF **block** is not successful exploitation. Follow [COMPROMISE-INVESTIGATION.md](COMPROMISE-INVESTIGATION.md).

**Example file:** `07-optional-dfir-findings.html`

---

## 3. CVE-2026-115560 (additional advisory)

Shown only when php.ini evidence (or inspected candidates) is present.

| Status (human) | Meaning |
| --- | --- |
| Manual verification required | Risky serialize_handler + upload progress On in observed config |
| Mitigation configured (runtime not verified) | Upload progress Off observed — confirm effective SAPI + restart |
| No risky initial serialize_handler observed | Handler appears `php` — apps may still change it at runtime |
| Undetermined | Conflicts, missing settings, or sample-only evidence |

PHP’s temporary mitigation: set `session.upload_progress.enabled=0` in pre-request config and restart workers. **No invented fixed PHP versions.**

---

## 4. CSV and status JSON (automation)

| Artifact | Use |
| --- | --- |
| `.html` | Human review |
| `.csv` | Fleet rollup (`php2shell rollup`) |
| `.status.json` | Machine outcome: `exit_code`, `execution_status`, `scan_incomplete`, `status_json_written`, `error_ids` |

See [EXIT-CODES-AND-DEPLOYMENT.md](EXIT-CODES-AND-DEPLOYMENT.md) and [CSV-SCHEMA.md](CSV-SCHEMA.md).

---

## 5. Lifecycle notes (informational)

Support expiry (php.net) may appear beside installations. Meeting a CVE fix threshold does **not** mean the branch has long-term upstream support. Lifecycle notes are **not** separate critical CVE findings.
