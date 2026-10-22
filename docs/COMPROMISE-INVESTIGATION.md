# Compromise investigation (Phases A & B — development)

Evidence-based **investigation assist** for CVE-2026-109618 / CVE-2026-109619. This extends PHP2Shell beyond patch inventory. It is **not** a clearance tool and never claims a host is clean or confirmed compromised.

**Published release v2.6.0 is unchanged.** This capability is under development on `feat/compromise-investigation`; the next public version number is not finalized.

## Independent statuses

| Status | Meaning when investigation inputs are absent | Meaning when logs are assessed |
| --- | --- | --- |
| Vulnerability / patch exposure | Existing host vulnerability rollup | Unchanged; independent of IR |
| Exploitation attempts | **`NOT_ASSESSED`** (not a negative finding) | `NO_MATCHES_IN_SCOPE` or `SUSPECTED_ATTEMPTS_REVIEW` |
| Possible compromise | **`NOT_ASSESSED`** | Still **`NOT_ASSESSED`** in Phases A/B (no offline EDR/process telemetry yet) |
| Investigation coverage | **`NOT_REQUESTED`** | `ASSESSED_SCOPE_LIMITED`, `PARTIAL_TIMESTAMP_UNCERTAIN`, or `INCOMPLETE` |

Signed-pack IOC matches continue to set legacy `compromise_status` only; they do not auto-confirm compromise.

## CLI

```bash
php2shell scan \
  --access-log /var/log/nginx/access.log \
  --error-log /var/log/php8.3-fpm.log \
  --error-log /var/log/apache2/error.log \
  --investigate-from 2026-10-17 \
  --output-dir "$HOME/.php2shell/reports"
```

- `--investigate-from` / `--investigate-to`: UTC `RFC3339` or `YYYY-MM-DD`. Default from **2026-10-17** when investigating; analysts may choose an **earlier** date. Requires `--access-log` and/or `--error-log`.
- `--error-log`: bounded PHP/Apache error logs (≤32 MiB each, ≤20 files).
- First/last timestamps in logs **do not** prove continuous coverage (rotation, gaps, timezone ambiguity, parser failures).

## Research-backed patterns (Phase B)

| Pattern | Class | Max confidence | Notes |
| --- | --- | --- | --- |
| PHP Fatal memory exhausted **in Unknown on line 0** | verified_public_pattern | suspected | Datadog; memory exhaustion alone ≠ attack |
| Apache `AH00052` / child Segmentation fault | verified_public_pattern | suspected | Datadog; successful exploits may not crash |
| Long POST **request-target** (≥2048 characters of URI path/query as logged) | heuristic | unconfirmed | Measures **request-target length only** — not request-body length or total request size. Combined/IIS W3C access logs do not establish body size. Target text not retained. |
| Error research pattern within ±15 m of long request-target | correlation | unconfirmed | **Temporal proximity only — not causality.** Both sides require reliable timestamps; untimed lines are excluded. Finding lists exact contributing kinds/lines/times. Not confirmed exploitation or compromise. |

A **single** memory error, worker crash, or long request-target never implies successful exploitation or compromise. Correlation never auto-attributes PHP2Shell.

## Fleet CSV

Writers emit **`php2shell-fleet-csv/v3`** with:

- `exploitation_attempt_status`
- `possible_compromise_status`
- `investigation_coverage`
- `investigation_window_from_utc` / `investigation_window_to_utc`

Rollup accepts **v1–v3** and writes v3.

## Hard limits

- No exploit probes, no PHP execution, no uploads, no automatic remediation.
- Findings omit HTTP query secrets and raw sensitive log lines.
- AWS source IPs are **not** imported in Phases A/B (deferred; weak TI only when added later).
- Next phase priority: offline EDR/process telemetry (Windows + Linux), before weak IP-only indicators.

## Related

- [IOC-RULE-LIMITATIONS.md](IOC-RULE-LIMITATIONS.md)
- [THREAT-INTELLIGENCE.md](THREAT-INTELLIGENCE.md)
- [CSV-SCHEMA.md](CSV-SCHEMA.md)
- [ADVANCED-USAGE.md](ADVANCED-USAGE.md)
