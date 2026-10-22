# PHP2Shell fleet CSV schema

Every `php2shell scan` writes a UTF-8 CSV (with BOM for Excel) beside the HTML report. One **logical row per independently identified PHP installation**. Hosts with no comparable installation emit a single host-level row.

**Current writer schema:** `php2shell-fleet-csv/v3`  
**Readers / rollup:** accept `v1`, `v2`, and `v3` (older rows gain empty investigation columns when rolled up into v3 output).

## Columns (v3)

| Column | Description |
| --- | --- |
| `schema_version` | `php2shell-fleet-csv/v3` (or `v1`/`v2` on legacy inputs) |
| `scan_id` | Stable id for this scan result (derived from host metadata + timestamp) |
| `hostname` | Assessed host |
| `os` | GOOS value (e.g. `windows`, `linux`) |
| `architecture` | GOARCH value |
| `scan_timestamp_utc` | RFC3339 UTC |
| `scanner_version` | Embedded tool version (e.g. `2.6.0` public; `2.7.0` in unreleased RC trees) |
| `customer_label` | Optional `--customer` label (**not** authenticated tenancy) |
| `install_id` | Correlated install key (or `host:no_comparable_install`) |
| `php_version` | Observed / inferred version from **install evidence**, or empty |
| `version_confidence` | `HIGH` / `MEDIUM` / `LOW` / `NONE` |
| `version_evidence` | See values below |
| `install_path` | Primary binary/package location when known |
| `component_name` | Evidence component (e.g. `php.exe`, `php8.4-fpm`) |
| `upstream_minimum_fixed` | Official upstream minimum for the branch when comparable |
| `patch_status` | Same vocabulary as HTML patch assessments (unchanged meanings) |
| `remediation_priority` | e.g. `CRITICAL`, `VERIFY`, `REVIEW` |
| `recommended_action` | Primary remediation text |
| `qualification` | Limitations / confidence narrative |
| `active_http_runtime_status` | e.g. `NOT_VERIFIED`, `OPERATOR_REPORTED_NOT_ATTESTED` |
| `compromise_status` | Host compromise review status |
| `host_vulnerability_status` | Host-level vulnerability rollup status |
| `discovery_completeness` | `PARTIAL`, `INCOMPLETE`, `NO_PHP_OBSERVED_IN_SCOPE`, `PARTIAL_VERSION_UNKNOWN` |
| `limitations_summary` | Short caveats (may mention config candidates) |
| `config_discovery_status` | Host-level php.ini inventory status (see below) |
| `config_candidate_count` | Count of `php_ini_candidate` files |
| `config_setting_observation_count` | Count of whitelisted `configuration_observation` rows |
| `config_correlated_to_install` | `YES` / `NO` — whether a candidate relates to **this** install row |
| `config_primary_ini_path` | Path of a correlated primary `php.ini` when known (path only; never secrets) |
| `config_ini_classes` | Semicolon-separated classes (e.g. `primary_candidate;sample_or_template`) |
| `exploitation_attempt_status` | Independent IR axis (e.g. `NOT_ASSESSED`, `NO_MATCHES_IN_SCOPE`, `SUSPECTED_ATTEMPTS_REVIEW`) |
| `possible_compromise_status` | Independent IR axis: `NOT_ASSESSED` without usable `--process-telemetry` and/or `--webroot` investigation; else `NO_MATCHES_IN_SCOPE` or `POSSIBLE_COMPROMISE_REVIEW` (never auto-confirmed). Webroot-only review is low-confidence metadata (see `limitations_summary`) |
| `investigation_coverage` | Completeness of investigation inputs (`NOT_REQUESTED`, `ASSESSED_SCOPE_LIMITED`, `INCOMPLETE`, …) |
| `investigation_window_from_utc` | Effective investigation window start (RFC3339 UTC) |
| `investigation_window_to_utc` | Effective investigation window end (RFC3339 UTC) |

`compromise_status` remains the **legacy signed-IOC rollup** only. It is not a host clearance and is independent of exploitation-attempt / possible-compromise statuses.

### `config_discovery_status` values

| Value | Meaning |
| --- | --- |
| `NONE` | No php.ini-style candidates observed |
| `PRIMARY_CANDIDATES_OBSERVED` | One or more primary `php.ini` candidates |
| `UNCORRELATED_PRIMARY_CANDIDATES` | Primary `php.ini` found with no related binary install |
| `TEMPLATES_ONLY` | Only sample/template names (e.g. `php.ini-development`) |
| `MIXED_PRIMARY_AND_TEMPLATE` | Both primary and template candidates |
| `CANDIDATES_OBSERVED` | Other / fragment candidates |
| `COVERAGE_GAPS_ONLY` | Known candidates could not be inspected (path+reason only) |
| `*_WITH_SKIPS` | Suffix when skip diagnostics accompany another status (e.g. `UNCORRELATED_PRIMARY_CANDIDATES_WITH_SKIPS`) |
| `TRUNCATED` | Configuration file cap reached |

**Important:** Configuration columns are **supplementary discovery**. They must not be treated as:

- confirmed PHP installation  
- authoritative PHP version  
- active HTTP runtime attestation  
- definitive vulnerability status  

## `version_evidence` values

| Value | Meaning |
| --- | --- |
| `verified_binary_metadata` | Embedded string and/or PE resource |
| `path_inferred` | Installer path segment (labelled MEDIUM confidence) |
| `package_metadata` | OS package inventory |
| `operator_reported` | `--runtime-*` flags |
| `repository_declaration` | Dockerfile / compose declaration only |
| `version_unknown` | PHP binary path seen; version not established |
| `php_not_observed_in_scope` | No PHP **install** evidence in this scan scope (php.ini alone stays here) |
| `unknown` | Other / unclassified |

## Consolidation

```bash
php2shell rollup --input-dir ./server-reports --out ./customer-summary.csv
php2shell rollup --out ./customer-summary.csv a.csv b.csv c.csv
```

Select **one customer’s** report collection explicitly. Conflicting non-empty `customer_label` values are rejected. Labels are never proof of ownership. Mixed v1/v2 inputs are accepted; output is written as **v2**.

Legacy JSON rollup remains available: `php2shell rollup --format json --tenant-map map.json --out out.csv reports/*.json`.
