# PHP2Shell fleet CSV schema (`php2shell-fleet-csv/v1`)

Every `php2shell scan` writes a UTF-8 CSV (with BOM for Excel) beside the HTML report. One **logical row per independently identified PHP installation**. Hosts with no comparable installation emit a single host-level row.

## Columns

| Column | Description |
| --- | --- |
| `schema_version` | Always `php2shell-fleet-csv/v1` |
| `scan_id` | Stable id for this scan result (derived from host metadata + timestamp) |
| `hostname` | Assessed host |
| `os` | GOOS value (e.g. `windows`, `linux`) |
| `architecture` | GOARCH value |
| `scan_timestamp_utc` | RFC3339 UTC |
| `scanner_version` | Embedded tool version (e.g. `2.4.0`) |
| `customer_label` | Optional `--customer` label (**not** authenticated tenancy) |
| `install_id` | Correlated install key (or `host:no_comparable_install`) |
| `php_version` | Observed / inferred version, or empty |
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
| `limitations_summary` | Short fixed caveats |

## `version_evidence` values

| Value | Meaning |
| --- | --- |
| `verified_binary_metadata` | Embedded string and/or PE resource |
| `path_inferred` | Installer path segment (labelled MEDIUM confidence) |
| `package_metadata` | OS package inventory |
| `operator_reported` | `--runtime-*` flags |
| `repository_declaration` | Dockerfile / compose declaration only |
| `version_unknown` | PHP binary path seen; version not established |
| `php_not_observed_in_scope` | No PHP evidence in this scan scope |
| `unknown` | Other / unclassified |

## Consolidation

```bash
php2shell rollup --input-dir ./server-reports --out ./customer-summary.csv
php2shell rollup --out ./customer-summary.csv a.csv b.csv c.csv
```

Select **one customer’s** report collection explicitly. Conflicting non-empty `customer_label` values are rejected. Labels are never proof of ownership.

Legacy JSON rollup remains available: `php2shell rollup --format json --tenant-map map.json --out out.csv reports/*.json`.
