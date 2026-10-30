# Stable documentation assets

Files here are **long-lived** README / docs illustrations. Prefer this directory over `docs/pr-assets/` (which holds per-PR evidence).

| File | Use |
| --- | --- |
| `report-example-patch-assessment.png` | README example HTML executive summary (synthetic) |
| `report-example-patch-assessment.html` | Matching HTML sample for offline viewing |

**Anonymization / representativeness:** Synthetic lab fixture only — **not** a customer report. Host label is a non-customer lab name (`old-php`). No customer hostnames, paths, or engagement data. Regenerated from current `EncodeHTML` output for **v2.8.2** (CVE thresholds unchanged). To refresh: `PHP2SHELL_WRITE_README_ASSET=1 go test ./internal/audit/ -run TestWriteReadmeExampleAsset`, then capture a viewport screenshot of the HTML for the PNG.

Do not commit real customer reports here.
