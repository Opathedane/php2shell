# Stable documentation assets

Files here are **long-lived** README / docs illustrations. Prefer this directory over `docs/pr-assets/` (which holds per-PR evidence).

| File | Use |
| --- | --- |
| `report-example-patch-assessment.html` | Full interactive HTML sample (README links here) |
| `report-example-patch-assessment-v2.8.2.png` | Full-page README preview of that HTML (synthetic) |

**Anonymization / representativeness:** Synthetic lab fixture only — **not** a customer report. Host label is a non-customer lab name (`old-php`). No customer hostnames, paths, or engagement data. HTML regenerated from current `EncodeHTML` for **v2.8.2** (CVE thresholds unchanged). To refresh: `PHP2SHELL_WRITE_README_ASSET=1 go test ./internal/audit/ -run TestWriteReadmeExampleAsset`, then capture a **full-page** screenshot of the HTML (device height ≥ document scroll height) and bump the PNG filename when replacing so GitHub CDN cache refreshes.

Do not commit real customer reports here.
