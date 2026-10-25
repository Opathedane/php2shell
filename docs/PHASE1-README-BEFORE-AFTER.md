# Phase 1 — README before / after

Comparison for Draft PR review. **Before** = `main` at v2.8.0 publish tip. **After** = this branch.

## Structure

| Before | After |
| --- | --- |
| Numbered sections 1–8 mixing install, features, enterprise, and stale “more docs” | Hero → naming → quick start → outputs → coverage → docs map |
| Doc map promoted v2.7.2 acceptance / distribution readiness | Doc map points at living guides + `docs/README.md` |
| No screenshot | Stable synthetic screenshot under `docs/assets/` |
| No badges | Release / license / CI badges |
| macOS omitted from platform table | macOS downloads + quick start |
| nginx/FPM absent from README | Coverage section + honesty limits + design link |
| “Windows and Linux” only in intro | Windows, Linux, and macOS |

## Honesty / naming

| Before | After |
| --- | --- |
| Weak product-vs-CVE distinction | Explicit naming callout (tool vs advisories assessed) |
| Limitations in “Does not” list | Same limits plus explicit “config ≠ verified runtime” and link to SUPPORTED-COVERAGE |

## What did not change

- Scanner code, schemas, workflows, Version string  
- Latest public release remains **v2.8.0**  
- No claim of complete discovery, verified active runtime, patch clearance, or clean host  
