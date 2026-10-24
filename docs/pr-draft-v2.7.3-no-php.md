# Draft PR — v2.7.3 no-PHP reporting

## Summary

- Fix confusing HTML/CLI reporting when **no PHP** is found (especially Windows hosts without PHP).
- Distinguish **completed applicable inventory** vs **incomplete discovery** vs **version-unknown** vs **assessable PHP**.
- Target release: **v2.7.3**. Does **not** modify the published **v2.7.2** tag or release.

## Assessment changes (short)

| Situation | Before (v2.7.2 UX) | After (v2.7.3) |
| --- | --- | --- |
| Windows, applicable discovery OK, no PHP | “Unable to determine”, “inventory incomplete”, dpkg/RPM noise, patch/runtime next steps | `NO_PHP_DETECTED_WITHIN_SCAN_COVERAGE`, informational priority, 0 installs, no PHP-specific remediation spam |
| Relevant sources failed (IIS/PATH/process ACCESS_DENIED/UNAVAILABLE) | Mixed / noisy | “Unable to determine — inventory incomplete”; gaps listed; ScanIncomplete unchanged |
| Linux packages `NOT_SUPPORTED` (RPM etc.) | Treated like a hard “missing” package DB on every OS | Soft packaging gap on Linux only; **ignored on Windows** |
| Clearance language | Risk of sounding like “find the SAPI / patch now” | Explicit: not PHP-free, not patched, not uncompromised |

Machine `vulnerability_status` for empty comparable versions remains schema-stable (`NO_COMPARABLE_PHP_VERSION_FOUND_INVENTORY_INCOMPLETE`). Human labels + `summary.php_discovery` / `summary.patch_review` carry the clearer semantics.

## Before / after HTML

![Before — v2.7.2 no-PHP UX](pr-assets/v2.7.3-no-php/before-no-php.png)

![After — v2.7.3 no PHP within coverage](pr-assets/v2.7.3-no-php/after-no-php.png)

![After — genuine Windows incomplete coverage](pr-assets/v2.7.3-no-php/after-windows-incomplete.png)

## Pre-review checklist

- [x] No-PHP “complete” only when applicable expected discovery sources evaluated successfully
- [x] Genuine Windows failures (IIS, filesystem/PATH, processes, ACCESS_DENIED/UNAVAILABLE) remain visible
- [x] Unsupported Linux package managers do not create false Windows coverage warnings
- [x] No-PHP results never imply PHP-free / patched / uncompromised
- [x] Visual review of updated HTML (complete no-PHP + incomplete Windows)
- [x] CLI / HTML / CSV / status JSON semantics aligned; exit codes & fleet compatibility preserved
- [x] `go test ./...` and `go vet ./...` pass

## Out of scope

- New scanning features
- Vulnerability threshold changes
- Merge / tag / publish without approval
