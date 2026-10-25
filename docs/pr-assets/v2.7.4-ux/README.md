# v2.7.4 UX polish — PR assets

Synthetic before/after samples for the console UX & reliability patch.

| File | Purpose |
| --- | --- |
| `console-windows-no-php-before.txt` | Simulated v2.7.3 CLI with incorrect Linux package-DB note on Windows |
| `console-windows-no-php-after.txt` | v2.7.4 CLI: no dpkg note; overall priority + recommended next |
| `console-below-threshold-after.txt` | Clear patch assessment + installation action + next step |
| `html-*.html` | Executive summary scenarios (open in a browser) |
| `screenshot-windows-no-php.png` | HTML executive: Windows no-PHP within coverage |
| `screenshot-incomplete-inventory.png` | HTML executive: incomplete inventory |
| `screenshot-below-threshold.png` | HTML executive: below upstream fix |
| `screenshot-multi-install.png` | HTML executive: mixed multi-install |

Regenerate text/HTML:

```bash
PHP2SHELL_WRITE_PR_ASSETS=1 go test ./internal/console/ -run TestWritePRAssets
```

**Windows PowerShell 5.1 / Windows Terminal interactive ANSI:** NOT TESTED on a real Windows host in this PR (cross-compile + VT best-effort unit path only).
