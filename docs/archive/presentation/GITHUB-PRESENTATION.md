# GitHub presentation (maintainer UI checklist)

These settings are configured in the GitHub web UI, not by committing files.

## Repository description (About)

```
PHP security assessment scanner for Windows and Linux. Detect PHP installations, assess upstream patch exposure, and generate HTML and CSV reports for single hosts or customer fleets.
```

(Avoid claiming “open source” in the description until an approved LICENSE is committed.)

## Topics

Suggested:

`php`, `cybersecurity`, `vulnerability-scanner`, `security-assessment`, `incident-response`, `windows`, `linux`, `golang`, `html-report`, `csv`

Optional later (only after license approval): `open-source`, `apache-2-0`

## About sidebar checklist

1. Set **Description** (above).
2. Set **Topics**.
3. Enable **Issues** (templates already in `.github/ISSUE_TEMPLATE/`).
4. Link **Security policy** (`SECURITY.md`).
5. Feature **Releases**; keep prerelease alphas unmarked as Latest.
6. Do not mark draft or unapproved license text as the project license until approved.

## How to edit

GitHub → repository → gear icon beside **About** → paste description → add topics → Save.
