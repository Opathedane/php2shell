# GitHub presentation proposal (Phase 1 — do not apply yet)

Values for the repository **About** sidebar. Apply only after explicit maintainer approval (GitHub UI). Do not commit secrets.

## About description (proposed)

```
Read-only PHP discovery and patch-review scanner for Windows, Linux, and macOS. Produces HTML+CSV reports for CVE-2026-109618/109619 assessment — never claims a host is clean or that the active HTTP runtime is verified.
```

## Homepage / documentation URL (proposed)

```
https://github.com/Opathedane/php2shell/tree/main/docs
```

(Use `main`, not `master`. Points at the docs index.)

## Topics (proposed — remove `cvs`)

Keep / add:

- `php`
- `security`
- `security-assessment`
- `vulnerability-scanner`
- `dfir`
- `incident-response`
- `golang`
- `windows`
- `linux`
- `html-report`
- `csv`
- `apache-2-0`

Remove:

- `cvs` (incorrect / misleading)
- Overly vague topics that do not describe the product (revisit `reporting` / `standalone` / `php2shell` as optional)

Suggested final set:

`php` `golang` `security-assessment` `vulnerability-scanner` `dfir` `incident-response` `windows` `linux` `html-report` `csv` `apache-2-0`

## Suggested README badges (markdown)

Use shields.io against public GitHub APIs. Place under the title in README when approved:

```markdown
[![Release](https://img.shields.io/github/v/release/Opathedane/php2shell?display_name=tag)](https://github.com/Opathedane/php2shell/releases/latest)
[![License](https://img.shields.io/github/license/Opathedane/php2shell)](LICENSE)
[![CI](https://github.com/Opathedane/php2shell/actions/workflows/ci.yml/badge.svg)](https://github.com/Opathedane/php2shell/actions/workflows/ci.yml)
```

Optional (only if accurate): Go report card, etc. Do **not** badge “coverage 100%” or “production certified.”

## Not in this proposal

- Enabling Wiki / Projects (recommend leave off or disable if unused — separate decision)
- Changing visibility or ownership
