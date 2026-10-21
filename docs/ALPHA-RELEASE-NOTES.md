# Historical: PHP2Shell v2.2.0-alpha.2 release notes

> **Status:** Historical prerelease notes only. The current prepared release is **v2.6.0**. Do not treat this file as current product documentation. Official notes: [RELEASE-NOTES.md](RELEASE-NOTES.md).

## Original alpha summary (unchanged for history)

- Standalone builds for Linux, Windows and macOS; no target runtime required.
- Uses PHP's official 21 October 2026 fixed-release thresholds (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35).
- The HTML report included a three-part evidence-qualified summary and next steps, followed by per-evidence patch assessments. Alpha builds also exported JSON and CSV; **v2.3.0 `scan` writes HTML only**.
- **This was not a production-cleared or complete compromise scanner**: backported vendor patches and the serving runtime must be independently verified; no validated PHP2Shell-specific compromise IOCs are bundled.

[Official patch instructions](https://www.php.net/) · [PHP CVE advisories](https://github.com/php/php-src/security/advisories)

Existing alpha GitHub Releases remain unchanged as prereleases. Prefer v2.3.0+ for new assessments.
