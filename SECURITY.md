# Security policy

**Obtain authorization before scanning production systems.** PHP2Shell is a read-only assessment aid, not a penetration-test tool, and does not contain exploit code. It cannot alone certify that a host is patched or uncompromised.

## Reporting vulnerabilities

Disclose security issues in PHP2Shell **privately** to the maintainer at **jesma@itm8.com**. Do not open a public GitHub issue for exploitable defects in the scanner, signing workflow, or release pipeline.

Do **not** send customer evidence, credentials, access logs, or production endpoint inventories via ordinary email. Agree a secure channel first. No automatic data transfer takes place from the scanner.

## Public issue hygiene

Do not attach customer HTML reports, access logs, network architecture, credentials, or production endpoint names to public GitHub issues. Prefer redacted reproduction steps. See the issue templates under `.github/ISSUE_TEMPLATE/`.

## Product security limitations

- The scanner refuses to open non-regular/symlinked input files based on pathname inspection; on an adversary-controlled filesystem, pathname TOCTOU races remain possible (no filesystem snapshot or OS-specific `openat2` hardening). Prefer minimum permissions, a protected reports directory, or an offline forensic copy.
- It does not prevent tampering with logs or package databases on a compromised host.
- The local Docker socket is inherently privileged even for read-only requests; `--docker` is strictly opt-in.
- There is no Authenticode signature, notarization, or remotely attested chain of custody for binaries or reports. Verify `SHA256SUMS` from a trusted release page.
- HTML reports escape dynamic content and use a restrictive local CSP. Fleet and legacy CSV outputs apply spreadsheet formula sanitization; treat all exported files as untrusted inputs.
- Report files are mode `0600` on systems honoring POSIX permissions; Windows output privacy depends on the parent directory ACL.
- HTML and CSV from one scan may contain hostnames, paths, and package metadata — keep them inside the engagement boundary.

## Supply chain

Release publication is gated by `.github/workflows/release.yml` (tag must match embedded version; version-specific `docs/releases/vX.Y.Z.md`; `scripts/check-release-docs.sh`; existing releases are not overwritten). See `docs/GOVERNANCE.md` and `docs/RELEASE-CHECKLIST.md` before publishing a new version. Never overwrite published release assets for existing tags (`v2.3.0`–`v2.8.2`, …). Optional `--deep-root` Deep Discovery (v2.6.0+) is off by default, refuses UNC/volume roots, never executes PHP, and must report truncation explicitly. nginx/PHP-FPM configuration discovery (v2.8.0+) is read-only and never attests the active HTTP-serving runtime or its patch state.
