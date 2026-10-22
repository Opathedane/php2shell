# Rule design and compromise-assessment limitations

These are data-only, Ed25519-verified IOC rules — not a PHP2Shell exploitation simulator, XDR, EDR or a forensic acquisition utility.

**A match is a lead**: Review the complete original server evidence and context with a qualified analyst; a substring can also match ordinary requests. A negative result means only that no supported rule matched in the files actually inspected. It does not establish that a system was not exploited.

Detection constraints:
- `http_target_literal` compares only the request target from Apache/nginx combined or IIS W3C formats, not POST bodies, arbitrary headers or TCP packets.
- Log files must be explicitly supplied using `--access-log`. They must be regular files and 32 MiB or smaller. Rotated `.gz` logs, oversized lines, other log formats and missing timestamps are not supported; see log coverage status.
- IIS `applicationHost.config` is static handler metadata, not a proof that a specific site has a vulnerable or patched active PHP runtime.
- File hash checks require `--webroot`, are bounded, and deliberately skip symlinks, devices and large files. No malware code executes.
- No historical parent-child process telemetry, Windows event history, Sysmon queries, Defender queries, scheduled task audit, web shell heuristics, exploit requests or YARA engine (offline process/EDR file ingest is planned after Phases A/B; see [COMPROMISE-INVESTIGATION.md](COMPROMISE-INVESTIGATION.md)).
- Phases A/B investigation patterns (error-log OOM/segfault, long POST heuristic) are **suspected leads** only; they do not use the signed pack engine and never imply confirmed compromise.
- Verified rules can arrive via GitHub *after operator key pinning*. A repo compromise alone cannot alter accepted rules, but a compromised signing key could. Public key rotation is manual.
- PHP2Shell official affected/fixed versions and actual exploitation characteristics are required before publishing vulnerability rules or meaningful CVE-specific match claims. Vendor backports can invalidate naive version comparisons.

Incident-response handling: preserve original evidence (prefer immutable copies), gather PHP/FPM/IIS error logs, EDR records, outbound connections, auth records and file histories as appropriate. Do not rely on this report to decide that a host is clean.
