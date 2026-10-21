# Maintainer-managed indicator bundles

**No PHP2Shell-specific indicators have been confirmed by an upstream official advisory in this source snapshot (21 October 2026, before 14:00 UTC). `template.json` is intentionally EMPTY. Never interpret an empty bundle as evidence of a clean server.**

## Safe publication workflow

1. Independent reviewer confirms any proposed IOC through an official vendor advisory or a reproducible, documented and responsibly sourced investigation. Do not import unverified leaked PoCs.
2. Add indicator objects with unique IDs, type `http_target_literal` or `file_sha256`, source URL, severity, confidence and explanation. No regular expressions, scripting, YARA execution or arbitrary commands are accepted.
3. Increment `sequence`; update issued/expiry dates (max 90 days). Use a short expiry for urgent rules.
4. Maintainer generates a dedicated **Ed25519 signing keypair outside the Git checkout**:
   `php2shell rules keygen --out-dir /secure/location`
5. Put **ONLY the public key** (`rule-signing-public.hex`) in a trusted separate distribution channel. Customers explicitly pin it ONCE using `php2shell rules trust --key rule-signing-public.hex`. This is a trust-on-first-use process: verify the key fingerprint through an independent authenticated channel.
6. Sign reviewed bundle offline:
   `php2shell rules sign --input rules/template.json --private /secure/location/rule-signing-private.hex --out rules/signed.json`
7. Check locally:
   `php2shell rules verify --bundle rules/signed.json --key /secure/location/rule-signing-public.hex`
8. Commit ONLY reviewed bundle source and signed envelope; **NEVER** commit the private signing key. Apply branch protections, code-owner review and signed commits. Publish `rules/signed.json` through a stable GitHub raw URL.
9. Customers opt into downloads with:
   `php2shell rules update --url https://raw.githubusercontent.com/Opathedane/php2shell/main/rules/signed.json`
   Updates reject redirects, unsupported hosts, invalid signatures, expiry and stale sequence numbers. `php2shell scan` then uses the cached signed bundle.

## Data definitions

- `http_target_literal`: case-insensitive fixed substring in the HTTP request target in explicit Apache/nginx or IIS W3C access logs. This is a match, **not** proof of successful exploit.
- `file_sha256`: SHA-256 digest of a regular file under an explicit `--webroot` (limited to 16 MiB each, 3000 files, 256 MiB total). A digest match can support triage, but requires context and provenance.

All rules are inert UTF-8 JSON. Invalid signatures or unsupported types fail closed. Results keep rule ID, source, location and line number, but **no raw HTTP client IP or query parameter**. Missing logs, dropped logs, missing EDR telemetry, and absent matches are not clean verdicts.

**Key rotation is deliberately NOT automatic.** A compromised signing key needs an out-of-band incident response / verified re-trust; do not publish a new public key inside a signed update controlled by the compromised key.
