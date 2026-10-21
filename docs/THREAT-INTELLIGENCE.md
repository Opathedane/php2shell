# Threat intelligence and detection policy

## Evidence hierarchy

1. **Authoritative**: official php.net release notes/patch commits and distro/vendor backport notices; only source for fixed version and affected version rule definitions.
2. **Corroborated**: verified independent technical analysis and reproduceable, benign lab experiments; use to design controls, but not to certify systems safe unless exact preconditions and false negatives are understood.
3. **Context**: VirusTotal Internet Scanning data, observed PHP version banners, attack surface or open ports; prioritisation only, not CVE exploitability or proof of compromise.
4. **Unverified**: social media PoC screenshots, leaked claims or one-off indicators; **exclude from detection rules** pending validation.

## Specific constraints

- The user-requested unverified X PoC and its technical assertions are **not used** in scanner signatures or risk classification.
- PHP version hidden from HTTP does not mean PHP absent (VirusTotal survey 21 Oct 2026).
- `session.upload_progress.enabled=Off` is not an independently proven full mitigation. `expose_php=Off` only hides a banner.
- Edge WAF configuration can reduce risk but may be bypassed when the origin is reachable; never mark patched because of WAF.
- A PHP build can be vendor-patched without changing upstream minor/patch representation; correlate build IDs and package vendor security notice.
- An existing compromise can survive patching; historical investigation is a separate workflow.
- CLI PHP version is not evidence of FPM/mod_php/CGI version; repo PHP version is not a deployment assertion; Docker tag is not image attestation.
- Threat intelligence from VirusTotal can inform priorities via opt-in analyst workflows but does not require uploading any customer data from scanner.

## Planned validated features (not delivered)

- Authoritative version/advisory rule bundle signed by the maintainer, no unattended auto-update.
- Real serving-runtime evidence per SAPI, IIS and popular vendor hosting panels, container layers, OS package backports.
- Verified compromise indicators with sensitivity/false-negative caveats; log-retention and EDR process lineage coverage.
- Separate signed offline evidence bundles and customer-safe transfer, tenant-bound ingestion, identity verification, evidence chain of custody.
- Authorized perimeter origin-versus-WAF check as a separate consenting module (no network requests in default scanner).

Reference: https://blog.virustotal.com/2026/10/sizing-php-exposure-window-for-cve-2026.html
