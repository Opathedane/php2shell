# Release gates — 2.1.0-alpha.2

## Completed in this repository

- [x] Native Go builds; no Python or PHP interpreter required on scanning host.
- [x] Non-execution of customer PHP / shell code; scanner has only local bounded read operations by default.
- [x] Report outputs exclusive and owner-only on POSIX; HTML escaped, CSV formula escaped.
- [x] Windows process snapshot and IIS FastCGI/handler static XML parser, plus IIS W3C request log summarization.
- [x] Opt-in GitHub raw HTTPS downloads of inert Ed25519-signed rules, with initially pinned public key, expiry enforcement and monotonic sequence validation.
- [x] Unit tests for signature tamper/wrong key, expiry, rollback, HTTP/IIS privacy, SHA-256 file matches and existing output risks.
- [x] Independent coverage states; no false `SAFE`, `PATCHED`, `NOT_VULNERABLE`, or `CLEAN` result.
- [x] GitHub Actions configured to run tests on Linux, Windows and macOS after push.

## MUST complete before public customer-facing production release

- [ ] Observe actual CI results on GitHub-hosted Windows and macOS runners; locally built Windows binary has not run on Windows yet.
- [ ] Real Windows Server 2019/2022/2025/IIS 10 integration tests with site handler inheritance, URL Rewrite, ACL/restricted account, Win32 processes, app pools and log rotation.
- [ ] Live Linux tests on Apache/mod_php, nginx/PHP-FPM, LiteSpeed/LSAPI, containers, dpkg/apk/RPM enterprise vendor builds.
- [ ] Patch matrix based on OFFICIAL PHP advisories for CVE-2026-109618 and CVE-2026-109619, checking actively serving SAPI, packaging and vendor backports.
- [ ] Publish reviewed verified IOC bundle signed by an org-controlled Ed25519 key (private key HSM/offline; public key distributed independently).
- [ ] Add more incident-hunting evidence sources (EDR, historical process lineage, webshell verification, filesystem persistence), independently validate false positive/negative behavior.
- [ ] Independent security code review and adversarial tests incl. symlink/TOCTOU races, Windows ACL protections, input caps and performance.
- [ ] Windows Authenticode code signing and publisher trust, approved release checksums and platform signing; optional macOS notarization.
- [ ] GitHub Actions pin actions to reviewed immutable digests; protect branches/tags, prevent supply-chain tampering, review dependencies/release signing.
- [ ] Obtain approved open-source license/owner attribution, legal approval for third-party branding and public release, maintainer/security contact and support terms.
- [ ] End-user instructions and validation on customer environments. Confirm no customer data is included in source or build artifacts.

**DO NOT present this alpha as a product that establishes PHP2Shell absence, successful patch deployment, or lack of compromise.**

## v2.2.0-alpha.2 official advisory release gate

- [ ] Review PHP upstream fix thresholds (8.2.35, 8.3.36, 8.4.27, 8.5.12) against primary PHP advisories.
- [ ] Review version comparator fixtures, vendor-backport qualifications and runtime evidence limitations.
- [ ] Verify new report sections (HTML / JSON / CSV / MSSP rollup) across Windows and Linux.
- [ ] Test native Windows Server IIS/FastCGI and Linux Apache/FPM against both below-fix and fixed versions.
- [ ] Confirm documented sign-off for customer rollout; this remains an unsigned development alpha until approved.
- [ ] Upload all revised source files through GitHub Desktop, including hidden `.github/workflows` files.
- [ ] Run CI and ensure *all three* jobs succeed.
- [ ] Publish an entirely new pre-release tag `v2.2.0-alpha.2` (never overwrite v2.1 binaries).
- [ ] Do not claim full vulnerability clearance, verified vendor backports or compromise clearance.
