# Security policy

**Obtain authorization before scanning production systems.** PHP2Shell is a read-only assessment aid, not a penetration-test tool, and does not contain exploit code. It cannot alone certify that a host is patched or uncompromised.

Do not attach customer reports, access logs, network architecture, credentials or production endpoint names to public GitHub issues. Disclose vulnerabilities privately to the maintainer. Contact the maintainer privately at **jesma@itm8.com** for responsible disclosure. Do not send customer evidence or credentials via ordinary email. No automatic data transfer takes place.

The scanner deliberately refuses to open nonregular/symlinked input files based on pathname inspection; on a live adversary-controlled filesystem, pathname TOCTOU races are still possible (no filesystem snapshot or OS-specific openat2 hardening). Run with minimum permissions, with protected reports directory, or against an offline forensic copy. It does not prevent tampering with logs or package databases on a compromised host.

The local Docker socket is inherently privileged even for read-only requests; `--docker` is strictly opt-in. There is no signature, notarization or remotely attested chain of custody for binaries or reports. HTML reports escape dynamic content and use restrictive local CSP; CSV formula injection is mitigated, but handle all exported files as untrusted inputs. Report files are mode 0600 on systems honoring POSIX permissions; Windows output privacy depends on the parent directory ACL.

See `docs/RELEASE-CHECKLIST.md` before publication.
