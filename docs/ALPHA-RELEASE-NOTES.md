# PHP2Shell v2.1.0-alpha.2 – standalone pre-release

**Development and assessment preview – NOT production-approved and not a CVE-specific clearance tool.**

Download a matching Windows/Linux executable (or ZIP/tar.gz with instructions). No Python/Go required to run.

- Passive local PHP inventory; partial IIS static configuration and limited Windows process discovery
- Bounded access log coverage on Apache/nginx and IIS W3C files when explicitly requested
- Repository metadata review and limited file hash IOC support
- Optional Ed25519-signed, data-only IOC pack updates from your trusted GitHub repository (not enabled by default)
- Local HTML/JSON/CSV evidence reports and MSSP rollup

**Major limitations:** No verified PHP2Shell-specific IOC content or official vendor runtime fix detection included. Scan cannot establish that a server is patched, exploitable, compromised or clean. Windows Server/IIS production validation, vendor-backport verification, and Authenticode signing are outstanding. All binaries are unsigned. Never interpret missing results as a negative finding. Review `README.md` and `SECURITY.md`.

**Release authenticity:** Verify against SHA256SUMS and a separately trusted channel. This release does not include a signed binary or an initial pinned IOC public key.
