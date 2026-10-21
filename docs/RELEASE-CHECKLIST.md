# Release gates – must be completed before PUBLIC production release

- [x] Remove external runtime dependency via native Go binaries.
- [x] No execution of discovered PHP code/binaries or external shell commands.
- [x] File output exclusive/no overwrite; private modes where supported.
- [x] HTML dynamic text escaped; CSV formula-like values escaped.
- [x] Explicit coverage/limitations; no `CLEAN`/`SAFE` conclusion.
- [x] Source tests, basic Linux smoke, cross-compilation.
- [ ] Independent secure-code review and adversarial tests (including filesystem races and Windows ACL).
- [ ] Linux distros and PHP SAPI integration matrix; enterprise/vendor PHP builds.
- [ ] Windows Server/IIS PHP effective runtime coverage and integration tests.
- [ ] macOS/ARM coverage and signed/notarized distributables.
- [ ] PHP official advisory-specific affected/fixed/version/backport logic, tested on affected and patched workloads.
- [ ] Compromise detector with verified indicators, sensitivity notes, false negatives and analyst escalation.
- [ ] Scan performance and cap tests on very large roots, logs, containers and highly restricted hosts.
- [ ] Version checks and detached release checksum/signatures published in an approved secure process.
- [ ] Source provenance, legal OSS license, itm8 branding/organizational approval and private security contact.
- [ ] Harden GitHub Actions action pins and permissions; release signing and supply-chain review; maintainer ownership. The current manual workflow only uploads unsigned build artifacts and does not publish a GitHub Release.
- [ ] Approved customer instructions, readme peer review and incident-response evidence-handling guidance.
