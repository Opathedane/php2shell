# Windows Authenticode signing recommendation

PHP2Shell Windows release assets are currently **unsigned**. Users verify downloads with **SHA256SUMS** published beside each GitHub Release.

Signing is **not** required to finish technical QA, but it is a **P0 usability/trust** item for broad Windows distribution (SmartScreen, AppLocker/WDAC friendliness).

**Implementation plan (costs, GHA integration):** [AUTHENTICODE-IMPLEMENTATION.md](AUTHENTICODE-IMPLEMENTATION.md).

---

## 1. What signing does and does not do

| Signing provides | Signing does **not** guarantee |
| --- | --- |
| Publisher identity for Authenticode | Immediate SmartScreen reputation (new certs still warn until reputation builds) |
| Integrity of the PE after download | That the assessment conclusions are correct |
| Better fit for enterprise allowlisting | Compatibility with Server 2012 R2 without also shipping the legacy build |

Always keep publishing **SHA256SUMS** and document verification steps (see README).

---

## 2. Practical options

| Option | Pros | Cons |
| --- | --- | --- |
| **OV Authenticode certificate** (org-validated) | Lower cost; common for ISVs | More SmartScreen friction early |
| **EV Authenticode certificate** | Faster reputation; hardware token | Higher cost; token logistics |
| **Cloud signing** (Azure Trusted Signing / similar) | No USB token on laptops; CI-friendly | Cloud dependency; account setup |
| **Leave unsigned** + strong SHA256 + internal catalog signing | Fine for closed enterprise pilots | Poor for anonymous public download |

---

## 3. Suggested release workflow integration

1. `scripts/build-release.sh` produces unsigned `dist/*.exe` + archives + `SHA256SUMS`.
2. Signing job (maintainer-controlled secrets) signs:
   - `php2shell-windows-amd64.exe`
   - `php2shell-windows-legacy-amd64.exe`
3. Re-zip archives; regenerate `SHA256SUMS`.
4. `gh release create` uploads signed artifacts only.
5. CI verifies signature: `Get-AuthenticodeSignature` → `Valid` (or `osslsigncode verify` on Linux runners).

Never store the private key in the public repo. Prefer OIDC → cloud HSM/trusted signing over long-lived secrets in GitHub when possible.

---

## 4. Validation commands (Windows)

```powershell
Get-AuthenticodeSignature .\php2shell-windows-amd64.exe | Format-List *
# Status should be Valid for production releases
```

```powershell
Get-FileHash .\php2shell-windows-amd64.exe -Algorithm SHA256
# Compare to SHA256SUMS line for that file
```

---

## 5. Cost & operations (order-of-magnitude)

| Item | Typical |
| --- | --- |
| OV cert (1 year) | Low hundreds USD |
| EV cert (1 year) | Higher hundreds–low thousands USD + token |
| Azure Trusted Signing | Pay-as-you-go / subscription — check current Microsoft pricing |
| Ops | Dual control for release signing; revoke plan if key compromised |

---

## 6. Recommendation for PHP2Shell

1. **Short term (pilots):** unsigned + SHA256SUMS + internal software deployment catalog signing if the customer requires it.
2. **Before unrestricted public Windows download:** OV or Trusted Signing on **both** standard and legacy EXEs; document SmartScreen expectations.
3. Do **not** delay merging technical QA solely for certificate purchase — track signing as an explicit P0 distribution gate.
