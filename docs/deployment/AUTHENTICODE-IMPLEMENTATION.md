# Authenticode signing — practical implementation plan

Windows release EXEs are **unsigned** today. Users verify **SHA256SUMS**. Signing is recommended before unrestricted public Windows download; it is **not** required to finish technical QA or controlled pilots.

Related: [DISTRIBUTION-SIGNING.md](DISTRIBUTION-SIGNING.md) (overview).

---

## 1. Goals

| Must | Must not assume |
| --- | --- |
| Sign `php2shell-windows-amd64.exe` and `php2shell-windows-legacy-amd64.exe` | Signing removes all SmartScreen warnings immediately |
| Timestamp signatures so they remain valid after cert expiry | Signing proves assessment correctness |
| Keep publishing SHA256SUMS after signing | Private keys belong in the git repo |
| Verify signature in CI before `gh release create` | One smoke on 2012 R2 = all legacy environments OK |

---

## 2. Recommended option (2026)

**Preferred for CI:** [Azure Artifact Signing](https://azure.microsoft.com/en-us/products/artifact-signing) (formerly Trusted Signing), where geo-eligibility allows.

| Plan (order of magnitude — verify current Azure pricing) | Approx. |
| --- | --- |
| Basic | ~USD **9.99**/month for up to 5,000 signatures; then ~USD 0.005 each |
| Premium | ~USD **99.99**/month for up to 100,000 signatures |

**Fallback:** OV code signing from DigiCert/Sectigo/etc. (typically low–mid hundreds USD/year; HSM/token required). EV is mainly for driver scenarios; it no longer guarantees instant SmartScreen bypass.

Expect early SmartScreen prompts until publisher reputation builds across successive signed releases.

---

## 3. Prerequisites

1. Legal entity / identity validation with Microsoft (Artifact Signing) or a CA (OV).
2. Azure subscription (if using Artifact Signing) in a supported geography.
3. GitHub Actions OIDC federation to Azure (preferred) — avoid long-lived secrets when possible.
4. Dual-control: who can approve release signing vs who can merge code.
5. Revocation / incident plan if the signing identity is compromised.

---

## 4. Integration into GitHub Actions (sketch)

Current flow ([`.github/workflows/release.yml`](../../.github/workflows/release.yml)):

1. `scripts/build-release.sh` → unsigned `dist/*` + `SHA256SUMS`
2. `gh release create` uploads artifacts for tag `vX.Y.Z` at `${GITHUB_SHA}`

**Insert after build, before publish:**

```yaml
# Illustrative — not enabled until secrets/OIDC exist
- name: Sign Windows executables
  env:
    AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
    AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
    AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
  run: |
    set -euo pipefail
    # 1) Az login via OIDC (azure/login action)
    # 2) Invoke Trusted Signing / SignTool for:
    #      dist/php2shell-windows-amd64.exe
    #      dist/php2shell-windows-legacy-amd64.exe
    # 3) Re-pack zip archives that contain those EXEs
    # 4) Regenerate dist/SHA256SUMS
    # 5) osslsigncode verify / SignTool verify on each EXE
```

**Validation (Windows runner or wine+osslsigncode on Linux):**

```powershell
Get-AuthenticodeSignature .\php2shell-windows-amd64.exe | Format-List Status, SignerCertificate
# Status should be Valid
Get-FileHash .\php2shell-windows-amd64.exe -Algorithm SHA256
```

**Release create** must upload **only** signed EXEs/archives and the regenerated `SHA256SUMS`.  
`--target "${GITHUB_SHA}"` already binds the GitHub Release to the reviewed commit — keep that.

Do **not** enable this job until identity validation completes; leave unsigned pilots on the current workflow.

---

## 5. User-facing verification (unchanged + signing)

1. Download EXE + `SHA256SUMS` from the GitHub Release matching the tag.
2. `Get-FileHash … -Algorithm SHA256` — must match the SUMS line.
3. After signing is live: `Get-AuthenticodeSignature` → `Valid`, publisher name matches your org.

---

## 6. Cost / ops summary

| Item | Expect |
| --- | --- |
| Artifact Signing Basic | ~$10/month + identity setup time |
| Traditional OV | ~$150–500+/year + token/HSM logistics |
| Ops | OIDC to Azure; release dual-control; timestamping; revoke plan |
| SmartScreen | Reputation builds over successive signed releases |

---

## 7. Decision for v2.7.2 vs v2.8.0

| Release | Signing |
| --- | --- |
| **v2.7.2** (stabilization) | May ship **unsigned** to pilots with SHA256 + clear disclosure |
| **v2.8.0** (public Windows milestone) | Prefer signed standard + legacy EXEs |
