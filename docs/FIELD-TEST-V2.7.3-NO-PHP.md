# Field retest plan — v2.7.3 no-PHP (Windows)

Use **after** PR #28 is approved and merged. Do **not** treat this as a published release.

## Build a local test binary (post-merge)

```bash
git checkout main && git pull
# confirm Version prints 2.7.3
grep 'const Version' internal/audit/model.go

GOOS=windows GOARCH=amd64 go build -o dist/php2shell-windows-amd64-test.exe ./cmd/php2shell
# optional SHA for transfer integrity
shasum -a 256 dist/php2shell-windows-amd64-test.exe
```

Copy the EXE to the same Windows machine used for the v2.7.2 no-PHP field test.

## Run

```powershell
.\php2shell-windows-amd64-test.exe version
.\php2shell-windows-amd64-test.exe scan --html report.html --csv report.csv --status-json report.status.json
```

## Expected results

| Check | Expect |
| --- | --- |
| Console / HTML PHP discovery | **No PHP detected within scan coverage** (when applicable inventory completed) |
| Installations | **0** |
| Patch assessment (human) | **No PHP-specific patch assessment** — not a flood of upstream patch/remediation steps |
| Linux inventory noise | **No** dpkg/apk/RPM missing-coverage warnings on Windows |
| Clearance language | Must **not** say the host is PHP-free, patched, or uncompromised |
| Exit / status JSON | Successful complete inventory → exit **0** / not `SCAN_INCOMPLETE` solely due to packages `NOT_SUPPORTED` |
| Incomplete inventory | If PATH/IIS/process checks fail → **inventory incomplete**, gaps listed, not “no PHP within coverage” |

## After field PASS

Proceed with stable **v2.7.3** publish only with explicit approval: finalize `docs/releases/v2.7.3.md` (remove draft banner), move CHANGELOG to `## v2.7.3 —`, update “latest public” docs, then tag `v2.7.3` (never rewrite `v2.7.2`).
