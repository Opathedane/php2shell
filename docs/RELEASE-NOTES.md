# PHP2Shell 2.3.1

Maintenance release focused on Windows PHP version detection and reporting accuracy. Builds on the public **v2.3.0** HTML-only assessment scanner. Does **not** overwrite v2.3.0 release assets — publish only as a new tag `v2.3.1`.

## Downloads

Standalone binaries (no Python, PHP, or Go required on the target host):

- `php2shell-windows-amd64.zip`
- `php2shell-linux-amd64.tar.gz`
- `php2shell-linux-arm64.tar.gz`
- `php2shell-darwin-amd64.tar.gz` / `php2shell-darwin-arm64.tar.gz` (developer convenience builds)

Verify checksums in `SHA256SUMS`. Release binaries are **not code-signed**.

### Verify download integrity

```bash
# Linux / macOS — from the directory containing the binary and SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

```powershell
Get-FileHash .\php2shell-windows-amd64.exe -Algorithm SHA256
```

Confirm the release is published by the `Opathedane/php2shell` repository and that the tag matches the embedded `php2shell version` string (`2.3.1`).

## What changed in 2.3.1

Real-world Windows 11 / AppData installs (official `Programs\PHP` layout) were discovered as binaries but reported **“no version marker found”**, producing zero comparable versions and zero patch assessments even when `php -v` showed 8.4.24.

### PE resource improvements

- Directed reads of the PE `.rsrc` section recover `FixedFileInfo` version metadata for large `php.exe` / `php-cgi.exe` builds where head/tail string windows miss the resource directory.
- PE parsing is portable (same logic on all CI platforms) and remains **read-only** — binaries are never executed.

### Confidence-aware path inference

- When authoritative binary metadata is absent, the scanner may infer an exact `x.y.z` version from installer path segments (for example `...\Programs\PHP\8.4.24\nts\x64\php.exe`).
- Inferred observations use evidence type `binary_path_inferred_version` and are labelled **PATH-INFERRED** with explicit **MEDIUM** confidence in HTML and CSV patch assessments.
- Verified embedded-string / PE observations remain `binary_static_version` with **HIGH** (or **MEDIUM** if inspection was partial) confidence.
- Path inference never invents a version from an unqualified `current` segment alone.

### Alias handling (`current` vs versioned trees)

- Paths under `Programs\PHP\current` are compared to versioned trees using `SameFile` or matching passive content fingerprints.
- Only when corroborated are they grouped as one install and allowed to inherit a labelled path-inferred version from the versioned tree.
- Non-matching content keeps separate records and emits a warning — identity is never assumed.

### Reporting and regression

- Patch assessments include confidence and limitations consistently in the HTML report and in `EncodeCSV` (legacy/test / rollup helpers).
- Install grouping prefers a single corroborated directory for `php.exe` + `php-cgi.exe`.
- Regression coverage reproduces the TestVM v2.3.0 report scenario (four marker-free binaries under `current` and `8.4.24\nts\x64` → version **8.4.24**, below upstream **8.4.27**, update review required) without executing PHP or claiming CLI as the active web runtime.

## Unchanged product posture

- HTML-only `scan` output; no customer data upload; no automatic remediation.
- Does **not** attest which PHP runtime serves HTTP.
- Does **not** verify vendor/LTS security backports by advisory ID.
- Does **not** prove absence of compromise when no indicators match.
- Does **not** execute discovered PHP binaries.

## Quick start

```bash
# Linux
./php2shell-linux-amd64 scan --quiet --output-dir /var/tmp/php2shell

# Windows (PowerShell)
.\php2shell-windows-amd64.exe scan --quiet --output-dir C:\ProgramData\PHP2Shell\Reports
```

Open the generated HTML report locally. See [INSTALL-FOR-CONSULTANTS.md](INSTALL-FOR-CONSULTANTS.md) and [ADVANCED-USAGE.md](ADVANCED-USAGE.md).

## Supported platforms (tested in CI)

- Linux (ubuntu-24.04 runners)
- Windows (windows-latest runners)
- macOS Intel (macos-15-intel runners)

macOS ARM64 binaries are built for convenience; CI currently validates darwin/amd64 rather than native arm64 runners.

---

## Prior release: 2.3.0

First official public release (HTML-only assessment report, upstream fix thresholds for the 21 October 2026 advisories, unattended `--quiet` / `--output-dir` / exit codes). See git tag `v2.3.0` and [CHANGELOG.md](../CHANGELOG.md).
