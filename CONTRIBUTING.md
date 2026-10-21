# Contributing to PHP2Shell

Thanks for helping improve PHP2Shell. This project is a **read-only** PHP discovery and patch-review aid. Contributions must preserve its safety and accuracy guarantees.

## Before you start

- Obtain authorization before scanning any system that is not yours.
- Do not submit exploit code, webshells, or offensive payloads.
- Do not commit customer reports, credentials, private keys, or signing private keys.
- Do not claim a host is “safe”, “patched”, or “clean” based solely on scanner output.

## Development

```bash
go test ./...
go vet ./...
go build -trimpath -o php2shell ./cmd/php2shell
```

CI runs on Linux, Windows, and macOS Intel for pull requests to `main`.

## Pull requests

1. Branch from the latest `main`.
2. Keep changes focused; include tests for behaviour changes.
3. Update `CHANGELOG.md` under Unreleased when user-visible behaviour changes.
4. Do not bump release tags or overwrite published GitHub Release assets in a PR.

## Reporting bugs

Use the GitHub issue templates. Redact customer hostnames, paths, and reports. See `SECURITY.md` for vulnerability disclosure.

## Licensing

The repository currently has **no approved open-source license** (`LICENSE.proposed` is a draft). Do not assume Apache-2.0 (or any other license) applies until the maintainer commits an approved `LICENSE`. See `docs/LICENSING.md`.
