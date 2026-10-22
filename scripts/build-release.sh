#!/usr/bin/env bash
# Builds unsigned release assets. No third-party dependencies beyond Go, tar, zip, sha256sum.
# Standard Windows/Linux/macOS binaries use the primary (current) Go toolchain.
# Windows Server 2012 R2 uses a separate Go 1.20 legacy artifact — see scripts/build-windows-legacy.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
rm -f dist/*
MODULE="github.com/Opathedane/php2shell/internal/audit"
for platform in linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64; do
  os="${platform%/*}"; arch="${platform#*/}"
  name="php2shell-${os}-${arch}"
  if [[ "$os" == "windows" ]]; then name="${name}.exe"; fi
  echo "Building ${os}/${arch} (standard)"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X ${MODULE}.BuildFlavor=standard" \
    -o "dist/$name" ./cmd/php2shell
  if [[ "$os" == "windows" ]]; then
    (cd dist && zip -q "php2shell-${os}-${arch}.zip" "$name" -j ../docs/INSTALL-FOR-CONSULTANTS.md ../docs/WINDOWS-LEGACY-2012R2.md)
  else
    (cd dist && tar -czf "php2shell-${os}-${arch}.tar.gz" "$name" -C .. docs/INSTALL-FOR-CONSULTANTS.md)
  fi
done
echo "Building windows/amd64 legacy (Go 1.20 / Server 2012 R2)"
bash scripts/build-windows-legacy.sh
(cd dist && sha256sum php2shell-* > SHA256SUMS)
echo "Wrote dist/{executables,archives,SHA256SUMS}"
