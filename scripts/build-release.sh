#!/usr/bin/env bash
# Builds unsigned preview assets. No third-party dependencies beyond Go, tar, zip, sha256sum.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
rm -f dist/*
for platform in linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64; do
  os="${platform%/*}"; arch="${platform#*/}"
  name="php2shell-${os}-${arch}"
  if [[ "$os" == "windows" ]]; then name="${name}.exe"; fi
  echo "Building ${os}/${arch}"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -buildid=' -o "dist/$name" ./cmd/php2shell
  if [[ "$os" == "windows" ]]; then
    (cd dist && zip -q "php2shell-${os}-${arch}.zip" "$name" -j ../docs/INSTALL-FOR-CONSULTANTS.md)
  else
    (cd dist && tar -czf "php2shell-${os}-${arch}.tar.gz" "$name" -C .. docs/INSTALL-FOR-CONSULTANTS.md)
  fi
done
(cd dist && sha256sum php2shell-* > SHA256SUMS)
echo "Wrote dist/{executables,archives,SHA256SUMS}"
