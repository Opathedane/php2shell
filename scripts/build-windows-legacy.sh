#!/usr/bin/env bash
# Builds php2shell-windows-legacy-amd64.exe with Go 1.20.14 for Windows Server 2012 R2.
# Does NOT change the primary toolchain (CI/release still use current Go for standard assets).
# Go 1.20 is end-of-support — see docs/WINDOWS-LEGACY-2012R2.md before shipping.
set -euo pipefail
cd "$(dirname "$0")/.."

LEGACY_GO_VERSION="${LEGACY_GO_VERSION:-1.20.14}"
OUT_DIR="${OUT_DIR:-dist}"
CACHE_ROOT="${PHP2SHELL_LEGACY_GO_CACHE:-${TMPDIR:-/tmp}/php2shell-go-legacy}"
MODULE="github.com/Opathedane/php2shell/internal/audit"

mkdir -p "$OUT_DIR" "$CACHE_ROOT"

host_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
host_arch="$(uname -m)"
case "$host_arch" in
  x86_64|amd64) host_arch=amd64 ;;
  aarch64|arm64) host_arch=arm64 ;;
  *) echo "ERROR: unsupported host arch $host_arch for fetching legacy Go" >&2; exit 1 ;;
esac
case "$host_os" in
  linux) go_os=linux ;;
  darwin) go_os=darwin ;;
  mingw*|msys*|cygwin*) go_os=windows ;;
  *) echo "ERROR: unsupported host OS $host_os" >&2; exit 1 ;;
esac

toolchain_dir="$CACHE_ROOT/go${LEGACY_GO_VERSION}.${go_os}-${host_arch}"
go_bin="$toolchain_dir/go/bin/go"
if [[ "$go_os" == "windows" ]]; then
  go_bin="$toolchain_dir/go/bin/go.exe"
fi

if [[ ! -x "$go_bin" ]]; then
  archive="go${LEGACY_GO_VERSION}.${go_os}-${host_arch}.tar.gz"
  if [[ "$go_os" == "windows" ]]; then
    archive="go${LEGACY_GO_VERSION}.windows-${host_arch}.zip"
  fi
  url="https://go.dev/dl/${archive}"
  echo "Fetching Go ${LEGACY_GO_VERSION} from ${url}"
  tmp="$CACHE_ROOT/download-$$"
  mkdir -p "$tmp"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmp/$archive"
  else
    wget -qO "$tmp/$archive" "$url"
  fi
  rm -rf "$toolchain_dir"
  mkdir -p "$toolchain_dir"
  if [[ "$archive" == *.zip ]]; then
    unzip -q "$tmp/$archive" -d "$toolchain_dir"
  else
    tar -C "$toolchain_dir" -xzf "$tmp/$archive"
  fi
  rm -rf "$tmp"
fi

echo "Using $($go_bin version)"

# Go 1.20 rejects go.mod language versions newer than itself. Pin a temporary
# go 1.20 directive for this build only; restore afterward.
gomod_backup="$(mktemp)"
cp go.mod "$gomod_backup"
cleanup() { cp "$gomod_backup" go.mod; rm -f "$gomod_backup"; }
trap cleanup EXIT

# Replace first "go N.N" / "go N.N.N" line with go 1.20
if grep -qE '^go [0-9]+\.[0-9]+(\.[0-9]+)?$' go.mod; then
  # portable in-place edit without relying on GNU sed -i
  awk 'BEGIN{done=0} /^go [0-9]+\.[0-9]+(\.[0-9]+)?$/ && !done {print "go 1.20"; done=1; next} {print}' go.mod > go.mod.legacy
  mv go.mod.legacy go.mod
else
  echo "ERROR: could not locate go directive in go.mod" >&2
  exit 1
fi

name="php2shell-windows-legacy-amd64.exe"
echo "Building ${name} (GOOS=windows GOARCH=amd64 CGO_ENABLED=0, BuildFlavor=legacy)"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  "$go_bin" build -trimpath \
  -ldflags="-s -w -X ${MODULE}.BuildFlavor=legacy" \
  -o "${OUT_DIR}/${name}" ./cmd/php2shell

echo "Wrote ${OUT_DIR}/${name}"
(cd "$OUT_DIR" && zip -q "php2shell-windows-legacy-amd64.zip" "$name" -j ../docs/INSTALL-FOR-CONSULTANTS.md ../docs/WINDOWS-LEGACY-2012R2.md)
echo "Wrote ${OUT_DIR}/php2shell-windows-legacy-amd64.zip"
