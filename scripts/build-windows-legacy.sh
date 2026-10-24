#!/usr/bin/env bash
# Builds php2shell-windows-legacy-amd64.exe with Go 1.20.14 for Windows Server 2012 R2.
# Does NOT change the primary toolchain (CI/release still use current Go for standard assets).
# Go 1.20 is end-of-support — see docs/WINDOWS-LEGACY-2012R2.md before shipping.
#
# Supply chain: every downloaded (and cached) Go archive is verified against pinned
# SHA-256 digests published by go.dev for go1.20.14 (include=all JSON, 2026-10-24).
set -euo pipefail
cd "$(dirname "$0")/.."

LEGACY_GO_VERSION="${LEGACY_GO_VERSION:-1.20.14}"
OUT_DIR="${OUT_DIR:-dist}"
CACHE_ROOT="${PHP2SHELL_LEGACY_GO_CACHE:-${TMPDIR:-/tmp}/php2shell-go-legacy}"
MODULE="github.com/Opathedane/php2shell/internal/audit"

# Pinned SHA-256 for go1.20.14 official archives (go.dev/dl/?mode=json&include=all).
expected_legacy_go_sha256() {
  case "$1" in
    go1.20.14.darwin-amd64.tar.gz)  echo 754363489e2244e72cb49b4ec6ddfd6a2c60b0700f8c4876e11befb1913b11c5 ;;
    go1.20.14.darwin-arm64.tar.gz)  echo 6da3f76164b215053daf730a9b8f1d673dbbaa4c61031374a6744b75cb728641 ;;
    go1.20.14.linux-amd64.tar.gz)   echo ff445e48af27f93f66bd949ae060d97991c83e11289009d311f25426258f9c44 ;;
    go1.20.14.linux-arm64.tar.gz)   echo 2096507509a98782850d1f0669786c09727053e9fe3c92b03c0d96f48700282b ;;
    go1.20.14.windows-amd64.zip)    echo 0e0d0190406ead891d94ecf00f961bb5cfa15ddd47499d2649f12eee80aee110 ;;
    go1.20.14.windows-arm64.zip)    echo 67dfb9de6c4775d3deffb3bf87c204f22b2d0ddebebc6eec5917a69e27af7370 ;;
    *) return 1 ;;
  esac
}

sha256_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print $1}'
  else
    echo "ERROR: need sha256sum or shasum to verify legacy Go toolchain" >&2
    exit 1
  fi
}

verify_archive_sha256() {
  local archive_path="$1" archive_name="$2"
  local want got
  want="$(expected_legacy_go_sha256 "$archive_name")" || {
    echo "ERROR: no pinned SHA-256 for $archive_name (refusing unverified legacy toolchain)" >&2
    exit 1
  }
  got="$(sha256_file "$archive_path")"
  if [[ "$got" != "$want" ]]; then
    echo "ERROR: SHA-256 mismatch for $archive_name" >&2
    echo "  expected: $want" >&2
    echo "  got:      $got" >&2
    exit 1
  fi
  echo "Verified $archive_name SHA-256"
}

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

if [[ "$LEGACY_GO_VERSION" != "1.20.14" ]]; then
  echo "ERROR: only Go 1.20.14 is pinned for checksum verification (got LEGACY_GO_VERSION=$LEGACY_GO_VERSION)" >&2
  exit 1
fi

archive="go${LEGACY_GO_VERSION}.${go_os}-${host_arch}.tar.gz"
if [[ "$go_os" == "windows" ]]; then
  archive="go${LEGACY_GO_VERSION}.windows-${host_arch}.zip"
fi
# Fail early if this host combo is not in the pin table.
expected_legacy_go_sha256 "$archive" >/dev/null

toolchain_dir="$CACHE_ROOT/go${LEGACY_GO_VERSION}.${go_os}-${host_arch}"
go_bin="$toolchain_dir/go/bin/go"
if [[ "$go_os" == "windows" ]]; then
  go_bin="$toolchain_dir/go/bin/go.exe"
fi
archive_cache="$CACHE_ROOT/$archive"

# Always verify the archive (download or cache) before trusting an extracted toolchain.
if [[ ! -f "$archive_cache" ]]; then
  # Prefer dl.google.com (same official bits); go.dev occasionally returns HTTP 403 to scripted clients.
  urls=(
    "https://dl.google.com/go/${archive}"
    "https://go.dev/dl/${archive}"
  )
  tmp="$CACHE_ROOT/download-$$"
  mkdir -p "$tmp"
  downloaded=0
  for url in "${urls[@]}"; do
    echo "Fetching Go ${LEGACY_GO_VERSION} from ${url}"
    if command -v curl >/dev/null 2>&1; then
      if curl -fsSL -A "php2shell-legacy-build/1.0 (+https://github.com/Opathedane/php2shell)" \
          "$url" -o "$tmp/$archive"; then
        downloaded=1
        break
      fi
    else
      if wget -qO "$tmp/$archive" "$url"; then
        downloaded=1
        break
      fi
    fi
    rm -f "$tmp/$archive"
  done
  if [[ "$downloaded" -ne 1 ]]; then
    echo "ERROR: failed to download $archive from official mirrors" >&2
    rm -rf "$tmp"
    exit 1
  fi
  verify_archive_sha256 "$tmp/$archive" "$archive"
  mv "$tmp/$archive" "$archive_cache"
  rm -rf "$tmp"
else
  echo "Using cached archive $archive_cache"
  verify_archive_sha256 "$archive_cache" "$archive"
fi

if [[ ! -x "$go_bin" ]]; then
  rm -rf "$toolchain_dir"
  mkdir -p "$toolchain_dir"
  if [[ "$archive" == *.zip ]]; then
    unzip -q "$archive_cache" -d "$toolchain_dir"
  else
    tar -C "$toolchain_dir" -xzf "$archive_cache"
  fi
fi

echo "Using $($go_bin version)"
# Stamp that this extraction came from a verified archive (best-effort cache hygiene).
echo "$archive $(expected_legacy_go_sha256 "$archive")" >"$toolchain_dir/.php2shell-go-sha256"
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
