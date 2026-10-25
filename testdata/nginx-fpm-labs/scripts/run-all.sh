#!/usr/bin/env bash
# Run LIVE_DOCKER nginx/PHP-FPM labs when Docker is available.
# If Docker is missing, record an honest skip (exit 0) — never treat fixtures as a live pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
LAB="$ROOT/testdata/nginx-fpm-labs"
RESULTS="$LAB/results"
BIN_DIR="$LAB/bin"
BIN="$BIN_DIR/php2shell-linux-amd64"

mkdir -p "$RESULTS" "$BIN_DIR"

if ! command -v docker >/dev/null 2>&1; then
  cat > "$RESULTS/SKIPPED-NO-DOCKER.txt" << EOF
LIVE_DOCKER labs were not executed.
Reason: docker command not found on this host.
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
CONFIG_TREE_OFFLINE coverage remains available via:
  go test ./internal/audit/ -run TestNginxFPMLabConfigTreesMatchGroundTruth
EOF
  echo "SKIP: Docker unavailable — wrote $RESULTS/SKIPPED-NO-DOCKER.txt" >&2
  exit 0
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "SKIP: docker compose unavailable" >&2
  echo "docker compose unavailable" > "$RESULTS/SKIPPED-NO-DOCKER.txt"
  exit 0
fi

echo "Building linux php2shell binary for lab scan containers..."
mkdir -p "$BIN_DIR"
( cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$BIN" ./cmd/php2shell )
chmod +x "$BIN"

PASS=0
FAIL=0
for scenario in "$LAB"/scenarios/*; do
  [ -d "$scenario" ] || continue
  id="$(basename "$scenario")"
  echo "=== LIVE lab: $id ==="
  mkdir -p "$RESULTS/$id"
  rm -f "$RESULTS/$id"/* 2>/dev/null || true
  # Restore secret.conf perms if previous run left it mode 000
  if [ -f "$scenario/fpm/secret.conf" ]; then
    chmod 644 "$scenario/fpm/secret.conf" || true
  fi
  (
    cd "$scenario"
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
    docker compose run --rm --no-deps scan
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  )
  if "$LAB/scripts/assert-live-results.sh" "$id"; then
    echo "PASS $id"
    PASS=$((PASS+1))
  else
    echo "FAIL $id" >&2
    FAIL=$((FAIL+1))
  fi
done

echo "LIVE labs: pass=$PASS fail=$FAIL"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
