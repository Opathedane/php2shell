#!/usr/bin/env bash
# LIVE_DOCKER nginx/PHP-FPM labs.
# Locally without Docker: exit 0 + SKIPPED file (honest skip).
# CI / PHP2SHELL_LABS_REQUIRE_LIVE=1: Docker required; any skip or fail => exit 1.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
LAB="$ROOT/testdata/nginx-fpm-labs"
RESULTS="$LAB/results"
BIN_DIR="$LAB/bin"
BIN="$BIN_DIR/php2shell-linux-amd64"
SUMMARY_JSON="$RESULTS/summary.json"
SUMMARY_MD="$RESULTS/SUMMARY.md"
IMAGES_TXT="$RESULTS/image-versions.txt"

REQUIRE_LIVE=0
if [[ "${PHP2SHELL_LABS_REQUIRE_LIVE:-}" == "1" || "${GITHUB_ACTIONS:-}" == "true" ]]; then
  REQUIRE_LIVE=1
fi

mkdir -p "$RESULTS" "$BIN_DIR"
rm -f "$RESULTS/SKIPPED-NO-DOCKER.txt" "$SUMMARY_JSON" "$SUMMARY_MD" "$IMAGES_TXT"

fail_or_skip_no_docker() {
  local reason="$1"
  cat > "$RESULTS/SKIPPED-NO-DOCKER.txt" << EOF
LIVE_DOCKER labs were not executed.
Reason: $reason
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
REQUIRE_LIVE=$REQUIRE_LIVE
CONFIG_TREE_OFFLINE remains: go test ./internal/audit/ -run TestNginxFPMLabConfigTreesMatchGroundTruth
EOF
  if [[ "$REQUIRE_LIVE" == "1" ]]; then
    echo "FAIL: LIVE_DOCKER required but unavailable ($reason)" >&2
    echo '{"live_docker":"FAIL","reason":"'"$reason"'"}' > "$SUMMARY_JSON"
    exit 1
  fi
  echo "SKIP: Docker unavailable — wrote $RESULTS/SKIPPED-NO-DOCKER.txt" >&2
  echo '{"live_docker":"SKIP","reason":"'"$reason"'"}' > "$SUMMARY_JSON"
  exit 0
}

command -v docker >/dev/null 2>&1 || fail_or_skip_no_docker "docker command not found"
docker compose version >/dev/null 2>&1 || fail_or_skip_no_docker "docker compose unavailable"

echo "Building linux php2shell binary for in-container scans..."
( cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BIN" ./cmd/php2shell )
chmod +x "$BIN"
test -s "$BIN"

# Pin/record image identities used by labs (pull + inspect).
IMAGES=(
  debian:bookworm-slim
  php:8.3-fpm-bookworm
  php:8.3-cli-bookworm
  nginx:1.27-bookworm
)
: > "$IMAGES_TXT"
for img in "${IMAGES[@]}"; do
  docker pull "$img" >/dev/null
  docker image inspect --format '{{.RepoTags}} {{.Id}} {{.RepoDigests}}' "$img" >> "$IMAGES_TXT"
done

PASS=0
FAIL=0
SKIP=0
declare -a ROWS=()

run_scenario() {
  local id="$1"
  local scenario="$LAB/scenarios/$id"
  local out="$RESULTS/$id"
  mkdir -p "$out"
  # Writable by nobody (65534) inside scan containers.
  chmod 777 "$out" || true
  rm -f "$out"/* 2>/dev/null || true
  if [[ -f "$scenario/fpm/secret.conf" ]]; then
    chmod 644 "$scenario/fpm/secret.conf" || true
  fi

  echo "=== LIVE lab: $id ==="
  set +e
  (
    set -e
    cd "$scenario"
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true

    # Runtime ground truth (independent of php2shell).
    case "$id" in
      01-unix-socket|02-tcp-local)
        docker compose --profile with-runtime up -d fpm >/dev/null
        # Wait briefly for php-fpm readiness (diagnostic only; not used by php2shell).
        sleep 3
        if docker compose --profile with-runtime ps --status running --services 2>/dev/null | grep -qx fpm; then
          cmd="$(docker compose --profile with-runtime exec -T fpm sh -c 'tr \"\\0\" \" \" </proc/1/cmdline' 2>/dev/null || true)"
          printf '{"php_fpm_service_running":true,"container_cmdline":%s,"note":"observed inside fpm service container; php2shell scan uses separate FS mounts"}\n' \
            "$(printf '%s' "$cmd" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')" \
            > "$out/ground-truth-runtime.json"
        else
          echo '{"php_fpm_service_running":false,"note":"fpm profile started but service not running"}' > "$out/ground-truth-runtime.json"
          exit 42
        fi
        ;;
      06-fpm-stopped)
        echo '{"php_fpm_service_started":false,"php_fpm_process_observed":false,"note":"fpm service intentionally not started; configs still mounted for scan"}' > "$out/ground-truth-runtime.json"
        ;;
      *)
        echo '{"note":"config-focused scenario; runtime process not required for ground truth"}' > "$out/ground-truth-runtime.json"
        ;;
    esac

    # Never use --no-deps: scenario 07 needs prepare.
    docker compose run --rm scan
    docker compose --profile with-runtime down -v --remove-orphans >/dev/null 2>&1 || true
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  )
  compose_rc=$?
  set -e
  if [[ "$compose_rc" -eq 42 ]]; then
    echo "FAIL $id: fpm runtime profile did not stay running" >&2
    FAIL=$((FAIL+1))
    ROWS+=("{\"id\":\"$id\",\"result\":\"FAIL\",\"reason\":\"fpm_not_running\"}")
    return
  fi
  if [[ "$compose_rc" -ne 0 ]]; then
    echo "FAIL $id: compose/scan exited $compose_rc" >&2
    FAIL=$((FAIL+1))
    ROWS+=("{\"id\":\"$id\",\"result\":\"FAIL\",\"reason\":\"compose_exit_$compose_rc\"}")
    return
  fi

  if [[ ! -f "$out/scan-context.txt" ]]; then
    echo "FAIL $id: missing scan-context.txt (scan did not run in-container?)" >&2
    FAIL=$((FAIL+1))
    ROWS+=("{\"id\":\"$id\",\"result\":\"FAIL\",\"reason\":\"missing_scan_context\"}")
    return
  fi
  if ! grep -q 'php2shell=' "$out/scan-context.txt"; then
    echo "FAIL $id: scan-context incomplete" >&2
    FAIL=$((FAIL+1))
    ROWS+=("{\"id\":\"$id\",\"result\":\"FAIL\",\"reason\":\"bad_scan_context\"}")
    return
  fi

  if "$LAB/scripts/assert-live-results.sh" "$id"; then
    echo "PASS $id"
    PASS=$((PASS+1))
    ROWS+=("{\"id\":\"$id\",\"result\":\"PASS\"}")
  else
    echo "FAIL $id" >&2
    FAIL=$((FAIL+1))
    ROWS+=("{\"id\":\"$id\",\"result\":\"FAIL\",\"reason\":\"assert_failed\"}")
  fi
}

for scenario in "$LAB"/scenarios/*; do
  [[ -d "$scenario" ]] || continue
  run_scenario "$(basename "$scenario")"
done

{
  echo "# LIVE_DOCKER summary"
  echo
  echo "- require_live: $REQUIRE_LIVE"
  echo "- pass: $PASS"
  echo "- fail: $FAIL"
  echo "- skip: $SKIP"
  echo "- generated_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "| Scenario | Result |"
  echo "| --- | --- |"
  for row in "${ROWS[@]}"; do
    id="$(echo "$row" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')"
    res="$(echo "$row" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')"
    echo "| $id | $res |"
  done
} > "$SUMMARY_MD"

STATUS="FAIL"
if [[ "$FAIL" -eq 0 && "$SKIP" -eq 0 && "$PASS" -ge 8 ]]; then
  STATUS="PASS"
fi
{
  echo "{"
  echo "  \"live_docker\": \"$STATUS\","
  if [[ "$REQUIRE_LIVE" == "1" ]]; then echo "  \"require_live\": true,"; else echo "  \"require_live\": false,"; fi
  echo "  \"pass\": $PASS,"
  echo "  \"fail\": $FAIL,"
  echo "  \"skip\": $SKIP,"
  echo "  \"scenarios\": ["
  i=0
  for row in "${ROWS[@]}"; do
    i=$((i+1))
    if [[ $i -lt ${#ROWS[@]} ]]; then
      echo "    $row,"
    else
      echo "    $row"
    fi
  done
  echo "  ]"
  echo "}"
} > "$SUMMARY_JSON"

# Ensure the Actions runner can package nobody-owned reports.
chmod -R a+rX "$RESULTS" 2>/dev/null || true

echo "LIVE labs: pass=$PASS fail=$FAIL skip=$SKIP (summary $SUMMARY_MD)"
if [[ "$FAIL" -ne 0 || "$SKIP" -ne 0 ]]; then
  exit 1
fi
if [[ "$PASS" -lt 8 ]]; then
  echo "FAIL: expected 8 live scenarios, got pass=$PASS" >&2
  exit 1
fi
exit 0
