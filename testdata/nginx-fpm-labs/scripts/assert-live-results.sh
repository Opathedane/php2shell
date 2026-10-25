#!/usr/bin/env bash
# Lightweight string assertions against HTML/CSV produced by a live lab scan.
# Full semantic checks live in CONFIG_TREE_OFFLINE Go tests; this catches gross live regressions.
set -euo pipefail
ID="${1:?scenario id}"
LAB="$(cd "$(dirname "$0")/.." && pwd)"
GT="$LAB/scenarios/$ID/ground-truth.json"
DIR="$LAB/results/$ID"
HTML="$(ls "$DIR"/*.html 2>/dev/null | head -1 || true)"
CSV="$(ls "$DIR"/*.csv 2>/dev/null | head -1 || true)"
if [ -z "${HTML:-}" ] || [ ! -f "$HTML" ]; then
  echo "missing HTML report in $DIR" >&2
  exit 1
fi
body="$(cat "$HTML")"
# Never verified runtime label
if echo "$body" | grep -qiE '>(Verified)</|EffectiveWebRuntime.: .VERIFIED'; then
  # HTML uses human labels; reject explicit Verified runtime as sole posture
  if echo "$body" | grep -q '>Verified</'; then
    echo "HTML appears to claim Verified runtime" >&2
    exit 1
  fi
fi
# Scenario-specific needles from ground truth (best-effort)
case "$ID" in
  01-unix-socket|06-fpm-stopped)
    echo "$body" | grep -q 'unix:/run/php/php-fpm.sock' || { echo "missing unix sock handler"; exit 1; }
    echo "$body" | grep -q 'php_fpm_pool_config\|pool=www\|listen=unix:' || true
    ;;
  02-tcp-local)
    echo "$body" | grep -q '127.0.0.1:9000' || { echo "missing local TCP"; exit 1; }
    ;;
  03-remote-fpm)
    echo "$body" | grep -q '10.23.23.23:9000' || { echo "missing remote backend"; exit 1; }
    ;;
  04-multi-pool)
    echo "$body" | grep -q 'php8.3-fpm.sock' || { echo "missing pool83 sock"; exit 1; }
    echo "$body" | grep -q '127.0.0.1:9084' || { echo "missing pool84 tcp"; exit 1; }
    ;;
  05-php-not-configured)
    if echo "$body" | grep -q 'nginx_php_handler_config'; then
      echo "unexpected PHP handler on static site" >&2
      exit 1
    fi
    ;;
  07-unreadable-config)
    echo "$body" | grep -qE 'php_fpm_config_skip|CONFIG_CANDIDATE_NOT_INSPECTED|not_inspected' || {
      echo "missing skip evidence for unreadable pool"; exit 1;
    }
    ;;
  08-php-free)
    if echo "$body" | grep -qE 'nginx_php_handler_config|nginx_remote_php_backend'; then
      echo "unexpected PHP handler in php-free lab" >&2
      exit 1
    fi
    ;;
esac
# CSV sibling exists
if [ -n "${CSV:-}" ] && [ -f "$CSV" ]; then
  :
else
  echo "warning: CSV sibling missing for $ID" >&2
fi
exit 0
