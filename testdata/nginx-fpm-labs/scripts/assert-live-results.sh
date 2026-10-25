#!/usr/bin/env bash
# Compare live HTML/CSV/status artifacts to ground-truth expectations.
# Writes results/<id>/comparison.json (expected vs actual checks).
set -euo pipefail
ID="${1:?scenario id}"
LAB="$(cd "$(dirname "$0")/.." && pwd)"
GT="$LAB/scenarios/$ID/ground-truth.json"
DIR="$LAB/results/$ID"
HTML="$(ls "$DIR"/*.html 2>/dev/null | head -1 || true)"
CSV="$(ls "$DIR"/*.csv 2>/dev/null | head -1 || true)"
STATUS="$(ls "$DIR"/*.status.json 2>/dev/null | head -1 || true)"
CMP="$DIR/comparison.json"
NOTES_FILE="$DIR/comparison-notes.txt"

: > "$NOTES_FILE"

if [[ -z "${HTML:-}" || ! -f "$HTML" ]]; then
  echo "missing HTML report in $DIR" >&2
  exit 1
fi
if [[ -z "${CSV:-}" || ! -f "$CSV" ]]; then
  echo "missing CSV report in $DIR" >&2
  exit 1
fi
body="$(cat "$HTML")"
csv_body="$(cat "$CSV")"

if echo "$body" | grep -q '>Verified</'; then
  echo "HTML claims Verified runtime" >&2
  exit 1
fi

fail=0

check_contains() {
  local needle="$1"
  if ! echo "$body" | grep -Fq "$needle"; then
    echo "missing HTML needle: $needle" >&2
    echo "missing:$needle" >> "$NOTES_FILE"
    fail=1
  else
    echo "found:$needle" >> "$NOTES_FILE"
  fi
}

check_absent() {
  local needle="$1"
  if echo "$body" | grep -Fq "$needle"; then
    echo "forbidden HTML needle present: $needle" >&2
    echo "forbidden_present:$needle" >> "$NOTES_FILE"
    fail=1
  else
    echo "absent_ok:$needle" >> "$NOTES_FILE"
  fi
}

case "$ID" in
  01-unix-socket|06-fpm-stopped)
    check_contains 'unix:/run/php/php-fpm.sock'
    check_contains 'local_candidate'
    check_absent '10.23.23.23:9000'
    ;;
  02-tcp-local)
    check_contains '127.0.0.1:9000'
    check_contains 'local_candidate'
    ;;
  03-remote-fpm)
    check_contains '10.23.23.23:9000'
    check_contains 'remote'
    if echo "$body" | grep -E '10\.23\.23\.23:9000' | grep -q 'Version 8\.'; then
      echo "remote backend appears versioned from local PHP" >&2
      echo "forbidden:remote_versioned" >> "$NOTES_FILE"
      fail=1
    fi
    ;;
  04-multi-pool)
    check_contains 'php8.3-fpm.sock'
    check_contains '127.0.0.1:9084'
    ;;
  05-php-not-configured)
    check_contains 'static.lab.local'
    # Pool rows may say scope=local_candidate; forbid nginx FastCGI handler tokens only.
    check_absent 'directive=fastcgi_pass'
    check_absent 'correlated_fpm_pool='
    if ! echo "$body$csv_body" | grep -Eqi 'binary_static_version|binary_path|PHP 8\.3'; then
      echo "expected PHP binary evidence from php CLI image on scan FS" >&2
      echo "missing:php_binary_evidence" >> "$NOTES_FILE"
      fail=1
    else
      echo "found:php_binary_evidence" >> "$NOTES_FILE"
    fi
    ;;
  07-unreadable-config)
    if ! echo "$body" | grep -Eqi 'php_fpm_config_skip|CONFIG_CANDIDATE_NOT_INSPECTED|not_inspected'; then
      echo "missing unreadable skip evidence" >&2
      echo "missing:skip_evidence" >> "$NOTES_FILE"
      fail=1
    else
      echo "found:skip_evidence" >> "$NOTES_FILE"
    fi
    check_contains 'unix:/run/php/php-fpm.sock'
    ;;
  08-php-free)
    check_contains 'free.lab.local'
    check_absent 'scope=local_candidate'
    check_absent 'directive=fastcgi_pass'
    check_absent 'scope=remote'
    ;;
  *)
    echo "unknown scenario id $ID" >&2
    exit 1
    ;;
esac

if ! head -1 "$CSV" | grep -q 'schema_version'; then
  echo "CSV missing schema_version header" >&2
  echo "missing:csv_schema" >> "$NOTES_FILE"
  fail=1
fi

if [[ -n "${STATUS:-}" && -f "$STATUS" ]]; then
  if grep -q '"effective_web_runtime"[[:space:]]*:[[:space:]]*"VERIFIED"' "$STATUS" 2>/dev/null; then
    echo "status JSON claims VERIFIED runtime" >&2
    echo "forbidden:status_verified" >> "$NOTES_FILE"
    fail=1
  fi
fi

RESULT="FAIL"
[[ $fail -eq 0 ]] && RESULT="PASS"
python3 - "$CMP" "$ID" "$RESULT" "$HTML" "$CSV" "${STATUS:-}" "$GT" "$NOTES_FILE" <<'PY'
import json, sys, os
path, sid, result, html, csv, status, gt, notes_path = sys.argv[1:9]
checks = []
if os.path.isfile(notes_path):
    checks = [ln.strip() for ln in open(notes_path, encoding="utf-8") if ln.strip()]
doc = {
    "scenario": sid,
    "result": result,
    "html": os.path.basename(html),
    "csv": os.path.basename(csv),
    "status_json": os.path.basename(status) if status else "",
    "ground_truth": os.path.basename(gt),
    "checks": checks,
}
open(path, "w", encoding="utf-8").write(json.dumps(doc, indent=2) + "\n")
PY

exit "$fail"
