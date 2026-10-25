#!/usr/bin/env bash
# Compare live HTML/CSV/status artifacts to ground-truth expectations.
set -euo pipefail
ID="${1:?scenario id}"
LAB="$(cd "$(dirname "$0")/.." && pwd)"
GT="$LAB/scenarios/$ID/ground-truth.json"
DIR="$LAB/results/$ID"
CMP="$DIR/comparison.json"
NOTES_FILE="$DIR/comparison-notes.txt"

# Host runner must be able to read nobody-owned reports.
chmod -R a+rX "$DIR" 2>/dev/null || true

: > "$NOTES_FILE"

HTML="$(find "$DIR" -maxdepth 1 -name '*.html' ! -name '*.status.json' | head -1 || true)"
CSV="$(find "$DIR" -maxdepth 1 -name '*.csv' | head -1 || true)"
STATUS="$(find "$DIR" -maxdepth 1 -name '*.status.json' | head -1 || true)"

if [[ -z "${HTML:-}" || ! -f "$HTML" ]]; then
  echo "missing HTML report in $DIR" | tee -a "$NOTES_FILE" >&2
  exit 1
fi
if [[ -z "${CSV:-}" || ! -f "$CSV" ]]; then
  echo "missing CSV report in $DIR" | tee -a "$NOTES_FILE" >&2
  exit 1
fi

# Search HTML + CSV together (HTML may omit raw type names).
blob="$(cat "$HTML" "$CSV")"

fail=0

note() { echo "$1" | tee -a "$NOTES_FILE" >&2; }

check_contains() {
  local needle="$1"
  if ! printf '%s' "$blob" | grep -Fq "$needle"; then
    note "missing:$needle"
    fail=1
  else
    echo "found:$needle" >> "$NOTES_FILE"
  fi
}

check_absent() {
  local needle="$1"
  if printf '%s' "$blob" | grep -Fq "$needle"; then
    note "forbidden_present:$needle"
    fail=1
  else
    echo "absent_ok:$needle" >> "$NOTES_FILE"
  fi
}

# Reject only an explicit verified runtime claim (not the phrase "not verified").
if printf '%s' "$blob" | grep -Eq '>(Verified)</|effective_web_runtime.: .VERIFIED'; then
  note "forbidden:verified_runtime_claim"
  fail=1
fi

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
    check_contains 'scope=remote'
    ;;
  04-multi-pool)
    check_contains 'php8.3-fpm.sock'
    check_contains '127.0.0.1:9084'
    ;;
  05-php-not-configured)
    check_contains 'static.lab.local'
    check_absent 'directive=fastcgi_pass'
    check_absent 'correlated_fpm_pool='
    if ! printf '%s' "$blob" | grep -Eqi 'binary_static_version|binary_path|PHP 8\.3'; then
      note "missing:php_binary_evidence"
      fail=1
    else
      echo "found:php_binary_evidence" >> "$NOTES_FILE"
    fi
    ;;
  07-unreadable-config)
    if ! printf '%s' "$blob" | grep -Eqi 'php_fpm_config_skip|CONFIG_CANDIDATE_NOT_INSPECTED|not_inspected'; then
      note "missing:skip_evidence"
      fail=1
    else
      echo "found:skip_evidence" >> "$NOTES_FILE"
    fi
    check_contains 'unix:/run/php/php-fpm.sock'
    ;;
  08-php-free)
    check_contains 'free.lab.local'
    check_absent 'directive=fastcgi_pass'
    check_absent 'scope=remote'
    ;;
  *)
    note "unknown_scenario:$ID"
    exit 1
    ;;
esac

if ! head -1 "$CSV" | grep -q 'schema_version'; then
  note "missing:csv_schema"
  fail=1
fi

RESULT="FAIL"
[[ $fail -eq 0 ]] && RESULT="PASS"

python3 -c "
import json, os
doc = {
  'scenario': '''$ID''',
  'result': '''$RESULT''',
  'html': os.path.basename('''$HTML'''),
  'csv': os.path.basename('''$CSV'''),
  'status_json': os.path.basename('''$STATUS''') if '''$STATUS''' else '',
  'ground_truth': os.path.basename('''$GT'''),
  'checks': [ln.strip() for ln in open('''$NOTES_FILE''', encoding='utf-8') if ln.strip()],
}
open('''$CMP''', 'w', encoding='utf-8').write(json.dumps(doc, indent=2) + '\n')
"

if [[ $fail -ne 0 ]]; then
  note "assert_failed_for:$ID"
  # Help CI logs: show whether sock/TCP tokens exist at all.
  printf '%s' "$blob" | tr '<' '\n' | grep -E 'unix:|127.0.0.1:9000|10.23.23.23|free.lab|static.lab|fastcgi|local_candidate|remote' | head -40 >&2 || true
fi

exit "$fail"
