#!/bin/sh
# Runs inside the lab scan container. Remains read-only w.r.t. discovery targets.
set -eu
HOSTNAME_LAB="${1:?hostname}"
mkdir -p /results
# Record scan filesystem context for artifacts (no secrets).
{
  echo "hostname_arg=$HOSTNAME_LAB"
  echo "pwd=$(pwd)"
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "php2shell=$(command -v php2shell || true)"
  ls -la /etc/nginx 2>/dev/null || echo "no_/etc/nginx"
  ls -la /usr/local/etc/php-fpm.d 2>/dev/null || echo "no_php-fpm.d"
  ls -la /etc/php 2>/dev/null || echo "no_/etc/php"
  command -v php >/dev/null 2>&1 && php -v 2>/dev/null | head -1 || echo "php_cli_absent"
} > /results/scan-context.txt

set +e
php2shell scan --hostname "$HOSTNAME_LAB" --output-dir /results --quiet
rc=$?
set -e
echo "$rc" > /results/php2shell.exit
ls -la /results
# Reports must exist; exit 0 (ok) or 2 (incomplete) are acceptable scan outcomes.
test -n "$(ls /results/*.html 2>/dev/null)"
test -n "$(ls /results/*.csv 2>/dev/null)"
# Prefer status json sibling when written
ls /results/*.status.json >/dev/null 2>&1 || ls /results/*status*.json >/dev/null 2>&1 || true
exit 0
