#!/bin/sh
# Runs inside the lab scan container. Remains read-only w.r.t. discovery targets.
# Hostname comes from the container hostname (compose `hostname:`), not a CLI flag.
set -eu
LABEL="${1:-lab}"
mkdir -p /results
{
  echo "label=$LABEL"
  echo "container_hostname=$(hostname 2>/dev/null || true)"
  echo "pwd=$(pwd)"
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "php2shell=$(command -v php2shell || true)"
  echo "uid=$(id -u 2>/dev/null || true)"
  ls -la /etc/nginx 2>/dev/null || echo "no_/etc/nginx"
  ls -la /usr/local/etc/php-fpm.d 2>/dev/null || echo "no_php-fpm.d"
  ls -la /etc/php 2>/dev/null || echo "no_/etc/php"
  command -v php >/dev/null 2>&1 && php -v 2>/dev/null | head -1 || echo "php_cli_absent"
} > /results/scan-context.txt

set +e
# --accept-incomplete: remote/unreadable scenarios exit 0 after writing reports while
# status JSON still records SCAN_INCOMPLETE. php2shell does not execute discovered binaries.
php2shell scan --customer "nginx-fpm-lab:$LABEL" --output-dir /results --quiet --accept-incomplete
rc=$?
set -e
echo "$rc" > /results/php2shell.exit
# Reports are written mode 0600 by php2shell; make them readable for the CI host assert/upload.
chmod -R a+rX /results 2>/dev/null || true
ls -la /results
test -n "$(ls /results/*.html 2>/dev/null)"
test -n "$(ls /results/*.csv 2>/dev/null)"
exit 0
