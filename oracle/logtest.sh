#!/usr/bin/env bash
# Send log lines (stdin, one per line) to wazuh-logtest and print one JSON
# result per line. See oracle/README.md.
#
# The target is the oracle container (rulelanes-oracle-manager). To query
# the live manager instead, pass --live; its API password is then read from
# LIVE_API_WUI_PASSWORD. Credentials come from the environment or from the
# git-ignored oracle/secrets.env; there is no built-in default.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
oracle="rulelanes-oracle-manager"
container="${WAZUH_MANAGER_CONTAINER:-$oracle}"
live=no
if [ "${1:-}" = "--live" ]; then live=yes; container="single-node-wazuh.manager-1"; fi
if [ "$container" != "$oracle" ] && [ "$live" != yes ]; then
  echo "logtest.sh: refusing to target '$container': only $oracle, or --live for the live manager" >&2
  exit 2
fi
if [ -f "$here/secrets.env" ]; then
  # shellcheck disable=SC1091
  set -a; . "$here/secrets.env"; set +a
fi
if [ "$live" = yes ]; then
  WAZUH_API_PASSWORD="${WAZUH_API_PASSWORD:-${LIVE_API_WUI_PASSWORD:-}}"
else
  WAZUH_API_PASSWORD="${WAZUH_API_PASSWORD:-${ORACLE_API_PASSWORD:-}}"
fi
if [ -z "${WAZUH_API_PASSWORD:-}" ]; then
  echo "logtest.sh: no API password (set WAZUH_API_PASSWORD or create oracle/secrets.env)" >&2
  exit 2
fi
export WAZUH_API_PASSWORD
MSYS_NO_PATHCONV=1 exec docker exec -i \
  -e WAZUH_API_USER -e WAZUH_API_PASSWORD -e LOGTEST_LOG_FORMAT -e LOGTEST_LOCATION \
  "$container" /var/ossec/framework/python/bin/python3 -c "$(cat "$here/logtest.py")"
