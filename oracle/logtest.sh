#!/usr/bin/env bash
# Send log lines (stdin, one per line) to wazuh-logtest in the running Wazuh
# manager container and print one JSON result per line. See oracle/README.md.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
container="${WAZUH_MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
MSYS_NO_PATHCONV=1 exec docker exec -i \
  -e WAZUH_API_USER -e WAZUH_API_PASSWORD -e LOGTEST_LOG_FORMAT -e LOGTEST_LOCATION \
  "$container" /var/ossec/framework/python/bin/python3 -c "$(cat "$here/logtest.py")"
