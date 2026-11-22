#!/usr/bin/env bash
# Put a manager's stock <ruleset> configuration back after an interrupted
# rulelanes oracle run, remove the run's files and lock, and restart that
# manager. Safe to run when nothing needs restoring.
#
#   oracle/restore-ruleset.sh          # the oracle container (default)
#   oracle/restore-ruleset.sh --live   # the live manager (only needed for
#                                      # runs made before the oracle split)
set -euo pipefail
container="rulelanes-oracle-manager"
if [ "${1:-}" = "--live" ]; then container="single-node-wazuh.manager-1"; fi
MSYS_NO_PATHCONV=1 docker exec "$container" sh -c '
  E=/var/ossec/etc
  if [ -f $E/ossec.conf.rulelanes-stock ]; then
    cat $E/ossec.conf.rulelanes-stock > $E/ossec.conf && rm $E/ossec.conf.rulelanes-stock
    echo "restored stock ruleset configuration"
  fi
  rm -rf $E/rulelanes; rmdir $E/rulelanes.lock 2>/dev/null || true
  /var/ossec/bin/wazuh-control restart >/dev/null 2>&1
  sed -n "/<ruleset>/,/<\/ruleset>/p" $E/ossec.conf'
echo "checked $container"
