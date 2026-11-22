#!/usr/bin/env bash
# Install Evan's UniFi decoder and rules (git submodules under
# third_party/unifi/, MIT) into a Wazuh manager's custom ruleset directories,
# as their READMEs describe, and restart that manager.
#
#   oracle/install-unifi.sh            # the oracle container (default)
#   oracle/install-unifi.sh --live     # the live single-node manager
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
oracle="rulelanes-oracle-manager"
live="single-node-wazuh.manager-1"
container="$oracle"
if [ "${1:-}" = "--live" ]; then container="$live"; fi

git -C "$repo" submodule update --init -- third_party/unifi/wazuh-unifi-decoder third_party/unifi/wazuh-unifi-rules
for m in wazuh-unifi-decoder wazuh-unifi-rules; do
  echo "$m at $(git -C "$repo/third_party/unifi/$m" rev-parse HEAD)"
done
winpath() { cygpath -w "$1" 2>/dev/null || echo "$1"; }
export MSYS_NO_PATHCONV=1
docker cp "$(winpath "$repo/third_party/unifi/wazuh-unifi-decoder/ubiquiti_decoders.xml")" "$container:/var/ossec/etc/decoders/ubiquiti_decoders.xml"
docker cp "$(winpath "$repo/third_party/unifi/wazuh-unifi-rules/ubiquiti_rules.xml")" "$container:/var/ossec/etc/rules/ubiquiti_rules.xml"
docker exec "$container" sh -c '
  cd /var/ossec/etc &&
  chown wazuh:wazuh decoders/ubiquiti_decoders.xml rules/ubiquiti_rules.xml &&
  chmod 660 decoders/ubiquiti_decoders.xml rules/ubiquiti_rules.xml &&
  /var/ossec/bin/wazuh-control restart >/dev/null 2>&1
  grep -E "wazuh-analysisd: (ERROR|CRITICAL|WARNING)" /var/ossec/logs/ossec.log | tail -5 || true'
echo "installed into $container"
