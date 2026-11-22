#!/usr/bin/env bash
# Fetch Evan's UniFi decoder and rules (public GitHub repos) into the
# git-ignored oracle/unifi/ directory and install them into the running Wazuh
# manager's custom ruleset directories, as their READMEs describe, then
# restart the manager. The files are fetched at setup time only and never
# committed here. Pin a commit with UNIFI_DECODER_REF / UNIFI_RULES_REF.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
container="${WAZUH_MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
dec_ref="${UNIFI_DECODER_REF:-3a9a2d522840ed876e3f634232ea36392d94478f}"
rul_ref="${UNIFI_RULES_REF:-36193597001b99c94994972412253c3c712fcb93}"


fetch() {  # repo ref
  local dir="$here/unifi/$1"
  if [ ! -d "$dir/.git" ]; then
    git clone -q "https://github.com/evangress/$1.git" "$dir"
  fi
  git -C "$dir" fetch -q origin
  git -C "$dir" checkout -q "$2"
  echo "$1 at $(git -C "$dir" rev-parse HEAD)"
}
fetch wazuh-unifi-decoder "$dec_ref"
fetch wazuh-unifi-rules "$rul_ref"

MSYS_NO_PATHCONV=1 docker cp "$(cygpath -w "$here/unifi/wazuh-unifi-decoder/ubiquiti_decoders.xml" 2>/dev/null || echo "$here/unifi/wazuh-unifi-decoder/ubiquiti_decoders.xml")" "$container:/var/ossec/etc/decoders/ubiquiti_decoders.xml"
MSYS_NO_PATHCONV=1 docker cp "$(cygpath -w "$here/unifi/wazuh-unifi-rules/ubiquiti_rules.xml" 2>/dev/null || echo "$here/unifi/wazuh-unifi-rules/ubiquiti_rules.xml")" "$container:/var/ossec/etc/rules/ubiquiti_rules.xml"
MSYS_NO_PATHCONV=1 docker exec "$container" sh -c '
  cd /var/ossec/etc &&
  chown wazuh:wazuh decoders/ubiquiti_decoders.xml rules/ubiquiti_rules.xml &&
  chmod 660 decoders/ubiquiti_decoders.xml rules/ubiquiti_rules.xml &&
  /var/ossec/bin/wazuh-control restart >/dev/null &&
  grep -E "wazuh-analysisd: (ERROR|CRITICAL|WARNING)" /var/ossec/logs/ossec.log | tail -5 || true'
echo "installed; check with: printf '%s\n' '<line>' | $here/logtest.sh"
