#!/usr/bin/env bash
# Add (or replace) a syslog <remote> block on the live manager so it accepts
# UDP 514 from the given sources, then recreate the manager container (its
# entrypoint copies config/wazuh_cluster/wazuh_manager.conf to ossec.conf at
# start). The block is marked so the script can be rerun.
#
#   oracle/live-syslog.sh                       # allow the Docker NAT gateway
#   oracle/live-syslog.sh <allowed-ip-or-cidr>...
#
# With Docker Desktop on Windows the manager sees every syslog packet as
# coming from the gateway of the compose network (single-node_default),
# not from the sender (checked in ops-live-manager; see oracle/README.md,
# "Receiving UniFi syslog"). With no argument that gateway address is read
# from Docker and allowed; the real filtering of senders is the Windows
# firewall rule.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if [ $# -eq 0 ]; then
  gw="$(docker network inspect single-node_default --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}')"
  [ -n "$gw" ] || { echo "cannot read the single-node_default gateway" >&2; exit 2; }
  set -- "$gw"
fi
conf="$here/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf"
allowed=""
for a in "$@"; do allowed="$allowed    <allowed-ips>$a</allowed-ips>\n"; done
block="  <!-- rulelanes: UniFi syslog (begin) -->\n  <remote>\n    <connection>syslog</connection>\n    <port>514</port>\n    <protocol>udp</protocol>\n$allowed  </remote>\n  <!-- rulelanes: UniFi syslog (end) -->"
# Drop an earlier copy of the block, then insert it after the first </remote>.
awk -v block="$block" '
  /<!-- rulelanes: UniFi syslog \(begin\) -->/ {skip=1}
  skip && /<!-- rulelanes: UniFi syslog \(end\) -->/ {skip=0; next}
  skip {next}
  {print}
  !done && /<\/remote>/ {print ""; print block; done=1}
' "$conf" > "$conf.new" && mv "$conf.new" "$conf"
# Recreate (not `docker restart`): on a plain restart the image's init
# script fails before it copies the mounted config (seen with 4.14.10).
(cd "$here/wazuh-docker/single-node" &&
  docker compose -f docker-compose.yml -f ../../compose.live.yml --env-file ../../secrets.env \
    up -d --force-recreate --no-deps wazuh.manager)
echo "syslog remote block set; manager recreated"
