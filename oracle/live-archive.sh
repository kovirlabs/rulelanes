#!/usr/bin/env bash
# Turn the live manager's full event archive on or off, then recreate the
# manager container. With it on, every received event is written to
# /var/ossec/logs/archives/archives.log and archives.json, whether or not a
# rule fires. Wazuh rotates and compresses the files daily; they are not
# sent to the indexer.
#
#   oracle/live-archive.sh on|off
set -euo pipefail
case "${1:-}" in on) v=yes ;; off) v=no ;; *) echo "usage: $0 on|off" >&2; exit 2 ;; esac
here="$(cd "$(dirname "$0")" && pwd)"
conf="$here/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf"
sed -i -E "s#<logall>(yes|no)</logall>#<logall>$v</logall>#; s#<logall_json>(yes|no)</logall_json>#<logall_json>$v</logall_json>#" "$conf"
grep -n "<logall" "$conf"
# Recreate, not `docker restart` (see live-syslog.sh).
(cd "$here/wazuh-docker/single-node" &&
  docker compose -f docker-compose.yml -f ../../compose.live.yml --env-file ../../secrets.env \
    up -d --force-recreate --no-deps wazuh.manager)
echo "archive $1; manager recreated"
