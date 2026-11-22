#!/usr/bin/env bash
# Replace the upstream default passwords of the live single-node stack with
# the values in the git-ignored oracle/secrets.env, following "Changing the
# default password of Wazuh users" (Wazuh 4.14 Docker docs). Prints no
# password. Run from the repository root, with the stack up:
#
#   oracle/live-passwords.sh
#
# Steps: hash each indexer internal user's new password with the indexer
# image's hash.sh and write it to internal_users.yml; set the dashboard's
# wazuh-wui password in wazuh.yml; recreate the stack with compose.live.yml
# (which takes the passwords from secrets.env); apply internal_users.yml
# with securityadmin.sh; change the API user "wazuh" through the API.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
sn="$here/wazuh-docker/single-node"
secrets="$here/secrets.env"
[ -f "$secrets" ] || { echo "missing $secrets" >&2; exit 2; }
set -a; . "$secrets"; set +a
export MSYS_NO_PATHCONV=1
compose() { (cd "$sn" && docker compose -f docker-compose.yml -f ../../compose.live.yml --env-file ../../secrets.env "$@"); }

# 1. Hashes for every internal user in internal_users.yml.
users="admin kibanaserver kibanaro logstash readall snapshotrestore"
iu="$sn/config/wazuh_indexer/internal_users.yml"
for u in $users; do
  var="LIVE_INDEXER_$(echo "$u" | tr a-z A-Z)_PASSWORD"
  PW="${!var}" HASH="$(PW="${!var}" docker run --rm -e PW wazuh/wazuh-indexer:4.14.10 \
      bash -c 'bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$PW"' | grep '^\$2' | tail -1)"
  [ -n "$HASH" ] || { echo "hash failed for $u" >&2; exit 1; }
  U="$u" HASH="$HASH" awk '
    $0 ~ "^"ENVIRON["U"]":" {inuser=1; print; next}
    /^[a-z_]+:/ {inuser=0}
    inuser && $1 == "hash:" {print "  hash: \"" ENVIRON["HASH"] "\""; next}
    {print}' "$iu" > "$iu.new" && mv "$iu.new" "$iu"
  echo "hashed $u"
done

# 2. Dashboard's API connection password (wazuh-wui).
wy="$sn/config/wazuh_dashboard/wazuh.yml"
P="$LIVE_API_WUI_PASSWORD" awk '$1 == "password:" {sub(/password:.*/, "password: \"" ENVIRON["P"] "\"")} {print}' "$wy" > "$wy.new" && mv "$wy.new" "$wy"
echo "updated wazuh.yml"

# 3. Recreate the stack with the new environment.
compose down
compose up -d

# 4. Apply internal_users.yml (wait for the indexer first).
for i in $(seq 1 60); do
  if docker exec single-node-wazuh.indexer-1 bash -c 'curl -sk https://localhost:9200 >/dev/null'; then break; fi
  sleep 5
done
sleep 30
docker exec single-node-wazuh.indexer-1 bash -c '
  INSTALLATION_DIR=/usr/share/wazuh-indexer
  CONFIG_DIR=$INSTALLATION_DIR/config
  CACERT=$CONFIG_DIR/certs/root-ca.pem
  KEY=$CONFIG_DIR/certs/admin-key.pem
  CERT=$CONFIG_DIR/certs/admin.pem
  export JAVA_HOME=/usr/share/wazuh-indexer/jdk
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
    -cd $CONFIG_DIR/opensearch-security/ -nhnv -cacert $CACERT -cert $CERT -key $KEY -p 9200 -icl' \
  | grep -E "Done with success|ERR|rror" || true

# 5. API user "wazuh": change its password through the API (as wazuh-wui).
for i in $(seq 1 60); do
  docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-apid is running" && break
  sleep 3
done
sleep 10
WUI="$LIVE_API_WUI_PASSWORD" NEWPW="$LIVE_API_WAZUH_PASSWORD" docker exec -i -e WUI -e NEWPW single-node-wazuh.manager-1 \
  /var/ossec/framework/python/bin/python3 - <<'PY'
import base64, json, os, ssl, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
api = 'https://localhost:55000'
def call(method, path, headers, body=None):
    req = urllib.request.Request(api + path, method=method, headers=headers,
                                 data=None if body is None else json.dumps(body).encode())
    with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
        return r.read().decode()
basic = base64.b64encode(('wazuh-wui:' + os.environ['WUI']).encode()).decode()
tok = call('POST', '/security/user/authenticate?raw=true', {'Authorization': 'Basic ' + basic}).strip()
h = {'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json'}
users = json.loads(call('GET', '/security/users', h))['data']['affected_items']
uid = next(u['id'] for u in users if u['username'] == 'wazuh')
res = json.loads(call('PUT', '/security/users/%d' % uid, h, {'password': os.environ['NEWPW']}))
print('API user wazuh: failed items', res['data']['total_failed_items'])
PY
echo "done"
