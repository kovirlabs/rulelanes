#!/usr/bin/env bash
# R6: measure Wazuh analysisd's event rate on the same ruleset and corpus as
# rulelanes-bench, in the oracle container (never the live manager).
#
#   oracle/analysisd-bench.sh [SECS] [SENDERS]       (from the repo root)
#   RUN_MACHINE=ryzen RUN_DATE=YYYY-MM-DD RUN_NOTE="..." oracle/analysisd-bench.sh 20 12
#       also writes runs/<machine>/<date>-analysisd[-n].json
#
# What it does, in the oracle container `rulelanes-oracle-manager`:
#   1. takes the oracle lock (the same lock directory the Rust oracle uses);
#   2. installs testdata/ruleset under /var/ossec/etc/rulelanes and points
#      <ruleset> at it only (same isolation as the R1 oracle runs);
#   3. sets analysisd.state_interval=1 in local_internal_options.conf so the
#      state file is written every second, and restarts the manager's
#      daemons (wazuh-control restart);
#   4. starts a sampler of wazuh-analysisd.state and SENDERS processes that
#      send the corpus in a loop for SECS seconds to analysisd's local
#      datagram socket (standard Wazuh message format, queue 1);
#   5. summarises, restores ossec.conf and local_internal_options.conf,
#      removes its files, restarts the daemons and releases the lock (also on
#      error).
# Prints the summary JSON on stdout. Alerts are written to the container's
# alerts.log and alerts.json as usual.
set -euo pipefail
SECS="${1:-20}"
SENDERS="${2:-4}"
LOCATIONS=4
C=rulelanes-oracle-manager
E=/var/ossec/etc
PY=/var/ossec/framework/python/bin/python3
dx() { MSYS_NO_PATHCONV=1 docker exec -i "$C" "$@"; }

dx sh -c "mkdir $E/rulelanes.lock" || { echo "oracle busy (lock exists)" >&2; exit 1; }
restore() {
  dx sh -c "
    if [ -f $E/ossec.conf.rulelanes-stock ]; then cat $E/ossec.conf.rulelanes-stock > $E/ossec.conf && rm $E/ossec.conf.rulelanes-stock; fi
    if [ -f $E/local_internal_options.conf.rulelanes-stock ]; then cat $E/local_internal_options.conf.rulelanes-stock > $E/local_internal_options.conf && rm $E/local_internal_options.conf.rulelanes-stock; fi
    rm -rf $E/rulelanes /tmp/rl-bench
    /var/ossec/bin/wazuh-control restart >/dev/null 2>&1
    rmdir $E/rulelanes.lock" || true
  echo "restored $C" >&2
}
trap restore EXIT

dx sh -c "rm -rf $E/rulelanes /tmp/rl-bench && mkdir -p $E/rulelanes/decoders $E/rulelanes/rules /tmp/rl-bench"
for f in testdata/ruleset/decoders/*.xml; do dx sh -c "cat > $E/rulelanes/decoders/$(basename "$f")" < "$f"; done
for f in testdata/ruleset/rules/*.xml; do dx sh -c "cat > $E/rulelanes/rules/$(basename "$f")" < "$f"; done
dx sh -c "chown -R root:wazuh $E/rulelanes && chmod -R g+rX $E/rulelanes"
dx sh -c "cat > /tmp/rl-bench/corpus.log" < testdata/corpus/corpus.log
dx sh -c "cat > /tmp/rl-bench/bench.py" < oracle/analysisd_bench.py

dx sh -c "
  ( [ -f $E/ossec.conf.rulelanes-stock ] || cp -p $E/ossec.conf $E/ossec.conf.rulelanes-stock ) &&
  awk '/<ruleset>/{print; print \"    <decoder_dir>etc/rulelanes/decoders</decoder_dir>\"; print \"    <rule_dir>etc/rulelanes/rules</rule_dir>\"; skip=1; next} /<\\/ruleset>/{skip=0} !skip' $E/ossec.conf.rulelanes-stock > /tmp/rl-bench/ossec.conf &&
  cat /tmp/rl-bench/ossec.conf > $E/ossec.conf &&
  cp -p $E/local_internal_options.conf $E/local_internal_options.conf.rulelanes-stock &&
  echo 'analysisd.state_interval=1' >> $E/local_internal_options.conf &&
  /var/ossec/bin/wazuh-control restart >/dev/null 2>&1"
sleep 5
dx sh -c "sed -n '/<ruleset>/,/<\/ruleset>/p' $E/ossec.conf" >&2
dx sh -c "/var/ossec/bin/wazuh-control status | grep analysisd" >&2

dx sh -c "cd /tmp/rl-bench && $PY bench.py sample $((SECS + 40)) samples.jsonl" &
SAMPLER=$!
sleep 2
START=$(dx sh -c 'date +%s.%N')
for i in $(seq 1 "$SENDERS"); do
  dx sh -c "cd /tmp/rl-bench && $PY bench.py send corpus.log $SECS $LOCATIONS sent-$i.json" &
done
wait_for_senders() { for p in $(jobs -p); do [ "$p" = "$SAMPLER" ] || wait "$p"; done; }
wait_for_senders
wait "$SAMPLER"
SENT=$(for i in $(seq 1 "$SENDERS"); do printf ' sent-%s.json' "$i"; done)
dx sh -c "cd /tmp/rl-bench && $PY bench.py summarize samples.jsonl $START $SECS $SENT" > /tmp/rl-analysisd-summary.$$

# Run file (when RUN_MACHINE and RUN_DATE are set): metadata from the host
# and the container, the summary, and the command (no local paths).
if [ -n "${RUN_MACHINE:-}" ] && [ -n "${RUN_DATE:-}" ]; then
  mkdir -p "runs/$RUN_MACHINE"
  out="runs/$RUN_MACHINE/$RUN_DATE-analysisd.json"; k=2
  while [ -e "$out" ]; do out="runs/$RUN_MACHINE/$RUN_DATE-analysisd-$k.json"; k=$((k + 1)); done
  MSYS_NO_PATHCONV=1 docker exec -i \
    -e RUN_MACHINE="$RUN_MACHINE" -e RUN_DATE="$RUN_DATE" -e RUN_NOTE="${RUN_NOTE:-}" \
    -e OS_BUILD="$(cmd //c ver 2>/dev/null | tr -d '\r' | grep -v '^$' || uname -srv)" \
    -e COMMIT="$(git rev-parse HEAD)" \
    -e DIRTY="$(git status --porcelain --untracked-files=no | wc -l)" \
    -e DOCKER="$(docker version --format '{{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}}, kernel {{.Server.KernelVersion}})' 2>/dev/null)" \
    -e CMD="oracle/analysisd-bench.sh $SECS $SENDERS" -e SECS="$SECS" -e SENDERS="$SENDERS" \
    "$C" "$PY" -c '
import json, os, subprocess, sys
summary = json.load(sys.stdin)
sh = lambda c: subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()
print(json.dumps({
  "kind": "analysisd-throughput",
  "machine": os.environ["RUN_MACHINE"],
  "date_local": os.environ["RUN_DATE"],
  "os_build": os.environ["OS_BUILD"],
  "docker": os.environ["DOCKER"],
  "container": {"name": "rulelanes-oracle-manager", "image": "wazuh/wazuh-manager:4.14.10",
                "nproc": sh("nproc"), "mem_total_mb": sh("free -m | awk \"/Mem:/{print \\$2}\""),
                "wazuh": sh("/var/ossec/bin/wazuh-control info | tr \"\\n\" \" \"")},
  "rulelanes": {"commit": os.environ["COMMIT"], "uncommitted_changes": os.environ["DIRTY"] != "0"},
  "ruleset": "testdata/ruleset only (isolated <ruleset>, as for the R1 oracle runs)",
  "corpus": {"file": "testdata/corpus/corpus.log", "locations": 4, "assignment": "round robin"},
  "method": {
    "input": "senders in the container write the corpus in a loop to analysisd local datagram socket /var/ossec/queue/sockets/queue, message 1:source-N:<line> (Wazuh standard message format)",
    "senders": int(os.environ["SENDERS"]), "secs": float(os.environ["SECS"]),
    "counters": "/var/ossec/var/run/wazuh-analysisd.state, written every second (analysisd.state_interval=1), sampled every 0.5 s",
    "rate_window": "from 2 s after the senders start to 1 s before they stop",
    "output": "alerts written to alerts.log and alerts.json as configured in the image (log_alert_level 3)",
    "latency": "not measured: analysisd gives no per-event receipt-to-alert time",
  },
  "results": summary,
  "command": os.environ["CMD"],
  "note": os.environ["RUN_NOTE"],
}, indent=2))
' < /tmp/rl-analysisd-summary.$$ > "$out"
  echo "$out" >&2
fi
cat /tmp/rl-analysisd-summary.$$
rm -f /tmp/rl-analysisd-summary.$$
