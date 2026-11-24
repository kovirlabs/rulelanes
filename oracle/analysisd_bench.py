#!/usr/bin/env python3
# Runs inside the oracle container with Wazuh's bundled Python (R6).
#
#   analysisd_bench.py send CORPUS SECS LOCATIONS OUT
#       Sends the corpus lines, in a loop, as fast as one process can, to
#       analysisd's local datagram socket /var/ossec/queue/sockets/queue in
#       the standard Wazuh message format "<queue>:<location>:<message>"
#       with queue 1 (local file log), for SECS seconds. Lines go to
#       locations source-0 .. source-(LOCATIONS-1) in turn, as in
#       rulelanes-bench. Writes {"sent": n, "secs": t, "errors": e} to OUT.
#   analysisd_bench.py sample SECS OUT
#       Reads /var/ossec/var/run/wazuh-analysisd.state every 0.5 s for SECS
#       seconds and writes one JSON line per read (time and counters).
#
# Format reference: Wazuh documentation, "Standard Wazuh message format"
# (development/message-format) and "wazuh-analysisd.state" (statistics
# files). Written here; nothing copied from Wazuh.
import json
import socket
import sys
import time

QUEUE = "/var/ossec/queue/sockets/queue"
STATE = "/var/ossec/var/run/wazuh-analysisd.state"
FIELDS = ("events_received", "events_processed", "events_dropped",
          "alerts_written", "total_events_decoded", "other_events_decoded",
          "event_queue_usage", "rule_matching_queue_usage",
          "alerts_queue_usage")


def send(corpus, secs, locations, out):
    with open(corpus, "rb") as f:
        lines = [l.rstrip(b"\r\n") for l in f if l.strip()]
    msgs = [b"1:source-%d:%s" % (i % locations, l) for i, l in enumerate(lines)]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.connect(QUEUE)
    sent = errors = 0
    n = len(msgs)
    t0 = time.monotonic()
    end = t0 + secs
    i = 0
    while True:
        # Check the clock every 1,000 sends to keep the loop cheap.
        for _ in range(1000):
            try:
                s.send(msgs[i % n])
                sent += 1
            except OSError:
                errors += 1
            i += 1
        if time.monotonic() >= end:
            break
    t = time.monotonic() - t0
    with open(out, "w") as f:
        json.dump({"sent": sent, "secs": t, "errors": errors}, f)


def read_state():
    vals = {}
    with open(STATE) as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                if k in FIELDS:
                    vals[k] = float(v.strip("'"))
    return vals


def sample(secs, out):
    end = time.monotonic() + secs
    with open(out, "w") as f:
        while time.monotonic() < end:
            row = {"t": time.time()}
            try:
                row.update(read_state())
            except OSError as e:
                row["error"] = str(e)
            f.write(json.dumps(row) + "\n")
            f.flush()
            time.sleep(0.5)


def rate(rows, key, t0, t1):
    """Counter increase per second between the first sample at or after t0
    and the last sample at or before t1."""
    w = [r for r in rows if key in r and t0 <= r["t"] <= t1]
    if len(w) < 2 or w[-1]["t"] <= w[0]["t"]:
        return None
    return (w[-1][key] - w[0][key]) / (w[-1]["t"] - w[0]["t"])


def summarize(samples, start, secs, sent_files):
    rows = [json.loads(l) for l in open(samples) if l.strip()]
    rows = [r for r in rows if "events_received" in r]
    senders = [json.load(open(p)) for p in sent_files]
    end = start + secs
    last = rows[-1]
    first = [r for r in rows if r["t"] <= start] or rows[:1]
    base = first[-1]
    d = {k: last[k] - base[k] for k in ("events_received", "events_processed",
                                        "events_dropped", "alerts_written")}
    # The time at which events_processed stopped rising (drain finished).
    done = next((r["t"] for r in rows
                 if r["t"] > end and r["events_processed"] == last["events_processed"]),
                last["t"])
    out = {
        "senders": senders,
        "sent_total": sum(s["sent"] for s in senders),
        "send_errors_total": sum(s["errors"] for s in senders),
        "sent_rate_eps": sum(s["sent"] / s["secs"] for s in senders),
        "deltas": d,
        "received_rate_eps_window": rate(rows, "events_received", start + 2, end - 1),
        "processed_rate_eps_window": rate(rows, "events_processed", start + 2, end - 1),
        "processed_rate_eps_overall": d["events_processed"] / max(done - start, 1e-9),
        "drain_finished_after_secs": done - start,
        "alerts_per_processed": d["alerts_written"] / max(d["events_processed"], 1),
        "max_event_queue_usage": max(r.get("event_queue_usage", 0) for r in rows),
        "max_rule_matching_queue_usage": max(r.get("rule_matching_queue_usage", 0) for r in rows),
        "max_alerts_queue_usage": max(r.get("alerts_queue_usage", 0) for r in rows),
        "samples": len(rows),
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    if sys.argv[1] == "send":
        send(sys.argv[2], float(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
    elif sys.argv[1] == "sample":
        sample(float(sys.argv[2]), sys.argv[3])
    elif sys.argv[1] == "summarize":
        summarize(sys.argv[2], float(sys.argv[3]), float(sys.argv[4]), sys.argv[5:])
    else:
        sys.exit("usage: send CORPUS SECS LOCATIONS OUT | sample SECS OUT"
                 " | summarize SAMPLES START SECS SENT...")
