# Wazuh in Docker: the oracle and the live manager

Two separate Wazuh 4.14.10 deployments run on this machine:

- **The oracle** (`rulelanes-oracle-manager`, compose project
  `rulelanes-oracle`): a manager-only container used only for
  `wazuh-logtest` runs (R1). `wazuh-logtest` on it defines correct output
  (SPEC §6). Oracle runs edit its `ossec.conf` for their duration.
- **The live manager** (the official single-node stack: manager, indexer,
  dashboard): Evan's real server. It receives UniFi syslog. No test touches
  it; the tools refuse it unless told `--live` explicitly.

Nothing from Wazuh is committed here: the single-node deployment files live
in a git-ignored checkout, and only their identity (tag, commit, hashes,
image digests) is recorded below.

## Identity (recorded 2026-11-22)

| Item | Value |
| --- | --- |
| Deployment | official `wazuh/wazuh-docker`, directory `single-node/` |
| Tag | `v4.14.10` (newest stable 4.x tag; `v4.14.11-rc1`/`-rc2` and `v5.0.0-rc2` exist but are pre-releases) |
| Commit | `76ddb88b9c8b618a254a287f2684f93d3c5ac2f4` |
| `single-node/docker-compose.yml` sha256 | `129b43cde3e1126912f0111c309e9739710d44741745471a92310b4d6c895eb6` |
| `single-node/generate-indexer-certs.yml` sha256 | `c37d4b4183801f102d0ab366de5c5fa8c28ed881eebe72e4b436ccb8455adfa8` |
| `single-node/config/wazuh_cluster/wazuh_manager.conf` sha256 | `5ac9b51c67d805fbbf5dc9dbc8d06396dbd8b6e7f5d11537dd93c1c55bee90e4` |
| `wazuh/wazuh-manager:4.14.10` | `sha256:eabfa7ee4e63acb51c2130fa0583e30f843d030b091cf45a4fbd93d78fa21517` |
| `wazuh/wazuh-indexer:4.14.10` | `sha256:1d2aeadb9de88c6d17ce12030606425deca5a210cdf5c87008843da38eb629ea` |
| `wazuh/wazuh-dashboard:4.14.10` | `sha256:4d48be7210a291c00a2bd148cbd8bd61a25876e947b81790fd03f7d2aabda95a` |
| `wazuh/wazuh-certs-generator:0.0.5` | `sha256:1be9f9abfb6a37ac7bd3d6d707e1b43589c2b81b23c01a46992e93832795abf9` |
| `wazuh-logtest -V` | `v4.14.10` (banner "Starting wazuh-logtest v4.14.10") |
| Docker | Docker Desktop, engine 29.8.2, Compose v5.5.1 |

The compose file is not copied into this repo because it carries a GPLv2
header (GPL-2.0-only), which is not compatible with this repo's GPL-3.0-only.
The hashes above identify it.


## Files here

| File | What it is |
| --- | --- |
| `compose.oracle.yml` | The oracle: manager only, API on `127.0.0.1:55001`, no syslog or agent ports, no indexer |
| `compose.live.yml` | Override for the live single-node stack: UDP 514 published on all interfaces, every other port on `127.0.0.1`; passwords from `secrets.env` |
| `secrets.env` | **Git-ignored.** All generated passwords (oracle and live). Never commit, never print |
| `live-passwords.sh` | Replaces the upstream default passwords of the live stack with those in `secrets.env` (official procedure) |
| `live-syslog.sh` | Adds the syslog `<remote>` block to the live manager and recreates it |
| `live-archive.sh` | Turns the live manager's full event archive (`logall`) on or off and recreates it |
| `install-unifi.sh` | Installs the UniFi decoder and rules from the submodules in `third_party/unifi/` (oracle by default, `--live` for the live manager) |
| `logtest.py` | Driver that runs inside a manager container and calls `PUT /logtest` and `DELETE /logtest/sessions/{token}`; needs `WAZUH_API_PASSWORD` |
| `logtest.sh` | Host wrapper: `printf '%s\n' "<log line>" \| oracle/logtest.sh` (oracle), or `oracle/logtest.sh --live` |
| `restore-ruleset.sh` | Puts the stock `<ruleset>` back after an interrupted oracle run (oracle by default) |
| `survey_syntax.py` | Counts decoder and rule elements in the stock ruleset (M0) |

## The oracle

```
docker compose -f oracle/compose.oracle.yml --env-file oracle/secrets.env up -d
oracle/install-unifi.sh
printf '%s\n' "<log line>" | oracle/logtest.sh
```

Without an indexer the image's Filebeat keeps logging connection errors;
analysisd, remoted, the API and logtest run normally (checked). The Rust
oracle (`rulelanes-oracle`) targets this container and refuses any other
unless `RULELANES_ALLOW_NON_ORACLE_TARGET=1`.

## The live stack

Setup (what was run, from `oracle/wazuh-docker/single-node`):

```
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.10 oracle/wazuh-docker
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose -f docker-compose.yml -f ../../compose.live.yml --env-file ../../secrets.env up -d
../../live-passwords.sh        # once: replaces the upstream default passwords
../../live-syslog.sh           # syslog remote block (see below)
../../install-unifi.sh --live  # UniFi decoder and rules
```

Stop, start, recreate (from `oracle/wazuh-docker/single-node`; always pass
the override and the env file, compose refuses to start without them):

```
docker compose -f docker-compose.yml -f ../../compose.live.yml --env-file ../../secrets.env stop
docker compose -f docker-compose.yml -f ../../compose.live.yml --env-file ../../secrets.env start
docker compose -f docker-compose.yml -f ../../compose.live.yml --env-file ../../secrets.env up -d --force-recreate
```

Use `up -d --force-recreate` rather than `docker restart` for the manager:
on a plain restart the image's init script fails (multigroups copy) before
it copies the mounted `ossec.conf`, so configuration changes are not
applied (seen with 4.14.10). `vm.max_map_count` in the Docker Desktop VM
was already 262144.

## Credentials and certificates

- Every upstream default password has been replaced (indexer `admin`,
  `kibanaserver`, `kibanaro`, `logstash`, `readall`, `snapshotrestore`;
  API `wazuh-wui` and `wazuh`; the dashboard logs in as indexer `admin`).
  The passwords are in `oracle/secrets.env` only. The indexer hashes are in
  the checkout's `config/wazuh_indexer/internal_users.yml` and the
  dashboard's API password in `config/wazuh_dashboard/wazuh.yml`; both are
  inside the git-ignored checkout.
- TLS certificates and keys: `oracle/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/`
  (git-ignored, with `*.pem` and `*.key` also ignored).

## Receiving UniFi syslog

Manager side: **ready.**

- The manager listens on UDP 514 (`<remote>` with `<connection>syslog`,
  `<protocol>udp`), published on all host interfaces; the UniFi decoder and
  rules are installed; the stock ruleset is active.
- **Source address.** With Docker Desktop on Windows the manager sees every
  syslog packet as coming from the gateway of the compose network
  (`single-node_default`, 172.20.0.1 when checked), not from the sender:
  a UniFi sample sent over UDP from this PC, both to 127.0.0.1 and to the
  PC's LAN address, arrived with `location` 172.20.0.1 and fired rule
  100301. So `allowed-ips` is that gateway (`live-syslog.sh` reads it from
  Docker), it cannot tell senders apart, and Wazuh records 172.20.0.1, not
  the gateway's address, as the event source. The gateway is identified by
  the `unifi_*` fields and the syslog hostname in the message, not by the
  source address. A packet from a real LAN sender was not tested (no device
  was configured); it is expected to look the same.
- **Windows firewall.** Inbound rule "rulelanes Wazuh syslog UDP 514 (LAN)":
  allow, UDP, local port 514, remote address LocalSubnet, Private profile.
  Because the manager cannot filter by sender, this rule is the sender
  filter; narrow it to the gateway if wanted:
  `Set-NetFirewallRule -DisplayName "rulelanes Wazuh syslog UDP 514 (LAN)" -RemoteAddress <gateway-ip>`.
- **UniFi side (Evan's action):** UniFi Network, Integration > System
  Logging / SIEM, choose SIEM Server, server `<this-pc>`, port 514. The
  decoder README expects syslog-framed CEF on port 514 (any port works if
  the manager listens there); leave the controller's syslog debug option
  off.

## Ruleset modes for R1

R1 runs load only rulelanes' test decoders and rules into the oracle (see
`docs/status/M1.md`); the oracle's stock configuration is restored after
each run.
## Docker credential helper note (this machine)

From a non-interactive agent shell, `docker pull` failed with "error getting
credentials ... A specified logon session does not exist" (the Docker
Desktop credential store needs an interactive logon). Pulls were done with a
temporary `DOCKER_CONFIG` whose `credsStore` pointed at a helper that
reports "no credentials" (anonymous pulls). An interactive shell does not
need this.
