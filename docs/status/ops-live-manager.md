# ops-live-manager: separate oracle, live manager hardening, GPL-3.0, UniFi submodules
Machine: Ryzen 7 5700X desktop (Windows 11, Docker Desktop engine 29.8.2)   Date: 2026-11-22

Not a milestone and not M2: no pipeline work.

## Built

1. **Separate oracle.** `oracle/compose.oracle.yml`: container
   `rulelanes-oracle-manager` (project `rulelanes-oracle`), image
   `wazuh/wazuh-manager:4.14.10`, API on `127.0.0.1:55001`, no syslog or
   agent ports, no indexer. Checked first: the docs and community threads
   say the image always starts Filebeat (no switch to turn it off); in
   practice Filebeat logs connection errors and analysisd, remoted, the API
   and logtest run normally. UniFi content installed there too.
   `logtest.sh`, `restore-ruleset.sh`, `install-unifi.sh` and the
   `rulelanes-oracle` crate now target it by default. The crate refuses any
   other container unless `RULELANES_ALLOW_NON_ORACLE_TARGET=1`; the shell
   tools reach the live manager only with `--live`. `logtest.py` has no
   built-in password any more.
2. **Live manager hardening.** `oracle/compose.live.yml` (replaces
   `compose.localhost.yml`): UDP 514 on all interfaces, everything else on
   127.0.0.1, passwords taken from the git-ignored `oracle/secrets.env`
   (compose refuses to start without it). `oracle/live-passwords.sh`
   follows "Changing the default password of Wazuh users" (Wazuh 4.14
   Docker docs): new hashes for all six indexer internal users,
   `securityadmin.sh`, dashboard `wazuh.yml`, recreate, and the API user
   `wazuh` changed through the API. `oracle/live-syslog.sh` adds the syslog
   `<remote>` block (UDP 514, `allowed-ips` = the compose network gateway)
   and recreates the manager. A Windows firewall rule allows UDP 514 from
   the local subnet on the Private profile.
3. **GPL-3.0-only.** `LICENSE` is the GPL-3.0 text from gnu.org;
   `license = "GPL-3.0-only"` in the workspace (every crate inherits it);
   `CLAUDE.md`, `docs/SPEC.md`, `oracle/README.md` and file headers
   updated. There is no README in this repo, so none was changed. flowlanes
   stays Apache-2.0.
4. **UniFi submodules.** `third_party/unifi/wazuh-unifi-decoder` at
   `3a9a2d522840ed876e3f634232ea36392d94478f` and
   `third_party/unifi/wazuh-unifi-rules` at
   `36193597001b99c94994972412253c3c712fcb93` (MIT, LICENSE files in each).
   Submodules rather than copies: they pin the exact commit, keep the
   owner's repos as the source, and bring their LICENSE files along.
   `install-unifi.sh` installs from them. The decoder repo's
   `samples/events.log` (anonymised events from Evan's network, per its
   README) comes along as part of his repo.
5. Docs: `oracle/README.md` rewritten (oracle, live stack, credentials,
   "Receiving UniFi syslog"), this file.

## Checks

check | result | command that produced it
--- | --- | ---
Oracle container runs without an indexer | pass: analysisd, remoted, apid running | `docker compose -f oracle/compose.oracle.yml --env-file oracle/secrets.env up -d`; `docker exec rulelanes-oracle-manager /var/ossec/bin/wazuh-control status`
Oracle has stock + UniFi | pass: sshd sample → rule 5710 (level 5), UniFi README sample → decoder `ubiquiti`, rule 100301 (level 10) | `oracle/install-unifi.sh`; `printf ... \| oracle/logtest.sh`
Tools refuse the live manager | pass: `logtest.sh` exits 2 with a refusal; the crate's `available()` refuses other names | `WAZUH_MANAGER_CONTAINER=single-node-wazuh.manager-1 oracle/logtest.sh`
R1 live against the new oracle | pass, 1,200 of 1,200 equal; output identical to the recorded fixture, so nothing was re-recorded | `cargo test -p rulelanes-oracle --test r1 -- --nocapture` (205 s)
New passwords work, old defaults refused | pass: indexer `admin`, `kibanaserver`, `logstash` 200 with new / 401 with default; `kibanaro`, `readall`, `snapshotrestore` 403 (authenticated, no permission on `/`) with new / 401 with default; API `wazuh-wui` and `wazuh` 200 / 401; dashboard `admin` 200 / 401; oracle API `wazuh-wui` 200 / 401 | `curl -K -` with credentials on stdin against 127.0.0.1:9200, :55000, :443, :55001 (passwords read from `oracle/secrets.env`, never echoed)
securityadmin applied the new users | pass ("Done with success") | `oracle/live-passwords.sh`
Live manager has stock + UniFi after the changes and recreates | pass: sshd → 5710, UniFi → 100301 | `oracle/install-unifi.sh --live`; `printf ... \| oracle/logtest.sh --live`
Live manager listens on syslog | pass: "Listening on port 514/UDP (syslog)" in `ossec.log` | `oracle/live-syslog.sh`
UniFi sample over UDP reaches alerts and fires the rule | pass: sent from this PC to 127.0.0.1:514 and to the PC's LAN address:514; both in `alerts.json` with decoder `ubiquiti`, rule 100301, level 10, `location` 172.20.0.1 | `printf ... > /dev/udp/<addr>/514`; `grep <marker> /var/ossec/logs/alerts/alerts.json`
Source address the manager saw | 172.20.0.1 (gateway of the `single-node_default` compose network), for both sends | as above
Firewall rule added | pass (shell was elevated) | `New-NetFirewallRule -DisplayName "rulelanes Wazuh syslog UDP 514 (LAN)" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 514 -RemoteAddress LocalSubnet -Profile Private`
Dependencies GPL-3.0 compatible | pass: MIT, MIT OR Apache-2.0, Apache-2.0 OR MIT, Unlicense OR MIT, Zlib, (MIT OR Apache-2.0) AND Unicode-3.0; stagelanes (planned for M2) is Apache-2.0 | `cargo metadata --format-version 1`; `../stagelanes/Cargo.toml`
fmt, clippy, tests | pass | `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`

## Findings

- **Wazuh's licence:** v4.14.10 `LICENSE` grants "the GNU General Public
  License (version 2) as published by the FSF", with no "or (at your
  option) any later version" (the only "later version" text in the file is
  inside the quoted GPLv2 itself), plus an OpenSSL linking exception, and
  says it covers "the source code, as well as decoders, rules and any other
  data file". Source files carry the same "License (version 2)" header.
  So Wazuh is GPL-2.0-only, which is not compatible with GPL-3.0. The "no
  Wazuh content in this repo" rule stays.
- **NAT source.** Docker Desktop's port forward presents every syslog
  sender as 172.20.0.1, so `allowed-ips` cannot tell senders apart and
  Wazuh records 172.20.0.1 as the event source. The firewall rule is the
  sender filter. A packet from a real LAN device was not tested.
- **`docker restart` does not apply config changes** on this image: the
  init script fails at the multigroups copy before copying the mounted
  `ossec.conf`. Recreate the container instead. This is also why the
  isolated `ossec.conf` survived the earlier Docker restart (M1 incident).
- The oracle's API user `wazuh` does not accept the default password
  either (401); it was not changed, since the oracle API is local only.
- One commit (16526dd) also carries the rename of `compose.localhost.yml`
  to `compose.live.yml` (content unchanged in that commit; the new content
  is in the hardening commit).

## Open questions for Evan

- Narrow the firewall rule from LocalSubnet to the gateway's address
  (command in `oracle/README.md`).
- If the source address matters (it is always 172.20.0.1 now), the
  alternatives are host networking for the manager (not available for
  Docker Desktop's Linux VM in the same way) or a small syslog relay on
  Windows that forwards to the manager; neither was done.
- Point the UniFi controller at `<this-pc>`:514 (Integration > System
  Logging / SIEM, SIEM Server).

## Requests for other repos

None.
