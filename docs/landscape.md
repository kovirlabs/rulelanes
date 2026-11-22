# Landscape: existing decode-and-match engines

Checked 2026-11-22 (M0). Each fact carries its source. "Unverified" marks
anything that could not be confirmed from a primary source.

## Summary and decision

**Go.** No project found, in Rust or any other language, reads and evaluates
Wazuh 4.x decoder and rule XML outside Wazuh and OSSEC themselves. The
oracle (Wazuh 4.14.10) runs in Docker and answers `wazuh-logtest` queries,
so R1 can be checked against the real thing.

Two facts shape the scope:

1. **Wazuh 5.0 drops the XML format.** 4.x XML rules and decoders cannot be
   migrated to 5.x; decoders become YAML assets and rules become Sigma with
   Wazuh extensions that run on the indexer. 5.0 is not GA (newest tag
   `v5.0.0-rc2`). The 4.x XML audience will shrink once 5.0 ships, so the
   value of rulelanes is the staged engine and its no-drop and tail
   properties, with Wazuh 4.x XML as the first, oracle-checked input format
   and Sigma (M5) as the second.
2. **The Sigma side is crowded** (rsigma, sigma-rust, Hayabusa, Chainsaw,
   Tenzir). M5 should reuse or compare against `rsigma` (MIT) rather than
   assume a gap.

Licence: the Wazuh ruleset is GPL-2.0-only. rulelanes may read it from the
user's install at run time and must never ship it. The engine is written
from documented and observed behaviour; see `docs/status/M1.md` for how the
Wazuh source was used as a reference.

## Engines

| Engine | Language | Licence | Reads Wazuh XML | Pipeline / threading | Overlap with rulelanes |
| --- | --- | --- | --- | --- | --- |
| Wazuh 4.x `analysisd` | C | GPL-2.0-only (code and ruleset) | Yes (it defines it) | Per-type decode queues, a rule-matching queue, output queues; thread pools sized to cores; queues default to 16384 entries and drops are counted | Direct: this is the oracle and the R6 comparison |
| Wazuh 5.0 engine | C++ (from repo layout, unverified) | AGPL-3.0-or-later | No: YAML decoder assets, Sigma-based rules on the indexer | Not checked | Replaces the target format; out of scope until Evan decides (TBD in SPEC §6) |
| OSSEC-HIDS | C | GPL-2.0 | Its own XML dialect (diverged from Wazuh) | Not checked | A second XML engine; not a target |
| Falco | C++ | Apache-2.0 | No (YAML rules on syscall/plugin events) | Single-threaded by default; multi-thread support is a draft PR on hold | Low; shows the single-stream limit the roadmap cites |
| Vector | Rust | MPL-2.0 | No (VRL transforms, no detection rules) | Not checked | Possible ingest/transport stage only |
| rsigma | Rust | MIT | No (Sigma) | Streaming daemon with bounded channels between stages | M5: reuse or benchmark against |
| sigma-rust | Rust | MIT OR Apache-2.0 | No (Sigma) | Library: one rule against one event | M5 candidate |
| Hayabusa | Rust | AGPL-3.0 (rules DRL-1.1) | No (Sigma, Windows event logs) | Multi-threaded batch hunts | Low (batch EVTX) |
| Chainsaw | Rust | GPL-3.0 | No (Sigma via mapping, TAU engine) | Not stated | Low (batch hunts) |
| Zircolite | Python | LGPL (per README) | No (Sigma converted to SQL over SQLite) | Parallel workers | Low |
| pySigma | Python | LGPL-2.1 | No (converter only, does not evaluate) | n/a | None |
| Tenzir | C++ | BSD-3-Clause | No (`sigma` operator in a pipeline) | Not stated | Low |

Third-party Wazuh/OSSEC XML engines: none found. GitHub search for Rust
repositories mentioning Wazuh found API clients, MCP servers and ETL tools,
none of them a decoder or rule engine; "ossec rules" in Rust found nothing.
Wazuh's own tools are `wazuh-logtest` and `wazuh-regex`. This search was by
keyword and not exhaustive.

## Wazuh facts that the spec depends on

- Newest stable 4.x: **4.14.10** (GitHub "Latest"; release notes dated
  5 November 2026). 4.14.11 is at RC2. Wazuh 5.0 is at RC2, not GA.
- `wazuh-logtest` has a command-line tool (`/var/ossec/bin/wazuh-logtest`,
  options `-d -h -U -l -V -q -v`, one log per input line) and two API
  endpoints: `PUT /logtest` (body: `event`, `log_format`, `location`,
  optional `token` to reuse a session) and `DELETE /logtest/sessions/{token}`.
  Both were exercised against the container in M0. The API returns the
  structured result as JSON, so the oracle uses the API.
- Logtest sessions keep state (`firedtimes`, frequency history). Sessions
  time out after 15 minutes by default, at most 64 are open.
- The 4.x LICENSE covers "the source code, as well as decoders, rules and
  any other data file": GPL-2.0, no "or later".

## Sources

- Wazuh 4.14.10 LICENSE: https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/LICENSE
- Wazuh releases: https://github.com/wazuh/wazuh/releases ; release notes https://documentation.wazuh.com/4.14/release-notes/release-4-14-10.html
- wazuh-docker tags: `git ls-remote --tags https://github.com/wazuh/wazuh-docker.git` (run 2026-11-22)
- Analysisd queues: https://documentation.wazuh.com/current/user-manual/manager/wazuh-server-queue.html ; internal options https://documentation.wazuh.com/4.14/user-manual/reference/internal-options.html
- EPS limits: https://documentation.wazuh.com/4.8/user-manual/reference/ossec-conf/global.html
- wazuh-logtest tool: https://documentation.wazuh.com/4.14/user-manual/reference/tools/wazuh-logtest.html
- Logtest API: https://documentation.wazuh.com/4.14/user-manual/ruleset/testing.html
- Wazuh 5.0 concepts: https://documentation.wazuh.com/5.0-rc/user-manual/data-analysis/key-concepts.html ; migration https://documentation.wazuh.com/5.0-beta/migration-to-5x/transition-plan.html ; engine licence https://raw.githubusercontent.com/wazuh/wazuh/main/LICENSE
- OSSEC-HIDS: https://github.com/ossec/ossec-hids
- Falco: https://github.com/falcosecurity/falco ; multi-thread PR https://github.com/falcosecurity/falco/pull/3833
- Vector: https://github.com/vectordotdev/vector
- rsigma: https://github.com/timescale/rsigma ; sigma-rust: https://docs.rs/crate/sigma-rust/latest ; Hayabusa: https://github.com/Yamato-Security/hayabusa ; Chainsaw: https://github.com/WithSecureLabs/chainsaw ; Zircolite: https://github.com/wagga40/Zircolite ; pySigma: https://github.com/SigmaHQ/pySigma ; Tenzir: https://github.com/tenzir/tenzir
- wazuh-regex tool: https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-regex.html
