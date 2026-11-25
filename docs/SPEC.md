# rulelanes specification

Date: 2026-11-22. Status: DRAFT. Name (`rulelanes`) and licence (GPL-3.0-only,
changed from Apache-2.0 on 2026-11-22) are decided. Items marked TBD are open decisions for
Evan. Items marked "verify in M0" are from memory and must be checked
against current documentation before code depends on them.

## 1. Purpose

Security event engines decode a log line into fields, then match it against
a tree of rules. Wazuh's `analysisd` does this behind locked queues and
drops events when the queues fill. `rulelanes` does the same job as an
assembly line of pinned stages with batched lock-free handoff, and proves
its output against Wazuh itself.

It is a library, a command-line tool and later a service. It is not a
replacement for the Wazuh manager: it has no agent management, no indexer
and no dashboard.

## 2. Why this should work

From `../paralanes/atlas/runs/ryzen/2026-11-22-pipeline-3.json`
(`stagelanes-bench`, M6): a source, parse and 4-worker pipeline with 0.5 µs
of parse and 4 µs of work per item held p99 at 10.6 µs at 50% load and
11.1 µs at 90%, with zero allocations on stage cores after start-up. Decode
and match is the same shape with more work per item. Whether it holds with
real regex work is what M2 measures.

No GPU is used. `../paralanes/atlas/crossover.md` shows the GPU loses where
the CPU has fast paths, and CPU SIMD regex is one.

## 3. Requirements

| # | Requirement | How it is tested |
| --- | --- | --- |
| R1 | For supported syntax, alerts equal Wazuh's | A corpus of generated log lines runs through `wazuh-logtest` in the Wazuh container and through the reference engine with the same decoders and rules. Decoder name, extracted fields, rule id, level and groups must be equal for every line (M1 also compares decoder parent, rule description and the alert flag; the oracle loads only the ruleset under test, see `docs/status/M1.md`) |
| R2 | Unsupported syntax is refused, not ignored | Loading a decoder or rule that uses an unsupported element or attribute fails and names the file, the rule and the element |
| R3 | The pipeline equals the reference engine | The staged pipeline and the single-threaded reference engine produce the same alerts, in the same per-source order, for the corpus and for 10,000 generated cases |
| R4 | No event is lost | Events in equals events out plus events rejected, with every reject counted by reason. A full link applies back-pressure to the input |
| R5 | Latency holds at load | p99 from receipt to alert at 90% of measured capacity is at most 3× p99 at 50% (the `stagelanes` R2 rule), with evenly spaced arrivals (decided by Evan 2026-11-24). Poisson arrivals are still measured and published, not judged by this rule: random arrivals at 90% load queue for tens of service times even without stalls |
| R6 | Throughput is measured against Wazuh | Events per second and p99 for the same ruleset and corpus, `rulelanes` and `analysisd` on the same machine, both in a run file. Whichever wins is published |
| R7 | Stateful rules stay correct when sharded | Frequency and timeframe rules give the same alerts with 1 and with N match workers. Events are routed to workers by the rule's grouping key |
| R8 | Stage cores follow the stage rules | After start-up: no lock and no system call on decode and match stages. Allocations per event are counted and reported; the target is zero, and M2 records what is reached |
| R9 | Windows and Linux from one tree | CI builds and tests both. OS-specific code only in `platform` modules |
| R10 | Rules are data, not code | Changing a ruleset needs no rebuild; a reload swaps the compiled rule set between batches |

## 4. Supported syntax

M0 surveys the stock Wazuh ruleset inside the container and counts how often
each decoder and rule element and attribute appears. The supported subset
for M1 is chosen from that count, most used first, and listed in
`docs/syntax.md` with the count beside each item.

Expected M1 subset (checked in M0; the chosen subset and the counts are in
`docs/syntax.md`, which is authoritative):

- **Decoders:** `prematch`, `program_name`, `parent`, `regex`, `order`,
  `offset`, the pattern types (`osregex` and `pcre2` for `prematch` and
  `regex`; `osmatch`, `osregex` and `pcre2` for `program_name`; corrected
  in M0: decoder `prematch` and `regex` do not accept `osmatch`), and the
  JSON decoder.
- **Rules:** `if_sid`, `if_group`, `match`, `regex`, `decoded_as`,
  `field`, `srcip`, `dstip`, `srcport`, `dstport`, `user`, `program_name`,
  `hostname`, `id`, `level`, `description`, `group`, `options` (the common
  ones), and `overwrite`.
- **Later (M3):** `frequency`, `timeframe`, `if_matched_sid`,
  `if_matched_group`, `same_*` and `different_*`, `ignore`.
- **Not planned:** active response, CDB lists (TBD), `<list>` lookups
  (TBD), syscheck, rootcheck, SCA, vulnerability detection.

Wazuh's own `osregex` and `osmatch` pattern languages are not standard
regex. They are translated to an internal form with their exact semantics;
the translation is tested against `wazuh-logtest` on generated patterns and
inputs.

## 5. Architecture

```
input ──► pre-decode ──► decode ──► route ──► match (N workers) ──► output
(syslog,   (timestamp,   (parent     (by       (rule tree,           (JSON
 JSON       hostname,     prematch,   grouping  per-worker state)     lines)
 lines)     program)      child       key)
                          regex)
```

- One pinned thread per stage; `stagelanes-pipe` links between them; items
  are handles to pooled blocks (`stagelanes-mem`), never owned strings.
- Decoders compile to a prefilter (program name and literal prefixes) and
  then the patterns, so most decoders are skipped without running a regex.
- Rules compile to the Wazuh rule tree. Children are tried in Wazuh's
  order, because the first match wins and order is part of R1.
- Stateful rules keep their counters in the match worker that owns the
  grouping key, so no state is shared between workers.

### Crates

| Crate | Holds |
| --- | --- |
| `rulelanes-model` | Event, field table, alert, compiled decoder and rule types. No I/O |
| `rulelanes-syntax` | XML loading for decoders and rules; `osregex` and `osmatch` translation; load-time errors (R2) |
| `rulelanes-engine` | The single-threaded reference engine: pre-decode, decode, match |
| `rulelanes-pipe` | The staged pipeline on `stagelanes` |
| `rulelanes-oracle` | Test support: drives `wazuh-logtest` in the container and compares (R1). Dev-only |
| `rulelanes-bench` | Load generator and benchmark; writes run files |
| `rulelanes` | CLI: `logtest`, `check` (load a ruleset and report unsupported syntax), later `serve` |

## 6. The oracle

- Wazuh runs as the official single-node Docker deployment on Docker
  Desktop. M0 records the image tags and the compose file used, under
  `oracle/`.
- The oracle version is the current stable 4.x release (4.14.10 in M0, the
  line Evan's UniFi decoder and rules were tested on), because 5.0
  replaces `analysisd` with a new engine. TBD: when to add 5.x.
- `wazuh-logtest` is driven through its documented interface (checked in
  M0: the command-line tool `/var/ossec/bin/wazuh-logtest` and the API
  endpoints `PUT /logtest` and `DELETE /logtest/sessions/{token}`; the
  oracle uses the API because it returns JSON), not by scraping the
  dashboard.
- Test decoders and rules are written here and copied into the container's
  custom ruleset directories for the run.

## 7. Milestones

| M | Title | Gate |
| --- | --- | --- |
| M0 | Setup, landscape and syntax survey | Wazuh runs in Docker and answers a `wazuh-logtest` query from a script; `docs/landscape.md` covers existing engines (Wazuh 5 engine, Sigma engines, Falco, Vector, any Rust Wazuh-rule engine) with a go or no-go; `docs/syntax.md` holds the element counts and the M1 subset |
| M1 | Loader, reference engine, `logtest` | R1 and R2 pass for the M1 subset on a generated corpus of at least 1,000 lines over at least 20 decoders and 50 rules written here; `rulelanes check` reports what share of the stock ruleset loads |
| M2 | Staged pipeline and benchmark | R3, R4, R5 and R8 pass; R6 is measured and published |
| M3 | Stateful rules and sharding | R7 passes; R1 extended to the M3 syntax |
| M4 | Service: syslog and JSON inputs, JSON output, reload | R10 passes; a 24-hour soak loses no event |
| M5 | Sigma rules | A Sigma subset compiles to the same rule tree; checked against a reference Sigma engine |
| M6 | Archive re-scan (research) | A measured CPU baseline; a written case for or against a `bytelanes` multi-pattern op |

## 8. Risks

| Risk | Effect | Answer |
| --- | --- | --- |
| Wazuh's matching order and pattern semantics are subtle | R1 fails on edge cases | The oracle runs on every case; the supported subset grows only as it passes |
| Regex and field extraction allocate | R8's zero target is missed | Count and publish; use pooled blocks and offsets into the event, not owned strings |
| `analysisd` is already fast enough on one machine | R6 is a negative result | Publish it; the tail (R5) and the no-drop rule (R4) may still be the value |
| Wazuh 5.0 changes the rule format | The target moves | 4.x is the stated target; M0 records what 5.0 changes |
| Windows tails are wide | R5 fails on the first machine | Record it; repeat on Linux before drawing a conclusion |

## 9. Out of scope

Agent enrolment and the agent wire protocol, the indexer and dashboard,
file integrity monitoring, and any GPU work before M6.
