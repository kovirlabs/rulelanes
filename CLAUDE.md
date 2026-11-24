# rulelanes

A security event decode-and-match engine in Rust. It reads Wazuh-format
decoders and rules (later Sigma rules) and runs parse → decode → match →
write as pinned `stagelanes` stages. It is checked against a real Wazuh
manager: for the syntax it supports, it must raise the same alerts as
`wazuh-logtest`.

Read `docs/SPEC.md` before any change. It is the source of truth. The
background is `../paralanes/docs/ROADMAP.md` (project 1).

> DRAFT. Items marked TBD are open decisions for Evan.

## Repo map

| Repo | Role | Used here as |
| --- | --- | --- |
| `rulelanes` (this repo) | The engine, its CLI, its benchmark | — |
| `../stagelanes` | Pinned stages, rings, pinned memory | Path dependency, read-only. `stagelanes-pipe` is on its `main` |
| `../flowlanes` | Flow collector; a producer of events for this engine | Sibling; no code dependency |
| `../paralanes` | Roadmap and the measurements this design rests on | Read-only |

Never edit `stagelanes`, `bytelanes`, `diagsteno` or `paralanes` from here.
If this repo needs a change in one of them, write it under Requests in the
status file and stop that task.

## Hard rules

- **Agents push their own branches and open pull requests without
  asking** (remote `kovirlabs/rulelanes`; never push to `main`). Agents
  merge a pull request only when Evan asks for that merge. They never tag
  or publish. (Changed by Evan 2026-11-23.)
- **Run files carry no local paths.** Record the program by file name, not
  its directory, and no user or home directory anywhere in a run file.
- **One milestone per session unless Evan says otherwise.** Stop at the
  gate.
- **The oracle decides.** `wazuh-logtest` on a real Wazuh manager defines
  correct output for supported syntax. The single-threaded reference engine
  must match it, and the staged pipeline must match the reference engine.
  Unsupported syntax is rejected at load with a clear message, never
  ignored.
- **No unmeasured numbers.** A performance figure appears in a README or
  status file only with the run file that produced it. Every run file
  records machine, OS and build number, Rust version, the Wazuh version
  compared against, the ruleset used and the exact command.
- **A negative result is a result.** If `analysisd` is faster, publish that.
- **No Wazuh content in this repo.** Wazuh's code, decoders and rules are
  GPL-2.0-only (checked in its v4.14.10 LICENSE: "version 2", no "or
  later"), which is not compatible with GPL-3.0. Tests use decoders,
  rules and logs written or generated here. Runs against the stock ruleset
  read it from the Wazuh container at run time. Evan's UniFi decoder and
  rules (MIT, his own work, not Wazuh content) are pinned git submodules
  under `third_party/unifi/`.
- **Data rule.** Generated logs, or logs Evan confirms he owns. Never
  commit logs from a real network, an employer or a customer.
- **`unsafe` is forbidden** (`#![forbid(unsafe_code)]` in every crate).
- **No `#[cfg(target_os)]`** outside a module named `platform`.
- **Look up current docs** before using any crate API, the Wazuh ruleset
  syntax, or Docker images. Do not write them from memory.
- **Licence compatibility.** This repo is GPL-3.0-only (decided 2026-11-22,
  changed from Apache-2.0). Every new dependency must be GPL-3.0 compatible:
  MIT, Apache-2.0, BSD, ISC, Zlib, MPL-2.0, LGPL-3.0 or GPL-3.0 are fine;
  GPL-2.0-only, SSPL, BUSL and proprietary licences are not.
- Crates carry `publish = false` until Evan removes it.

## Status files

Each milestone writes `docs/status/M<n>.md`:

```markdown
# M<n>: <title>
Machine: <name>   Date: <YYYY-MM-DD>
## Built
## Gate results
<check> | pass/fail | command that produced it
## Open questions for Evan
## Requests for other repos
```

Run files go in `runs/<machine>/<YYYY-MM-DD>-<name>.json`. Do not edit a
run file after it is committed.

## Branches

- `main` is Evan's. Work on `m<n>-<short-topic>`.
- Small commits, one logical change each. Run fmt, clippy and tests before
  each commit.

## Commands

```
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p rulelanes -- logtest --decoders <dir> --rules <dir>   # one log line per stdin line
cargo run --release -p rulelanes-bench -- --machine <name> --machine-desc <text> --date <YYYY-MM-DD> [--priority time-critical] [--repeats N] --note <text>
RUN_MACHINE=<name> RUN_DATE=<YYYY-MM-DD> RUN_NOTE=<text> oracle/analysisd-bench.sh [SECS] [SENDERS]   # R6, oracle container only
```

Set `RULELANES_SKIP_LIVE=1` to skip the R1 test against the live oracle
container (it takes about 200 s).

## Machines

The first build machine is the Ryzen 7 5700X desktop (Windows 11, Docker
Desktop). Windows cannot isolate a core (see
`../paralanes/docs/experiments/2026-11-22-windows-isolation.md`), so tail
latency figures from it are provisional until repeated on Linux.

## Open decisions (TBD)

- GitHub owner (decided 2026-11-22: the name `rulelanes` is final and the
  licence is GPL-3.0-only, changed from Apache-2.0 the same day)
- Whether status and run files move to `paralanes` like the other repos'
- Which Wazuh version is the oracle once 5.0 ships its new engine
