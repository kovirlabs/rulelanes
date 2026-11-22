//! Oracle tool.
//!
//! ```text
//! rulelanes-oracle corpus                write testdata/corpus/corpus.log
//! rulelanes-oracle record                run the corpus through wazuh-logtest (live
//!                                        container) and write the fixture
//! rulelanes-oracle compare [--live]      compare the engine with the fixture, or
//!                                        with the live container
//! ```
//! Run from the repository root.
#![forbid(unsafe_code)]

use rulelanes_oracle::{FixtureRow, Observed, Oracle, corpus};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const CORPUS: &str = "testdata/corpus/corpus.log";
const FIXTURE: &str = "testdata/fixtures/r1-wazuh-4.14.10.jsonl";
const LOCATION: &str = "rulelanes";

fn files(dir: &str) -> Vec<PathBuf> {
    rulelanes_syntax::xml_files(Path::new(dir)).unwrap_or_default()
}

fn lines() -> Vec<String> {
    std::fs::read_to_string(CORPUS)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("corpus") => {
            let c = corpus::generate(corpus::SEED, corpus::SIZE);
            let mut text = c.join("\n");
            text.push('\n');
            if let Err(e) = std::fs::write(CORPUS, text) {
                eprintln!("{CORPUS}: {e}");
                return ExitCode::from(1);
            }
            println!("wrote {} lines to {CORPUS}", c.len());
            ExitCode::SUCCESS
        }
        Some("record") => record(),
        Some("compare") => compare(args.iter().any(|a| a == "--live")),
        _ => {
            eprintln!("usage: rulelanes-oracle corpus | record | compare [--live]");
            ExitCode::from(2)
        }
    }
}

fn record() -> ExitCode {
    let oracle = Oracle::from_env();
    if let Err(e) = oracle.available() {
        eprintln!("oracle not available: {e}");
        return ExitCode::from(1);
    }
    let lines = lines();
    let results = match oracle.run_isolated(
        &files("testdata/ruleset/decoders"),
        &files("testdata/ruleset/rules"),
        &lines,
        LOCATION,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("oracle run failed: {e}");
            return ExitCode::from(1);
        }
    };
    let rows: Vec<FixtureRow> = lines
        .iter()
        .zip(&results)
        .map(|(l, v)| FixtureRow {
            event: l.clone(),
            observed: Observed::from_json(v),
        })
        .collect();
    let header = serde_json::json!({
        "what": "wazuh-logtest results for testdata/corpus/corpus.log with testdata/ruleset only",
        "wazuh": oracle.version().unwrap_or_default(),
        "container": oracle.container,
        "location": LOCATION,
        "lines": rows.len(),
    });
    if let Err(e) = rulelanes_oracle::write_fixture(Path::new(FIXTURE), &header, &rows) {
        eprintln!("{FIXTURE}: {e}");
        return ExitCode::from(1);
    }
    println!("recorded {} oracle results to {FIXTURE}", rows.len());
    ExitCode::SUCCESS
}

fn compare(live: bool) -> ExitCode {
    let set = match rulelanes_syntax::load_files(
        &files("testdata/ruleset/decoders"),
        &files("testdata/ruleset/rules"),
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("load failed: {e}");
            return ExitCode::from(1);
        }
    };
    let engine = rulelanes_engine::Engine::new(set);
    let expected: Vec<FixtureRow> = if live {
        let oracle = Oracle::from_env();
        let lines = lines();
        match oracle.run_isolated(
            &files("testdata/ruleset/decoders"),
            &files("testdata/ruleset/rules"),
            &lines,
            LOCATION,
        ) {
            Ok(r) => lines
                .iter()
                .zip(&r)
                .map(|(l, v)| FixtureRow {
                    event: l.clone(),
                    observed: Observed::from_json(v),
                })
                .collect(),
            Err(e) => {
                eprintln!("oracle run failed: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        match rulelanes_oracle::read_fixture(Path::new(FIXTURE)) {
            Ok((_, rows)) => rows,
            Err(e) => {
                eprintln!("{FIXTURE}: {e}");
                return ExitCode::from(1);
            }
        }
    };
    let mut bad = 0;
    for row in &expected {
        let got = Observed::from_outcome(&engine.process(&row.event, LOCATION));
        let d = row.observed.diff(&got);
        if !d.is_empty() {
            bad += 1;
            if bad <= 40 {
                println!("MISMATCH {}", row.event);
                for x in d {
                    println!("    {x}");
                }
            }
        }
    }
    println!(
        "{} of {} lines equal ({} mismatches) against {}",
        expected.len() - bad,
        expected.len(),
        bad,
        if live { "the live container" } else { FIXTURE }
    );
    if bad == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
