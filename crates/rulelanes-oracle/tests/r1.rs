//! R1: for supported syntax, the reference engine gives what
//! `wazuh-logtest` gives.
//!
//! `recorded_fixture` runs offline against oracle output recorded from the
//! live Wazuh 4.14.10 container. `live_container` runs the same corpus
//! through the container now; it prints SKIPPED and passes when the
//! container is not running.

use rulelanes_oracle::{Observed, Oracle, corpus, read_fixture};
use std::path::{Path, PathBuf};

const LOCATION: &str = "rulelanes";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn files(dir: &str) -> Vec<PathBuf> {
    rulelanes_syntax::xml_files(&root().join(dir)).unwrap()
}

fn engine() -> rulelanes_engine::Engine {
    let set = rulelanes_syntax::load_files(
        &files("testdata/ruleset/decoders"),
        &files("testdata/ruleset/rules"),
    )
    .unwrap();
    rulelanes_engine::Engine::new(set)
}

fn corpus_lines() -> Vec<String> {
    std::fs::read_to_string(root().join("testdata/corpus/corpus.log"))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn committed_corpus_is_the_generated_one() {
    let lines = corpus_lines();
    assert_eq!(lines, corpus::generate(corpus::SEED, corpus::SIZE));
    assert!(lines.len() >= 1000);
}

fn assert_equal(rows: &[(String, Observed)], source: &str) {
    let e = engine();
    let mut bad = Vec::new();
    for (line, want) in rows {
        let got = Observed::from_outcome(&e.process(line, LOCATION));
        let d = want.diff(&got);
        if !d.is_empty() {
            bad.push(format!("{line}\n    {}", d.join("\n    ")));
        }
    }
    assert!(
        bad.is_empty(),
        "{} of {} lines differ from {source}:\n{}",
        bad.len(),
        rows.len(),
        bad.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn recorded_fixture() {
    let (header, rows) =
        read_fixture(&root().join("testdata/fixtures/r1-wazuh-4.14.10.jsonl")).unwrap();
    assert_eq!(rows.len(), corpus::SIZE, "fixture covers the whole corpus");
    let lines = corpus_lines();
    for (r, l) in rows.iter().zip(&lines) {
        assert_eq!(&r.event, l, "fixture is for a different corpus");
    }
    eprintln!("R1 offline against recorded oracle output: {header}");
    let rows: Vec<_> = rows.into_iter().map(|r| (r.event, r.observed)).collect();
    assert_equal(&rows, "the recorded oracle fixture");
}

#[test]
fn live_container() {
    if std::env::var("RULELANES_SKIP_LIVE").is_ok() {
        eprintln!("SKIPPED live_container: RULELANES_SKIP_LIVE is set");
        return;
    }
    let oracle = Oracle::from_env();
    if let Err(why) = oracle.available() {
        eprintln!("SKIPPED live_container: {why}");
        return;
    }
    let lines = corpus_lines();
    let results = oracle
        .run_isolated(
            &files("testdata/ruleset/decoders"),
            &files("testdata/ruleset/rules"),
            &lines,
            LOCATION,
        )
        .expect("oracle run");
    eprintln!("R1 live against {}", oracle.version().unwrap_or_default());
    let rows: Vec<_> = lines
        .into_iter()
        .zip(results.iter().map(Observed::from_json))
        .collect();
    assert_equal(&rows, "the live container");
}
