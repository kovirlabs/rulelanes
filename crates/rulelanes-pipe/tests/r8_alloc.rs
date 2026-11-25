//! R8: allocations made by the decode and match steps, per event, after a
//! warm-up pass over the same inputs.
//!
//! `breakdown` prints the count per decoder (run with `--nocapture`); it
//! asserts nothing and is a diagnostic.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rulelanes_engine::{Engine, decode, matcher, predecode};
use stagelanes_mem::CountingAlloc;
use stagelanes_mem::alloc_count::{arm_current_thread, disarm_current_thread};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn engine() -> Engine {
    let files = |d: &str| rulelanes_syntax::xml_files(&root().join(d)).unwrap();
    let set = rulelanes_syntax::load_files(
        &files("testdata/ruleset/decoders"),
        &files("testdata/ruleset/rules"),
    )
    .unwrap();
    Engine::new(set)
}

fn corpus() -> Vec<String> {
    std::fs::read_to_string(root().join("testdata/corpus/corpus.log"))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn breakdown() {
    let e = engine();
    let set = e.ruleset();
    let lines = corpus();
    let events: Vec<_> = lines
        .iter()
        .map(|l| predecode::predecode(l, "source-0"))
        .collect();
    // One output and one set of buffers, reused for every event, as a
    // stage does.
    let mut d = rulelanes_model::DecodedEvent::default();
    let mut sc = decode::Scratch::default();
    let mut hit = None;
    let mut spare = String::new();
    // Warm-up.
    for ev in &events {
        decode::decode_into(set, ev, &mut d, &mut sc);
        matcher::match_into(set, ev, &d, e.alert_level(), &mut hit, &mut spare);
    }
    // name -> (events, decode allocations, match allocations)
    let mut per: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    for ev in &events {
        arm_current_thread();
        decode::decode_into(set, ev, &mut d, &mut sc);
        let da = disarm_current_thread();
        arm_current_thread();
        matcher::match_into(set, ev, &d, e.alert_level(), &mut hit, &mut spare);
        let ma = disarm_current_thread();
        let name = d
            .decoder
            .as_ref()
            .map_or("(none)".to_string(), |d| d.name.to_string());
        let row = per.entry(name).or_default();
        row.0 += 1;
        row.1 += da;
        row.2 += ma;
    }
    let (mut n, mut da, mut ma) = (0, 0, 0);
    eprintln!("decoder | events | decode allocs/event | match allocs/event");
    for (name, (k, d, m)) in &per {
        eprintln!(
            "{name} | {k} | {:.2} | {:.2}",
            *d as f64 / *k as f64,
            *m as f64 / *k as f64
        );
        n += k;
        da += d;
        ma += m;
    }
    eprintln!(
        "all | {n} | {:.2} | {:.2}",
        da as f64 / n as f64,
        ma as f64 / n as f64
    );
}
