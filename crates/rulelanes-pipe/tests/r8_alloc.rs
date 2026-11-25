//! R8: allocations made by the decode and match steps, per event, after a
//! warm-up pass over the same inputs, with one output and one set of
//! buffers reused for every event as a stage does.
//!
//! - Match allocates nothing.
//! - Decode allocates only where a JSON event holds an array (its text is
//!   printed from a `serde_json::Value`).
//! - `breakdown` prints the counts per decoder (`--nocapture`).

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

struct Counted {
    line: String,
    decoder: String,
    decode: u64,
    matched: u64,
}

fn count() -> Vec<Counted> {
    let e = engine();
    let set = e.ruleset();
    let lines = corpus();
    let events: Vec<_> = lines
        .iter()
        .map(|l| predecode::predecode(l, "source-0"))
        .collect();
    let mut d = rulelanes_model::DecodedEvent::default();
    let mut sc = decode::Scratch::default();
    let mut hit = None;
    let mut spares = Vec::new();
    // Warm-up.
    for ev in &events {
        decode::decode_into(set, ev, &mut d, &mut sc);
        matcher::match_into(set, ev, &d, e.alert_level(), &mut hit, &mut spares);
    }
    let mut out = Vec::new();
    for (ev, line) in events.iter().zip(lines) {
        arm_current_thread();
        decode::decode_into(set, ev, &mut d, &mut sc);
        let decode = disarm_current_thread();
        arm_current_thread();
        matcher::match_into(set, ev, &d, e.alert_level(), &mut hit, &mut spares);
        let matched = disarm_current_thread();
        let decoder = d
            .decoder
            .as_ref()
            .map_or("(none)".to_string(), |d| d.name.to_string());
        out.push(Counted {
            line,
            decoder,
            decode,
            matched,
        });
    }
    out
}

#[test]
fn match_allocates_nothing() {
    let rows = count();
    let total: u64 = rows.iter().map(|r| r.matched).sum();
    assert_eq!(total, 0, "match allocations over {} events", rows.len());
}

#[test]
fn decode_allocates_only_for_json_arrays() {
    let e = engine();
    let set = e.ruleset();
    let names = |keep: &dyn Fn(&rulelanes_model::Decoder) -> bool| -> Vec<String> {
        set.decoders
            .iter()
            .filter(|d| keep(d))
            .map(|d| d.name.to_string())
            .collect()
    };
    let json = names(&|d| d.plugin.is_some());
    let rows = count();
    let mut zero = 0;
    for r in &rows {
        if r.decode == 0 {
            zero += 1;
            continue;
        }
        let allowed = json.contains(&r.decoder) && r.line.contains('[');
        assert!(
            allowed,
            "{} allocations decoding with {}: {}",
            r.decode, r.decoder, r.line
        );
    }
    eprintln!("{zero} of {} events decoded with no allocation", rows.len());
}

#[test]
fn breakdown() {
    // name -> (events, decode allocations, match allocations)
    let mut per: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    for r in count() {
        let row = per.entry(r.decoder).or_default();
        row.0 += 1;
        row.1 += r.decode;
        row.2 += r.matched;
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
