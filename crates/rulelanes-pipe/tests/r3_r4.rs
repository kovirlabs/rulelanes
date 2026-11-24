//! R3: the staged pipeline gives the reference engine's outcomes, in the
//! same per-source order, for the corpus and for 10,000 generated cases.
//! R4: events in equal events out plus events rejected, every reject
//! counted by reason, and a full link holds the input back.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rulelanes_engine::Engine;
use rulelanes_oracle::corpus;
use rulelanes_pipe::{Collect, Config, Input, Reject, SLOTS, Sink, Written, reference, start};

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

fn config(sources: u32) -> Config {
    Config::new((0..sources).map(|i| format!("source-{i}")).collect())
}

/// Runs `inputs` through the pipeline and through the reference engine and
/// asserts the outcomes are equal, in order, overall and per source.
fn assert_r3(inputs: &[(u32, Vec<u8>)], sources: u32) -> usize {
    let cfg = config(sources);
    let e = engine();
    let (mut feeder, running) = start(cfg.clone(), &e, Collect::default()).unwrap();
    for (source, bytes) in inputs {
        feeder.send(Input {
            source: *source,
            received: Instant::now(),
            bytes: bytes.as_slice().into(),
        });
    }
    let report = running.join(feeder);
    assert!(report.balanced(), "R4 identity");
    let borrowed: Vec<(u32, &[u8])> = inputs.iter().map(|(s, b)| (*s, b.as_slice())).collect();
    let want = reference(&cfg, &e, &borrowed);
    let got = report.sink.0;
    assert_eq!(got.len(), want.len());
    for (g, w) in got.iter().zip(&want) {
        assert_eq!(g, w, "outcome for input {}", w.0);
    }
    for s in 0..sources {
        let per = |v: &[(u64, u32, rulelanes_model::Outcome)]| -> Vec<u64> {
            v.iter().filter(|x| x.1 == s).map(|x| x.0).collect()
        };
        assert_eq!(per(&got), per(&want), "order of source {s}");
    }
    let alerts = got.iter().filter(|x| x.2.alert).count();
    assert!(alerts > 0, "some inputs alert");
    got.len()
}

fn round_robin(lines: &[String], sources: u32) -> Vec<(u32, Vec<u8>)> {
    lines
        .iter()
        .enumerate()
        .map(|(i, l)| ((i as u32) % sources, l.as_bytes().to_vec()))
        .collect()
}

#[test]
fn r3_corpus_equals_reference_engine() {
    let text = std::fs::read_to_string(root().join("testdata/corpus/corpus.log")).unwrap();
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    assert_eq!(lines.len(), corpus::SIZE);
    let n = assert_r3(&round_robin(&lines, 4), 4);
    assert_eq!(n, corpus::SIZE);
}

#[test]
fn r3_ten_thousand_generated_cases_equal_reference_engine() {
    // A different seed from the committed corpus.
    let lines = corpus::generate(0x5EED_2026_1123, 10_000);
    // Uneven source assignment, so per-source order is not just stride.
    let mut rng = corpus::Rng::new(7);
    let inputs: Vec<(u32, Vec<u8>)> = lines
        .iter()
        .map(|l| (rng.below(5) as u32, l.as_bytes().to_vec()))
        .collect();
    let n = assert_r3(&inputs, 5);
    assert_eq!(n, 10_000);
}

#[test]
fn r4_rejects_are_counted_by_reason() {
    let mut cfg = config(2);
    cfg.max_line = 300;
    let e = engine();
    let good = corpus::generate(corpus::SEED, 50);
    let mut inputs: Vec<(u32, Vec<u8>)> = Vec::new();
    for (i, l) in good.iter().enumerate() {
        inputs.push(((i % 2) as u32, l.as_bytes().to_vec()));
        match i % 10 {
            1 => inputs.push((0, Vec::new())),
            3 => inputs.push((1, vec![b'a'; 301])),
            5 => inputs.push((0, vec![b'x', 0xff, 0xfe])),
            7 => inputs.push((9, b"from nowhere".to_vec())),
            _ => {}
        }
    }
    let (mut feeder, running) = start(cfg.clone(), &e, Collect::default()).unwrap();
    for (s, b) in &inputs {
        feeder.send(Input {
            source: *s,
            received: Instant::now(),
            bytes: b.as_slice().into(),
        });
    }
    let r = running.join(feeder);
    assert!(r.balanced());
    assert_eq!(r.received, inputs.len() as u64);
    assert_eq!(r.written, 50);
    for reason in Reject::ALL {
        assert_eq!(r.rejected.get(reason), 5, "{}", reason.name());
    }
    assert_eq!(r.received, r.written + r.rejected.total());
}

/// A sink that does not return until it is released.
struct Stalled(Arc<AtomicBool>, u64);

impl Sink for Stalled {
    fn write(&mut self, _w: &Written<'_>) {
        while !self.0.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
        self.1 += 1;
    }
}

#[test]
fn r4_full_link_holds_the_input_back() {
    let cfg = config(1);
    let e = engine();
    let release = Arc::new(AtomicBool::new(false));
    let (mut feeder, running) = start(cfg, &e, Stalled(release.clone(), 0)).unwrap();
    let total = 4 * SLOTS as u64 + 2_000;
    let sent = Arc::new(AtomicU64::new(0));
    let sent2 = sent.clone();
    let line: Arc<[u8]> = corpus::generate(corpus::SEED, 1)
        .remove(0)
        .as_bytes()
        .into();
    let feeder_thread = std::thread::spawn(move || {
        for _ in 0..total {
            feeder.send(Input {
                source: 0,
                received: Instant::now(),
                bytes: line.clone(),
            });
            sent2.store(feeder.sent(), Ordering::Release);
        }
        feeder
    });
    std::thread::sleep(Duration::from_millis(500));
    let held = sent.load(Ordering::Acquire);
    // Four links of SLOTS each, plus at most one item in the hands of each
    // stage and one inside the stalled sink.
    assert!(
        held <= 4 * SLOTS as u64 + 5,
        "input was not held back: {held} sent"
    );
    assert!(held < total);
    release.store(true, Ordering::Release);
    let feeder = feeder_thread.join().unwrap();
    let r = running.join(feeder);
    assert!(r.balanced());
    assert_eq!(r.written, total);
    assert_eq!(r.sink.1, total);
    assert!(r.input_full_waits > 0, "the feeder saw a full link");
}
