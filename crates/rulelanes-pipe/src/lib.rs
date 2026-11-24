//! The staged pipeline (SPEC §5, M2): the reference engine's three steps
//! put on pinned `stagelanes` stages, plus a write stage.
//!
//! ```text
//! Feeder -> parse -> decode -> match -> write -> Sink
//!           (checks,  (decoder  (rule
//!            pre-     tree)     tree)
//!            decode)
//! ```
//!
//! - Each stage is one thread (`stagelanes_pipe::spawn_stage`), optionally
//!   pinned, joined to the next by a `stagelanes_pipe::link` of [`SLOTS`]
//!   slots. Items move in batches of up to [`BATCH`].
//! - A full link makes the sender wait (busy-poll), back to the
//!   [`Feeder`]: back-pressure reaches the input, nothing is dropped (R4).
//! - Every input is either written (one [`Outcome`] per input, alert or
//!   not) or rejected by the parse stage and counted by [`Reject`] reason,
//!   so `received == written + rejected` ([`Report::balanced`], R4).
//! - Decode and match each own a clone of the [`Engine`], so no compiled
//!   pattern is shared between threads.
//! - The order of inputs is kept end to end (one path, FIFO links), so the
//!   per-source order is the input order (R3).
//!
//! The decode and match code is the reference engine's own
//! (`rulelanes_engine::{predecode, decode, matcher}`). It builds owned
//! strings, so the stages allocate per event; the count is reported per
//! stage (R8), not yet zero.

#![forbid(unsafe_code)]

pub mod hist;

use std::thread::JoinHandle;
use std::time::Instant;

use rulelanes_engine::{Engine, decode, matcher, predecode};
use rulelanes_model::{DecodedEvent, Event, Outcome, RuleHit};
use stagelanes_arch::{OsCpu, Priority};
use stagelanes_pipe::{StageReport, StageSpec, Tx, link, spawn_stage};

pub use stagelanes_pipe::Error;

/// Slots in each link between stages.
pub const SLOTS: usize = 256;
/// Most items a stage takes from its input link at once.
pub const BATCH: usize = 32;

/// One received log line.
pub struct Input {
    /// Index into [`Config::locations`].
    pub source: u32,
    /// When it was received; latency is measured from here.
    pub received: Instant,
    /// The raw line, without its line terminator. Shared, so a receiver
    /// can hand a line over without copying or allocating.
    pub bytes: std::sync::Arc<[u8]>,
}

/// Why the parse stage refused an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Zero bytes.
    Empty,
    /// Longer than [`Config::max_line`].
    TooLong,
    /// Not valid UTF-8.
    NotUtf8,
    /// `source` is not an index into [`Config::locations`].
    UnknownSource,
}

impl Reject {
    /// Every reason, in report order.
    pub const ALL: [Reject; 4] = [
        Reject::Empty,
        Reject::TooLong,
        Reject::NotUtf8,
        Reject::UnknownSource,
    ];

    /// The name used in reports.
    pub fn name(self) -> &'static str {
        match self {
            Reject::Empty => "empty",
            Reject::TooLong => "too_long",
            Reject::NotUtf8 => "not_utf8",
            Reject::UnknownSource => "unknown_source",
        }
    }
}

/// Rejects counted by reason.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RejectCounts([u64; 4]);

impl RejectCounts {
    fn add(&mut self, r: Reject) {
        self.0[r as usize] += 1;
    }

    /// Rejects for one reason.
    pub fn get(&self, r: Reject) -> u64 {
        self.0[r as usize]
    }

    /// All rejects.
    pub fn total(&self) -> u64 {
        self.0.iter().sum()
    }
}

/// One written outcome, as the sink sees it.
pub struct Written<'a> {
    /// Position in the input stream (0-based, counting rejects).
    pub seq: u64,
    /// The input's source.
    pub source: u32,
    /// When the input was received.
    pub received: Instant,
    /// What the engine made of it.
    pub outcome: &'a Outcome,
}

/// Where the write stage puts outcomes. Runs on the write stage's thread.
pub trait Sink: Send + 'static {
    /// Called once per written input, in input order.
    fn write(&mut self, w: &Written<'_>);
}

/// How to run the pipeline.
#[derive(Clone, Debug)]
pub struct Config {
    /// The `location` of each source, as Wazuh reports it.
    pub locations: Vec<String>,
    /// Longest accepted line in bytes.
    pub max_line: usize,
    /// Cores for parse, decode, match and write, in that order; `None`
    /// leaves the stages unpinned.
    pub cpus: Option<[OsCpu; 4]>,
    /// Priority of the four stage threads.
    pub priority: Priority,
}

impl Config {
    /// Unpinned, normal priority, one location per source, lines up to
    /// 65,536 bytes (TBD: Wazuh's own limit is not checked against the
    /// oracle yet).
    pub fn new(locations: Vec<String>) -> Config {
        Config {
            locations,
            max_line: 65_536,
            cpus: None,
            priority: Priority::Normal,
        }
    }
}

struct Item {
    seq: u64,
    source: u32,
    received: Instant,
    event: Event,
    decoded: DecodedEvent,
    rule: Option<RuleHit>,
    alert: bool,
}

/// The input end of a running pipeline. Dropping it (or
/// [`Running::join`]) ends the input; the stages drain and stop.
pub struct Feeder {
    tx: Tx<Input, SLOTS>,
    sent: u64,
    full_waits: u64,
}

impl Feeder {
    /// Hands one input to the parse stage, waiting while its link is full.
    pub fn send(&mut self, input: Input) {
        if self.tx.free() == 0 {
            self.full_waits += 1;
        }
        self.tx.send(input);
        self.sent += 1;
    }

    /// Inputs handed over so far.
    pub fn sent(&self) -> u64 {
        self.sent
    }

    /// Times [`Feeder::send`] found the link full and had to wait.
    pub fn full_waits(&self) -> u64 {
        self.full_waits
    }
}

type Joined<T> = JoinHandle<(StageReport, T)>;

/// A started pipeline.
pub struct Running<S> {
    parse: Joined<(u64, RejectCounts)>,
    decode: Joined<u64>,
    matcher: Joined<u64>,
    write: Joined<(u64, S)>,
}

/// What a finished pipeline reports.
pub struct Report<S> {
    /// The sink, returned from the write stage.
    pub sink: S,
    /// Inputs the parse stage received.
    pub received: u64,
    /// Inputs the parse stage refused, by reason.
    pub rejected: RejectCounts,
    /// Items through the decode stage.
    pub decoded: u64,
    /// Items through the match stage.
    pub matched: u64,
    /// Outcomes handed to the sink.
    pub written: u64,
    /// Inputs the feeder sent.
    pub sent: u64,
    /// Times the feeder waited on a full link (back-pressure seen).
    pub input_full_waits: u64,
    /// One report per stage: parse, decode, match, write.
    pub stages: Vec<StageReport>,
}

impl<S> Report<S> {
    /// R4: everything sent was received, and everything received was
    /// written or counted as rejected.
    pub fn balanced(&self) -> bool {
        self.sent == self.received
            && self.received == self.written + self.rejected.total()
            && self.decoded == self.written
            && self.matched == self.written
    }
}

fn spec(name: &str, cfg: &Config, i: usize) -> StageSpec {
    StageSpec {
        name: name.to_string(),
        cpu: cfg.cpus.map(|c| c[i]),
        priority: cfg.priority,
    }
}

fn check<'a>(input: &'a Input, locations: &[String], max_line: usize) -> Result<&'a str, Reject> {
    if input.source as usize >= locations.len() {
        return Err(Reject::UnknownSource);
    }
    if input.bytes.is_empty() {
        return Err(Reject::Empty);
    }
    if input.bytes.len() > max_line {
        return Err(Reject::TooLong);
    }
    std::str::from_utf8(&input.bytes).map_err(|_| Reject::NotUtf8)
}

/// Starts the four stages. `engine` is cloned for the decode and match
/// stages.
pub fn start<S: Sink>(
    cfg: Config,
    engine: &Engine,
    sink: S,
) -> Result<(Feeder, Running<S>), Error> {
    let (tx_in, mut rx_in) = link::<Input, SLOTS>();
    let (mut tx_pd, mut rx_pd) = link::<Item, SLOTS>();
    let (mut tx_dm, mut rx_dm) = link::<Item, SLOTS>();
    let (mut tx_mw, mut rx_mw) = link::<Item, SLOTS>();

    let locations = cfg.locations.clone();
    let max_line = cfg.max_line;
    let parse = spawn_stage(spec("parse", &cfg, 0), move |ctx| {
        let mut received = 0u64;
        let mut rejects = RejectCounts::default();
        ctx.ready();
        loop {
            let got = rx_in.recv_with(BATCH, |input| {
                let seq = received;
                received += 1;
                match check(&input, &locations, max_line) {
                    Err(r) => rejects.add(r),
                    Ok(line) => {
                        let event = predecode::predecode(line, &locations[input.source as usize]);
                        tx_pd.send(Item {
                            seq,
                            source: input.source,
                            received: input.received,
                            event,
                            decoded: DecodedEvent::default(),
                            rule: None,
                            alert: false,
                        });
                    }
                }
            });
            match got {
                None => break,
                Some(0) => ctx.idle(),
                Some(_) => ctx.busy(),
            }
        }
        ctx.finish();
        drop(tx_pd);
        (received, rejects)
    })?;

    let dec_engine = engine.clone();
    let decode = spawn_stage(spec("decode", &cfg, 1), move |ctx| {
        let set = dec_engine.ruleset();
        let mut n = 0u64;
        ctx.ready();
        loop {
            let got = rx_pd.recv_with(BATCH, |mut item: Item| {
                item.decoded = decode::decode(set, &item.event);
                n += 1;
                tx_dm.send(item);
            });
            match got {
                None => break,
                Some(0) => ctx.idle(),
                Some(_) => ctx.busy(),
            }
        }
        ctx.finish();
        drop(tx_dm);
        n
    })?;

    let match_engine = engine.clone();
    let matcher = spawn_stage(spec("match", &cfg, 2), move |ctx| {
        let set = match_engine.ruleset();
        let level = match_engine.alert_level();
        let mut n = 0u64;
        ctx.ready();
        loop {
            let got = rx_dm.recv_with(BATCH, |mut item: Item| {
                let (rule, alert) = matcher::match_rules(set, &item.event, &item.decoded, level);
                item.rule = rule;
                item.alert = alert;
                n += 1;
                tx_mw.send(item);
            });
            match got {
                None => break,
                Some(0) => ctx.idle(),
                Some(_) => ctx.busy(),
            }
        }
        ctx.finish();
        drop(tx_mw);
        n
    })?;

    let mut sink = sink;
    let write = spawn_stage(spec("write", &cfg, 3), move |ctx| {
        let mut n = 0u64;
        ctx.ready();
        loop {
            let got = rx_mw.recv_with(BATCH, |item: Item| {
                let outcome = Outcome {
                    event: item.event,
                    decoded: item.decoded,
                    rule: item.rule,
                    alert: item.alert,
                };
                sink.write(&Written {
                    seq: item.seq,
                    source: item.source,
                    received: item.received,
                    outcome: &outcome,
                });
                n += 1;
            });
            match got {
                None => break,
                Some(0) => ctx.idle(),
                Some(_) => ctx.busy(),
            }
        }
        ctx.finish();
        (n, sink)
    })?;

    Ok((
        Feeder {
            tx: tx_in,
            sent: 0,
            full_waits: 0,
        },
        Running {
            parse,
            decode,
            matcher,
            write,
        },
    ))
}

impl<S> Running<S> {
    /// Ends the input, waits for every stage to drain and stop, and
    /// collects the report. Panics if a stage panicked.
    pub fn join(self, feeder: Feeder) -> Report<S> {
        let sent = feeder.sent;
        let input_full_waits = feeder.full_waits;
        drop(feeder);
        let (pr, (received, rejected)) = self.parse.join().expect("parse stage panicked");
        let (dr, decoded) = self.decode.join().expect("decode stage panicked");
        let (mr, matched) = self.matcher.join().expect("match stage panicked");
        let (wr, (written, sink)) = self.write.join().expect("write stage panicked");
        Report {
            sink,
            received,
            rejected,
            decoded,
            matched,
            written,
            sent,
            input_full_waits,
            stages: vec![pr, dr, mr, wr],
        }
    }
}

/// Runs the reference engine over the same inputs, the way the pipeline
/// does (same checks, same order): the expected outcomes for R3.
pub fn reference(
    cfg: &Config,
    engine: &Engine,
    inputs: &[(u32, &[u8])],
) -> Vec<(u64, u32, Outcome)> {
    let mut out = Vec::new();
    for (seq, (source, bytes)) in inputs.iter().enumerate() {
        let input = Input {
            source: *source,
            received: Instant::now(),
            bytes: (*bytes).into(),
        };
        if let Ok(line) = check(&input, &cfg.locations, cfg.max_line) {
            out.push((
                seq as u64,
                *source,
                engine.process(line, &cfg.locations[*source as usize]),
            ));
        }
    }
    out
}

/// Keeps every written outcome (for tests and small runs).
#[derive(Default)]
pub struct Collect(pub Vec<(u64, u32, Outcome)>);

impl Sink for Collect {
    fn write(&mut self, w: &Written<'_>) {
        self.0.push((w.seq, w.source, w.outcome.clone()));
    }
}
