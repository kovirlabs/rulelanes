//! rulelanes-bench: load runs for the staged pipeline.
//!
//! 1. Capacity: the feeder sends as fast as it can; capacity is the rate
//!    the write stage reaches after warm-up (median of the trials).
//! 2. Load steps: for each arrival pattern (evenly spaced, Poisson) and each
//!    load (default 50% and 90% of capacity), a fresh pipeline is fed at
//!    that rate. Latency is from the scheduled arrival time (the time of
//!    receipt) to the write stage handing the outcome to the sink, so a
//!    late feeder counts against the pipeline.
//! 3. R5: p99 at 90% over p99 at 50%, per pattern; the rule is at most 3.
//! 4. R8: allocations each stage made after start-up, per input.
//! 5. For context, the single-threaded reference engine's rate on the same
//!    corpus.
//!
//! The run file goes to `<out-dir>/<machine>/<date>-pipeline[-n].json` and
//! is never overwritten. The program is recorded by file name only and the
//! home directory is masked in the recorded command.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

use rulelanes_engine::Engine;
use rulelanes_pipe::hist::Histogram;
use rulelanes_pipe::{Config, Input, Reject, Sink, Written};
use serde_json::{Value, json};
use stagelanes_arch::{OsCpu, Priority, Topology};
use stagelanes_pipe::CorePlan;

/// The system allocator, counting allocations per stage (default).
#[cfg(not(feature = "mimalloc"))]
#[global_allocator]
static ALLOC: stagelanes_mem::CountingAlloc = stagelanes_mem::CountingAlloc;

/// The allocator experiment: mimalloc, whose per-thread heaps avoid a
/// shared heap; allocations are not counted (reported as 0).
#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const ALLOCATOR: &str = if cfg!(feature = "mimalloc") {
    "mimalloc (allocations not counted; the per-stage counts read 0)"
} else {
    "system, through stagelanes_mem::CountingAlloc"
};

const USAGE: &str = "usage: rulelanes-bench --machine NAME --machine-desc TEXT --date YYYY-MM-DD
    [--decoders DIR] [--rules DIR] [--corpus FILE] [--sources N]
    [--priority normal|high|time-critical] [--no-pin]
    [--secs S] [--warmup S] [--capacity-trials N] [--loads 0.5,0.9]
    [--patterns even,poisson] [--repeats N] [--note TEXT] [--out-dir DIR]";

struct Opts {
    machine: String,
    machine_desc: String,
    date: String,
    decoders: PathBuf,
    rules: PathBuf,
    corpus: PathBuf,
    sources: u32,
    priority: Priority,
    pin: bool,
    secs: f64,
    warmup: f64,
    capacity_trials: usize,
    loads: Vec<f64>,
    patterns: Vec<Pattern>,
    repeats: usize,
    note: String,
    out_dir: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Pattern {
    Even,
    Poisson,
}

impl Pattern {
    fn name(self) -> &'static str {
        match self {
            Pattern::Even => "even",
            Pattern::Poisson => "poisson",
        }
    }
}

fn priority_name(p: Priority) -> &'static str {
    match p {
        Priority::Normal => "normal",
        Priority::High => "high",
        Priority::TimeCritical => "time-critical",
    }
}

fn parse_args() -> Result<Opts, String> {
    let mut o = Opts {
        machine: String::new(),
        machine_desc: String::new(),
        date: String::new(),
        decoders: "testdata/ruleset/decoders".into(),
        rules: "testdata/ruleset/rules".into(),
        corpus: "testdata/corpus/corpus.log".into(),
        sources: 4,
        priority: Priority::Normal,
        pin: true,
        secs: 5.0,
        warmup: 1.0,
        capacity_trials: 3,
        loads: vec![0.5, 0.9],
        patterns: vec![Pattern::Even, Pattern::Poisson],
        repeats: 1,
        note: String::new(),
        out_dir: "runs".into(),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        if flag == "--no-pin" {
            o.pin = false;
            i += 1;
            continue;
        }
        let v = args
            .get(i + 1)
            .ok_or_else(|| format!("{flag} needs a value"))?;
        let num = |v: &str| v.parse::<f64>().map_err(|e| format!("{flag}: {e}"));
        match flag {
            "--machine" => o.machine = v.clone(),
            "--machine-desc" => o.machine_desc = v.clone(),
            "--date" => o.date = v.clone(),
            "--decoders" => o.decoders = v.into(),
            "--rules" => o.rules = v.into(),
            "--corpus" => o.corpus = v.into(),
            "--sources" => o.sources = num(v)? as u32,
            "--priority" => {
                o.priority = match v.as_str() {
                    "normal" => Priority::Normal,
                    "high" => Priority::High,
                    "time-critical" => Priority::TimeCritical,
                    _ => return Err(format!("unknown priority {v}")),
                }
            }
            "--secs" => o.secs = num(v)?,
            "--warmup" => o.warmup = num(v)?,
            "--capacity-trials" => o.capacity_trials = num(v)? as usize,
            "--repeats" => o.repeats = num(v)? as usize,
            "--loads" => {
                o.loads = v
                    .split(',')
                    .map(|x| x.parse::<f64>().map_err(|e| format!("--loads: {e}")))
                    .collect::<Result<_, _>>()?
            }
            "--patterns" => {
                o.patterns = v
                    .split(',')
                    .map(|x| match x {
                        "even" => Ok(Pattern::Even),
                        "poisson" => Ok(Pattern::Poisson),
                        _ => Err(format!("unknown pattern {x}")),
                    })
                    .collect::<Result<_, _>>()?
            }
            "--note" => o.note = v.clone(),
            "--out-dir" => o.out_dir = v.into(),
            _ => return Err(format!("unknown flag {flag}")),
        }
        i += 2;
    }
    if o.machine.is_empty() || o.machine_desc.is_empty() || o.date.is_empty() {
        return Err("--machine, --machine-desc and --date are required".into());
    }
    if o.sources == 0 || o.capacity_trials == 0 || o.repeats == 0 {
        return Err("--sources, --capacity-trials and --repeats must be at least 1".into());
    }
    Ok(o)
}

/// Measures latency and counts outcomes after warm-up.
struct Measure {
    warm_end: Instant,
    hist: Histogram,
    measured: u64,
    alerts: u64,
    first: Option<Instant>,
    last: Option<Instant>,
}

impl Measure {
    fn new(warm_end: Instant) -> Measure {
        Measure {
            warm_end,
            hist: Histogram::default(),
            measured: 0,
            alerts: 0,
            first: None,
            last: None,
        }
    }
}

impl Sink for Measure {
    fn write(&mut self, w: &Written<'_>) {
        let now = Instant::now();
        if w.received < self.warm_end {
            return;
        }
        self.hist
            .record(now.saturating_duration_since(w.received).as_nanos() as u64);
        self.measured += 1;
        self.alerts += u64::from(w.outcome.alert);
        self.first.get_or_insert(now);
        self.last = Some(now);
    }
}

/// xorshift64* for Poisson gaps; no dependency needed.
struct Rng(u64);

impl Rng {
    fn unit(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        let x = self.0.wrapping_mul(0x2545_F491_4F6C_DD1D);
        // (0, 1]: never zero, so ln is finite.
        ((x >> 11) as f64 + 1.0) / (1u64 << 53) as f64
    }
}

struct Setup {
    engine: Engine,
    lines: Vec<std::sync::Arc<[u8]>>,
    cfg: Config,
    feeder_cpu: Option<OsCpu>,
}

struct StepResult {
    json: Value,
    p99_ns: Option<u64>,
    rate: f64,
}

/// One pipeline run. `rate` None = as fast as possible.
fn step(s: &Setup, o: &Opts, rate: Option<f64>, pattern: Pattern, seed: u64) -> StepResult {
    let start_at = Instant::now() + Duration::from_millis(20);
    let warm_end = start_at + Duration::from_secs_f64(o.warmup);
    let end = warm_end + Duration::from_secs_f64(o.secs);
    let (mut feeder, running) =
        rulelanes_pipe::start(s.cfg.clone(), &s.engine, Measure::new(warm_end)).expect("start");
    let mut rng = Rng(seed | 1);
    let mut max_lag = Duration::ZERO;
    let mut t = 0f64;
    let total = (end - start_at).as_secs_f64();
    let mut i = 0usize;
    let n = s.lines.len();
    loop {
        let sched = match rate {
            None => Instant::now(),
            Some(r) => {
                if t > total {
                    break;
                }
                let sched = start_at + Duration::from_secs_f64(t);
                t += match pattern {
                    Pattern::Even => 1.0 / r,
                    Pattern::Poisson => -rng.unit().ln() / r,
                };
                let mut now = Instant::now();
                while now < sched {
                    std::hint::spin_loop();
                    now = Instant::now();
                }
                max_lag = max_lag.max(now - sched);
                sched
            }
        };
        if rate.is_none() && sched >= end {
            break;
        }
        feeder.send(Input {
            source: (i % s.cfg.locations.len()) as u32,
            received: sched,
            bytes: s.lines[i % n].clone(),
        });
        i += 1;
    }
    let report = running.join(feeder);
    let m = &report.sink;
    let span = match (m.first, m.last) {
        (Some(a), Some(b)) if b > a => (b - a).as_secs_f64(),
        _ => 0.0,
    };
    let achieved = if span > 0.0 {
        m.measured as f64 / span
    } else {
        0.0
    };
    let q = |x: f64| m.hist.quantile(x).map(|v| v as f64 / 1000.0);
    let stages: Vec<Value> = report
        .stages
        .iter()
        .map(|st| {
            json!({
                "name": st.name,
                "cpu": st.cpu.map(|c| c.to_string()),
                "allocations_after_ready": st.allocations_after_ready,
                "allocations_per_input": st.allocations_after_ready as f64 / report.received.max(1) as f64,
                "busy_polls": st.busy_polls,
                "idle_polls": st.idle_polls,
                "setup_errors": st.setup_errors,
            })
        })
        .collect();
    let rejects: serde_json::Map<String, Value> = Reject::ALL
        .iter()
        .map(|r| (r.name().to_string(), json!(report.rejected.get(*r))))
        .collect();
    let json = json!({
        "pattern": if rate.is_none() { "unpaced" } else { pattern.name() },
        "target_rate_eps": rate,
        "achieved_rate_eps": achieved,
        "sent": report.sent,
        "received": report.received,
        "written": report.written,
        "rejected": rejects,
        "balanced": report.balanced(),
        "input_full_waits": report.input_full_waits,
        "measured": m.measured,
        "alerts_measured": m.alerts,
        "latency_us": {
            "p50": q(0.5), "p90": q(0.9), "p99": q(0.99), "p999": q(0.999),
            "max": m.hist.max() as f64 / 1000.0,
        },
        "feeder_max_lag_us": max_lag.as_nanos() as f64 / 1000.0,
        "stages": stages,
    });
    StepResult {
        json,
        p99_ns: m.hist.quantile(0.99),
        rate: achieved,
    }
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (out.status.success() && !s.is_empty()).then(|| s.to_owned())
}

/// The command line: program by file name, home directory masked.
fn command_line() -> String {
    let mut args = std::env::args();
    let exe = args.next().unwrap_or_default();
    let exe = std::path::Path::new(&exe)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let homes: Vec<String> = ["USERPROFILE", "HOME"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .filter(|h| !h.is_empty())
        .collect();
    std::iter::once(exe)
        .chain(args.map(|a| {
            let mut a = a;
            for h in &homes {
                a = a.replace(h.as_str(), "<home>");
            }
            if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a
            }
        }))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() -> ExitCode {
    let o = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let files = |d: &PathBuf| rulelanes_syntax::xml_files(d).expect("ruleset directory");
    let set = match rulelanes_syntax::load_files(&files(&o.decoders), &files(&o.rules)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ruleset: {e}");
            return ExitCode::from(1);
        }
    };
    let engine = Engine::new(set);
    let text = std::fs::read_to_string(&o.corpus).expect("corpus");
    let lines: Vec<std::sync::Arc<[u8]>> = text.lines().map(|l| l.as_bytes().into()).collect();
    let locations: Vec<String> = (0..o.sources).map(|i| format!("source-{i}")).collect();

    // Cores: skip the first physical core (left to the OS), then four
    // stages, then the feeder.
    let mut cfg = Config::new(locations.clone());
    cfg.priority = o.priority;
    let mut feeder_cpu = None;
    let mut placement_notes = Vec::new();
    if o.pin {
        let topo = Topology::detect().expect("topology");
        let mut plan = CorePlan::for_socket(&topo, 0);
        let _os = plan.take(1).expect("a core for the OS");
        let c = plan.take(4).expect("four stage cores");
        cfg.cpus = Some([c[0], c[1], c[2], c[3]]);
        feeder_cpu = plan.take(1).ok().map(|v| v[0]);
    }
    if let Some(cpu) = feeder_cpu {
        if let Err(e) = stagelanes_arch::pin_current_thread(cpu) {
            placement_notes.push(format!("feeder not pinned: {e}"));
        }
        let prio = if o.priority == Priority::Normal {
            Ok(())
        } else {
            stagelanes_arch::set_current_thread_priority(o.priority)
        };
        if let Err(e) = prio {
            placement_notes.push(format!("feeder priority: {e}"));
        }
    }
    let s = Setup {
        engine,
        lines,
        cfg,
        feeder_cpu,
    };

    // Reference engine, one thread, for context.
    let reference = {
        let t0 = Instant::now();
        let mut n = 0u64;
        let mut alerts = 0u64;
        while t0.elapsed() < Duration::from_secs_f64(o.secs.min(3.0)) {
            for (i, l) in text.lines().enumerate() {
                let out = s.engine.process(l, &locations[i % locations.len()]);
                alerts += u64::from(out.alert);
                n += 1;
            }
        }
        let secs = t0.elapsed().as_secs_f64();
        json!({ "events": n, "alerts": alerts, "secs": secs, "rate_eps": n as f64 / secs,
                "thread": "the feeder's (main) thread" })
    };
    eprintln!("reference engine: {}", reference["rate_eps"]);

    let mut repeats = Vec::new();
    for rep in 0..o.repeats {
        let mut cap_trials = Vec::new();
        let mut caps = Vec::new();
        for t in 0..o.capacity_trials {
            let r = step(&s, &o, None, Pattern::Even, 0);
            eprintln!("repeat {rep} capacity trial {t}: {:.0} events/s", r.rate);
            caps.push(r.rate);
            cap_trials.push(r.json);
        }
        caps.sort_by(f64::total_cmp);
        let capacity = caps[caps.len() / 2];
        let mut steps = Vec::new();
        let mut r5 = serde_json::Map::new();
        for &p in &o.patterns {
            let mut p99s = Vec::new();
            for (k, &load) in o.loads.iter().enumerate() {
                let rate = capacity * load;
                let seed = 0x9E37_79B9_7F4A_7C15 ^ ((rep as u64) << 32) ^ (k as u64);
                let r = step(&s, &o, Some(rate), p, seed);
                eprintln!(
                    "repeat {rep} {} load {load}: {:.0} events/s, p99 {:?} ns",
                    p.name(),
                    r.rate,
                    r.p99_ns
                );
                let mut j = r.json;
                j["load"] = json!(load);
                steps.push(j);
                p99s.push((load, r.p99_ns));
            }
            let at = |l: f64| {
                p99s.iter()
                    .find(|(x, _)| (*x - l).abs() < 1e-9)
                    .and_then(|(_, v)| *v)
            };
            if let (Some(a), Some(b)) = (at(0.5), at(0.9)) {
                let ratio = b as f64 / a as f64;
                r5.insert(
                    p.name().into(),
                    json!({ "p99_at_50_us": a as f64 / 1000.0, "p99_at_90_us": b as f64 / 1000.0,
                            "ratio": ratio, "pass": ratio <= 3.0 }),
                );
            }
        }
        repeats.push(json!({
            "capacity_eps": capacity,
            "capacity_trials": cap_trials,
            "steps": steps,
            "r5": r5,
        }));
    }

    let git = |args: &[&str]| run("git", args);
    let file = json!({
        "kind": "rulelanes-pipeline",
        "machine": o.machine,
        "machine_desc": o.machine_desc,
        "os_build": run("cmd", &["/C", "ver"]).or_else(|| run("uname", &["-srv"])),
        "rustc": env!("BENCH_RUSTC"),
        "build": if cfg!(debug_assertions) { "debug" } else { "release" },
        "date_local": o.date,
        "unix_time_secs": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "rulelanes": {
            "commit": git(&["rev-parse", "HEAD"]),
            "branch": git(&["rev-parse", "--abbrev-ref", "HEAD"]),
            "uncommitted_changes": git(&["status", "--porcelain", "--untracked-files=no"]).is_some(),
        },
        "stagelanes_commit": git(&["-C", "../stagelanes", "rev-parse", "HEAD"]),
        "wazuh_compared": "none in this run file (R6 is a separate run)",
        "ruleset": { "decoders": o.decoders.to_string_lossy(), "rules": o.rules.to_string_lossy(),
                     "decoders_loaded": s.engine.ruleset().decoders.len(),
                     "rules_loaded": s.engine.ruleset().rules.len() },
        "corpus": { "file": o.corpus.to_string_lossy(), "lines": s.lines.len(),
                    "sources": o.sources, "assignment": "round robin" },
        "pipeline": {
            "stages": ["parse", "decode", "match", "write"],
            "link_slots": rulelanes_pipe::SLOTS, "batch": rulelanes_pipe::BATCH,
            "idle": "spin", "priority": priority_name(o.priority),
            "cpus": s.cfg.cpus.map(|c| c.iter().map(|x| x.to_string()).collect::<Vec<_>>()),
            "feeder_cpu": s.feeder_cpu.map(|c| c.to_string()),
            "placement_notes": placement_notes,
        },
        "method": {
            "secs_measured": o.secs, "warmup_secs": o.warmup,
            "capacity": "median of the unpaced trials: outcomes written after warm-up / time between first and last of them",
            "latency": "scheduled arrival time (receipt) to the write stage handing the outcome to the sink; a late feeder counts",
            "loads": o.loads, "patterns": o.patterns.iter().map(|p| p.name()).collect::<Vec<_>>(),
            "r5_rule": "p99 at 0.9 load <= 3 x p99 at 0.5 load",
            "allocations": "stagelanes_mem::CountingAlloc; per stage after ready, divided by inputs received",
            "allocator": ALLOCATOR,
        },
        "reference_engine_single_thread": reference,
        "repeats": repeats,
        "command": command_line(),
        "note": o.note,
    });

    let dir = o.out_dir.join(&o.machine);
    std::fs::create_dir_all(&dir).expect("out dir");
    let mut path = dir.join(format!("{}-pipeline.json", o.date));
    let mut k = 2;
    while path.exists() {
        path = dir.join(format!("{}-pipeline-{k}.json", o.date));
        k += 1;
    }
    let text = serde_json::to_string_pretty(&file).expect("json") + "\n";
    std::fs::write(&path, text).expect("write run file");
    println!("{}", path.display());
    ExitCode::SUCCESS
}
