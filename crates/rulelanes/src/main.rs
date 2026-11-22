//! `rulelanes` command line.
//!
//! ```text
//! rulelanes logtest --decoders <dir> [--decoders <dir>...] --rules <dir> [--rules <dir>...] [--location <loc>]
//!     Reads one log line per stdin line; writes one JSON result per line.
//! rulelanes check --decoders <dir>... --rules <dir>... [--json]
//!     Loads a rule set leniently and reports what share loads and why the
//!     rest does not.
//! ```
#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage:
  rulelanes logtest --decoders <dir>... --rules <dir>... [--location <loc>]
  rulelanes check --decoders <dir>... --rules <dir>... [--json]";

struct Args {
    decoders: Vec<PathBuf>,
    rules: Vec<PathBuf>,
    location: String,
    json: bool,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut a = Args {
        decoders: Vec::new(),
        rules: Vec::new(),
        location: "rulelanes".to_string(),
        json: false,
    };
    let mut i = 0;
    while i < args.len() {
        let value = |i: usize| {
            args.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{} needs a value", args[i]))
        };
        match args[i].as_str() {
            "--decoders" => {
                a.decoders.push(value(i)?.into());
                i += 1;
            }
            "--rules" => {
                a.rules.push(value(i)?.into());
                i += 1;
            }
            "--location" => {
                a.location = value(i)?;
                i += 1;
            }
            "--json" => a.json = true,
            other => return Err(format!("unknown argument '{other}'")),
        }
        i += 1;
    }
    if a.decoders.is_empty() || a.rules.is_empty() {
        return Err("--decoders and --rules are required".into());
    }
    Ok(a)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let args = match parse(&argv[1..]) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("rulelanes: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match cmd.as_str() {
        "logtest" => logtest(&args),
        "check" => check(&args),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn logtest(args: &Args) -> ExitCode {
    let set = match rulelanes_syntax::load_dirs(&args.decoders, &args.rules) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("rulelanes: {e}");
            return ExitCode::from(1);
        }
    };
    let engine = rulelanes_engine::Engine::new(set);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim_end_matches('\r');
        let o = engine.process(line, &args.location);
        let mut j = rulelanes_engine::outcome_json(&o);
        j["event"] = serde_json::Value::String(line.to_string());
        if writeln!(out, "{j}").is_err() {
            break;
        }
    }
    ExitCode::SUCCESS
}

fn check(args: &Args) -> ExitCode {
    let mut dfiles = Vec::new();
    let mut rfiles = Vec::new();
    for d in &args.decoders {
        match rulelanes_syntax::xml_files(d) {
            Ok(f) => dfiles.extend(f),
            Err(e) => {
                eprintln!("rulelanes: {}: {e}", d.display());
                return ExitCode::from(1);
            }
        }
    }
    for d in &args.rules {
        match rulelanes_syntax::xml_files(d) {
            Ok(f) => rfiles.extend(f),
            Err(e) => {
                eprintln!("rulelanes: {}: {e}", d.display());
                return ExitCode::from(1);
            }
        }
    }
    let (_set, report) = rulelanes_syntax::check_files(&dfiles, &rfiles);
    let pct = |a: usize, b: usize| {
        if b == 0 {
            0.0
        } else {
            100.0 * a as f64 / b as f64
        }
    };
    let unsupported = report.unsupported_counts();
    if args.json {
        let j = serde_json::json!({
            "decoder_files": dfiles.len(),
            "rule_files": rfiles.len(),
            "decoders_total": report.decoders_total,
            "decoders_loaded": report.decoders_loaded,
            "rules_total": report.rules_total,
            "rules_loaded": report.rules_loaded,
            "unsupported": unsupported,
            "item_errors": report.item_errors.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
            "file_errors": report.file_errors.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
            "warnings": report.warnings,
        });
        println!("{}", serde_json::to_string_pretty(&j).unwrap_or_default());
    } else {
        println!(
            "decoders: {} of {} loaded ({:.1}%) from {} files",
            report.decoders_loaded,
            report.decoders_total,
            pct(report.decoders_loaded, report.decoders_total),
            dfiles.len()
        );
        println!(
            "rules:    {} of {} loaded ({:.1}%) from {} files",
            report.rules_loaded,
            report.rules_total,
            pct(report.rules_loaded, report.rules_total),
            rfiles.len()
        );
        println!(
            "skipped with a warning (as Wazuh would): {}",
            report.warnings.len()
        );
        if !unsupported.is_empty() {
            println!("unsupported (items refused, by first unsupported element):");
            let mut v: Vec<_> = unsupported.iter().collect();
            v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
            for (k, n) in v {
                println!("  {n:6}  {k}");
            }
        }
        let invalid = report
            .item_errors
            .iter()
            .filter(|e| e.kind != rulelanes_syntax::error::ErrorKind::Unsupported)
            .count();
        println!("refused as invalid or dependent on a refused item: {invalid}");
        for e in report.file_errors.iter().take(20) {
            println!("file error: {e}");
        }
    }
    ExitCode::SUCCESS
}
