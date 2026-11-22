//! Load Wazuh 4.x decoder and rule XML into compiled rulelanes types.
//!
//! Only the M1 subset in `docs/syntax.md` is supported. Anything else is
//! refused with a [`LoadError`] naming the file, the decoder or rule, and
//! the element or attribute (requirement R2).
#![forbid(unsafe_code)]

pub mod decoders;
pub mod error;
pub mod patterns;
pub mod rules;
pub mod xml;

pub use error::{LoadError, LoadReport};

use rulelanes_model::RuleSet;
use std::path::{Path, PathBuf};

/// List the `.xml` files in a directory, sorted by name (Wazuh loads a
/// directory in name order).
pub fn xml_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "xml"))
        .collect();
    v.sort();
    Ok(v)
}

/// Load decoders then rules from directories, strictly: the first
/// unsupported or invalid item fails the whole load.
pub fn load_dirs(decoder_dirs: &[PathBuf], rule_dirs: &[PathBuf]) -> Result<RuleSet, LoadError> {
    let mut files = Vec::new();
    for d in decoder_dirs {
        files.extend(xml_files(d).map_err(|e| LoadError::io(d, e))?);
    }
    let mut rfiles = Vec::new();
    for d in rule_dirs {
        rfiles.extend(xml_files(d).map_err(|e| LoadError::io(d, e))?);
    }
    load_files(&files, &rfiles)
}

/// Load the given decoder files then rule files, strictly.
pub fn load_files(decoder_files: &[PathBuf], rule_files: &[PathBuf]) -> Result<RuleSet, LoadError> {
    let mut set = RuleSet::default();
    let mut report = LoadReport::default();
    for f in decoder_files {
        let text = std::fs::read_to_string(f).map_err(|e| LoadError::io(f, e))?;
        decoders::load_text(&mut set, &f.display().to_string(), &text, true, &mut report)?;
    }
    for f in rule_files {
        let text = std::fs::read_to_string(f).map_err(|e| LoadError::io(f, e))?;
        rules::load_text(&mut set, &f.display().to_string(), &text, true, &mut report)?;
    }
    Ok(set)
}

/// Load leniently: unsupported or invalid items are skipped and recorded in
/// the report, so the share of a rule set that loads can be measured
/// (`rulelanes check`).
pub fn check_files(decoder_files: &[PathBuf], rule_files: &[PathBuf]) -> (RuleSet, LoadReport) {
    let mut set = RuleSet::default();
    let mut report = LoadReport::default();
    for f in decoder_files {
        let name = f.display().to_string();
        match std::fs::read_to_string(f) {
            Ok(text) => {
                let _ = decoders::load_text(&mut set, &name, &text, false, &mut report);
            }
            Err(e) => report.file_errors.push(LoadError::io(f, e)),
        }
    }
    for f in rule_files {
        let name = f.display().to_string();
        match std::fs::read_to_string(f) {
            Ok(text) => {
                let _ = rules::load_text(&mut set, &name, &text, false, &mut report);
            }
            Err(e) => report.file_errors.push(LoadError::io(f, e)),
        }
    }
    (set, report)
}
