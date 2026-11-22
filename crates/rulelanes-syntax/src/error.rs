//! Load-time errors and the lenient-load report.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorKind {
    /// Valid Wazuh syntax that rulelanes does not support (yet).
    Unsupported,
    /// Syntax Wazuh itself would reject, or that cannot be parsed.
    Invalid,
    /// The file could not be read.
    Io,
}

/// A load error. It always names the file, and where it applies the
/// decoder or rule and the element or attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError {
    pub kind: ErrorKind,
    pub file: String,
    /// `decoder 'name'` or `rule 100100`.
    pub item: Option<String>,
    /// `<element>` or `<element attr=...>` or `rule@attr`.
    pub element: Option<String>,
    pub message: String,
}

impl LoadError {
    pub fn io(path: &Path, e: std::io::Error) -> LoadError {
        LoadError {
            kind: ErrorKind::Io,
            file: path.display().to_string(),
            item: None,
            element: None,
            message: e.to_string(),
        }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            ErrorKind::Unsupported => "unsupported",
            ErrorKind::Invalid => "invalid",
            ErrorKind::Io => "cannot read",
        };
        write!(f, "{}", self.file)?;
        if let Some(i) = &self.item {
            write!(f, ": {i}")?;
        }
        write!(f, ": {kind}")?;
        if let Some(e) = &self.element {
            write!(f, " {e}")?;
        }
        write!(f, ": {}", self.message)
    }
}

impl std::error::Error for LoadError {}

/// What a lenient load (`rulelanes check`) found.
#[derive(Debug, Clone, Default)]
pub struct LoadReport {
    pub decoders_total: usize,
    pub decoders_loaded: usize,
    pub rules_total: usize,
    pub rules_loaded: usize,
    /// Items that failed to load, one error each.
    pub item_errors: Vec<LoadError>,
    /// Whole files that could not be read or parsed.
    pub file_errors: Vec<LoadError>,
    /// Things Wazuh only warns about (for example `if_sid` naming a rule
    /// that does not exist); the item is skipped as Wazuh skips it.
    pub warnings: Vec<String>,
}

impl LoadReport {
    /// Count of unsupported elements or attributes, by name.
    pub fn unsupported_counts(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for e in &self.item_errors {
            if e.kind == ErrorKind::Unsupported {
                let key = e.element.clone().unwrap_or_else(|| e.message.clone());
                *m.entry(key).or_insert(0) += 1;
            }
        }
        m
    }
}
