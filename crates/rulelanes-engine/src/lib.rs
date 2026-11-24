//! The single-threaded reference engine. For the syntax it supports it must
//! give the same result as `wazuh-logtest` (R1); the staged pipeline (M2)
//! must give the same result as this engine (R3).
#![forbid(unsafe_code)]

pub mod decode;
pub mod matcher;
pub mod predecode;

use rulelanes_model::{Outcome, RuleSet};

/// Runs events through pre-decode, decode and match against one rule set.
///
/// The staged pipeline gives each stage its own clone, so that no two
/// threads use the same compiled patterns.
#[derive(Clone)]
pub struct Engine {
    set: RuleSet,
    alert_level: u8,
}

impl Engine {
    pub fn new(set: RuleSet) -> Engine {
        Engine {
            set,
            alert_level: DEFAULT_ALERT_LEVEL,
        }
    }

    pub fn ruleset(&self) -> &RuleSet {
        &self.set
    }

    /// The minimum level at which a matched rule raises an alert.
    pub fn alert_level(&self) -> u8 {
        self.alert_level
    }

    /// Process one log line received from `location`.
    pub fn process(&self, line: &str, location: &str) -> Outcome {
        let event = predecode::predecode(line, location);
        let decoded = decode::decode(&self.set, &event);
        let (rule, alert) = matcher::match_rules(&self.set, &event, &decoded, self.alert_level);
        Outcome {
            event,
            decoded,
            rule,
            alert,
        }
    }
}

/// The outcome as JSON in the shape of `wazuh-logtest`'s `output` object
/// (only the parts rulelanes produces), plus `alert`.
pub fn outcome_json(o: &Outcome) -> serde_json::Value {
    use serde_json::{Map, Value, json};
    let mut pre = Map::new();
    if let Some(h) = &o.event.hostname {
        pre.insert("hostname".into(), json!(h));
    }
    if let Some(p) = &o.event.program_name {
        pre.insert("program_name".into(), json!(p));
    }
    if let Some(t) = &o.event.timestamp {
        pre.insert("timestamp".into(), json!(t));
    }
    let mut dec = Map::new();
    if let Some(d) = &o.decoded.decoder {
        if let Some(p) = &d.parent {
            dec.insert("parent".into(), json!(p));
        }
        dec.insert("name".into(), json!(d.name));
    }
    let mut data = Map::new();
    for (k, v) in o.decoded.data() {
        insert_dotted(&mut data, &k, Value::String(v));
    }
    let mut out = Map::new();
    out.insert("full_log".into(), json!(o.event.full_log));
    out.insert("location".into(), json!(o.event.location));
    if !pre.is_empty() {
        out.insert("predecoder".into(), Value::Object(pre));
    }
    out.insert("decoder".into(), Value::Object(dec));
    if !data.is_empty() {
        out.insert("data".into(), Value::Object(data));
    }
    if let Some(r) = &o.rule {
        out.insert(
            "rule".into(),
            json!({
                "id": r.id.to_string(),
                "level": r.level,
                "description": r.description,
                "groups": r.groups,
            }),
        );
    }
    json!({ "alert": o.alert, "output": Value::Object(out) })
}

fn insert_dotted(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    v: serde_json::Value,
) {
    match key.split_once('.') {
        None => {
            map.insert(key.to_string(), v);
        }
        Some((head, tail)) => {
            let entry = map
                .entry(head.to_string())
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
            if let serde_json::Value::Object(inner) = entry {
                insert_dotted(inner, tail, v);
            }
        }
    }
}

/// Wazuh's default `<alerts><log_alert_level>` (also the value in the
/// oracle's `ossec.conf`, checked in M1).
pub const DEFAULT_ALERT_LEVEL: u8 = 3;

impl Engine {
    /// Use a different minimum alert level (the manager's
    /// `log_alert_level`).
    pub fn with_alert_level(mut self, level: u8) -> Engine {
        self.alert_level = level;
        self
    }
}
