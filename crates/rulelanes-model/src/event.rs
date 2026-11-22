//! Events, decoded fields and the outcome of running one event.

use std::collections::BTreeMap;

/// One input event after pre-decoding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Event {
    /// The line as received.
    pub full_log: String,
    /// Byte offset in `full_log` where the message starts (after the syslog
    /// header, when one was recognised).
    pub log_start: usize,
    pub timestamp: Option<String>,
    pub hostname: Option<String>,
    pub program_name: Option<String>,
    pub location: String,
}

impl Event {
    /// The message decoders and rules read: `full_log` after the header.
    pub fn log(&self) -> &str {
        &self.full_log[self.log_start..]
    }
}

/// Fields with a fixed meaning in Wazuh decoders (`order` names and rule
/// elements). Everything else is a dynamic field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StaticField {
    SrcUser,
    DstUser,
    SrcIp,
    DstIp,
    SrcPort,
    DstPort,
    Protocol,
    Action,
    Id,
    Url,
    Data,
    ExtraData,
    Status,
    SystemName,
}

impl StaticField {
    pub const ALL: [StaticField; 14] = [
        StaticField::SrcUser,
        StaticField::DstUser,
        StaticField::SrcIp,
        StaticField::DstIp,
        StaticField::SrcPort,
        StaticField::DstPort,
        StaticField::Protocol,
        StaticField::Action,
        StaticField::Id,
        StaticField::Url,
        StaticField::Data,
        StaticField::ExtraData,
        StaticField::Status,
        StaticField::SystemName,
    ];

    /// The key used in output and in `<field name=...>` lookups.
    pub fn key(self) -> &'static str {
        match self {
            StaticField::SrcUser => "srcuser",
            StaticField::DstUser => "dstuser",
            StaticField::SrcIp => "srcip",
            StaticField::DstIp => "dstip",
            StaticField::SrcPort => "srcport",
            StaticField::DstPort => "dstport",
            StaticField::Protocol => "protocol",
            StaticField::Action => "action",
            StaticField::Id => "id",
            StaticField::Url => "url",
            StaticField::Data => "data",
            StaticField::ExtraData => "extra_data",
            StaticField::Status => "status",
            StaticField::SystemName => "system_name",
        }
    }

    /// Map an `order` name to a static field. `user` is an alias of
    /// `dstuser`.
    pub fn from_order_name(name: &str) -> Option<StaticField> {
        if name == "user" {
            return Some(StaticField::DstUser);
        }
        StaticField::ALL.into_iter().find(|f| f.key() == name)
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// The decoder that matched, as reported in output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoderRef {
    pub name: String,
    pub parent: Option<String>,
}

/// Fields extracted by decoding one event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecodedEvent {
    pub decoder: Option<DecoderRef>,
    /// Index of the matched decoder in the rule set; used by `decoded_as`.
    pub decoder_index: Option<usize>,
    /// Category (decoder `type`); syslog when nothing decoded.
    pub category: crate::ruleset::Category,
    statics: [Option<String>; 14],
    /// Dynamic fields in the order they were set.
    pub dynamic: Vec<(String, String)>,
}

impl DecodedEvent {
    pub fn set_static(&mut self, f: StaticField, value: String) {
        self.statics[f.index()] = Some(value);
    }

    pub fn get_static(&self, f: StaticField) -> Option<&str> {
        self.statics[f.index()].as_deref()
    }

    pub fn push_dynamic(&mut self, key: String, value: String) {
        self.dynamic.push((key, value));
    }

    /// Look a field up by name the way rules do: static names first, then
    /// the first dynamic field with that key, both case-insensitively.
    pub fn find_field(&self, key: &str) -> Option<&str> {
        let lower = key.to_ascii_lowercase();
        if let Some(f) = StaticField::ALL.into_iter().find(|f| f.key() == lower) {
            return self.get_static(f);
        }
        self.dynamic
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// All fields as a flat map (dotted keys), as compared for R1. Empty
    /// dynamic fields are left out; empty static fields are kept. That is
    /// what wazuh-logtest 4.14.10 shows (checked in M1).
    pub fn data(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for f in StaticField::ALL {
            if let Some(v) = self.get_static(f) {
                out.insert(f.key().to_string(), v.to_string());
            }
        }
        for (k, v) in self.dynamic.iter().filter(|(_, v)| !v.is_empty()) {
            out.entry(k.clone()).or_insert_with(|| v.clone());
        }
        out
    }
}

/// The rule that a run settled on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHit {
    pub id: u32,
    pub level: u8,
    pub description: String,
    pub groups: Vec<String>,
}

/// The full result of running one event through decode and match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub event: Event,
    pub decoded: DecodedEvent,
    pub rule: Option<RuleHit>,
    /// True when an alert is generated (a rule matched with level > 0).
    pub alert: bool,
}
