//! Events, decoded fields and the outcome of running one event.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

/// One input event after pre-decoding.
///
/// The header parts are byte ranges into `full_log`, so filling an event
/// again ([`Event::reset`]) reuses its buffer and allocates nothing once
/// the buffer is as long as the longest line (R8).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Event {
    /// The line as received.
    pub full_log: String,
    /// Byte offset in `full_log` where the message starts (after the syslog
    /// header, when one was recognised).
    pub log_start: usize,
    /// Where the timestamp sits in `full_log`.
    pub timestamp_at: Option<Range<usize>>,
    /// Where the hostname sits in `full_log`.
    pub hostname_at: Option<Range<usize>>,
    /// Where the program name sits in `full_log`.
    pub program_name_at: Option<Range<usize>>,
    /// Shared with every event from the same source.
    pub location: Arc<str>,
}

impl Event {
    /// The message decoders and rules read: `full_log` after the header.
    pub fn log(&self) -> &str {
        &self.full_log[self.log_start..]
    }

    pub fn timestamp(&self) -> Option<&str> {
        self.timestamp_at.clone().map(|r| &self.full_log[r])
    }

    pub fn hostname(&self) -> Option<&str> {
        self.hostname_at.clone().map(|r| &self.full_log[r])
    }

    pub fn program_name(&self) -> Option<&str> {
        self.program_name_at.clone().map(|r| &self.full_log[r])
    }

    /// Empties the event and sets its line and location, keeping the
    /// line buffer.
    pub fn reset(&mut self, line: &str, location: &Arc<str>) {
        self.full_log.clear();
        self.full_log.push_str(line);
        self.log_start = 0;
        self.timestamp_at = None;
        self.hostname_at = None;
        self.program_name_at = None;
        if !Arc::ptr_eq(&self.location, location) {
            self.location = Arc::clone(location);
        }
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
    pub name: Arc<str>,
    pub parent: Option<Arc<str>>,
}

/// Fields extracted by decoding one event.
///
/// [`DecodedEvent::clear`] keeps every string buffer, so decoding into the
/// same value again allocates nothing once its buffers have grown to fit
/// (R8). Equality compares only the fields that are set.
#[derive(Debug, Clone, Default)]
pub struct DecodedEvent {
    pub decoder: Option<DecoderRef>,
    /// Index of the matched decoder in the rule set; used by `decoded_as`.
    pub decoder_index: Option<usize>,
    /// Category (decoder `type`); syslog when nothing decoded.
    pub category: crate::ruleset::Category,
    statics: [String; 14],
    /// Bit `i` set: static field `i` has a value.
    set: u16,
    /// Dynamic fields; only the first `dynamic_len` are set, the rest are
    /// buffers kept for reuse.
    dynamic: Vec<(String, String)>,
    dynamic_len: usize,
}

impl PartialEq for DecodedEvent {
    fn eq(&self, other: &Self) -> bool {
        self.decoder == other.decoder
            && self.decoder_index == other.decoder_index
            && self.category == other.category
            && StaticField::ALL
                .into_iter()
                .all(|f| self.get_static(f) == other.get_static(f))
            && self.dynamic() == other.dynamic()
    }
}

impl Eq for DecodedEvent {}

impl DecodedEvent {
    /// Forgets every field, keeping the buffers.
    pub fn clear(&mut self) {
        self.decoder = None;
        self.decoder_index = None;
        self.category = crate::ruleset::Category::default();
        self.set = 0;
        self.dynamic_len = 0;
    }

    pub fn set_static(&mut self, f: StaticField, value: &str) {
        let slot = &mut self.statics[f.index()];
        slot.clear();
        slot.push_str(value);
        self.set |= 1 << f.index();
    }

    pub fn get_static(&self, f: StaticField) -> Option<&str> {
        (self.set & (1 << f.index()) != 0).then(|| self.statics[f.index()].as_str())
    }

    pub fn push_dynamic(&mut self, key: &str, value: &str) {
        if self.dynamic_len == self.dynamic.len() {
            self.dynamic.push((String::new(), String::new()));
        }
        let (k, v) = &mut self.dynamic[self.dynamic_len];
        k.clear();
        k.push_str(key);
        v.clear();
        v.push_str(value);
        self.dynamic_len += 1;
    }

    /// Dynamic fields in the order they were set.
    pub fn dynamic(&self) -> &[(String, String)] {
        &self.dynamic[..self.dynamic_len]
    }

    /// Look a field up by name the way rules do: static names first, then
    /// the first dynamic field with that key, both case-insensitively.
    /// Allocates nothing.
    pub fn find_field(&self, key: &str) -> Option<&str> {
        if let Some(f) = StaticField::ALL
            .into_iter()
            .find(|f| f.key().eq_ignore_ascii_case(key))
        {
            return self.get_static(f);
        }
        self.dynamic()
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
        for (k, v) in self.dynamic().iter().filter(|(_, v)| !v.is_empty()) {
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
    /// Shared with the rule, so a hit does not copy them.
    pub groups: Arc<[String]>,
}

/// The full result of running one event through decode and match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    pub event: Event,
    pub decoded: DecodedEvent,
    pub rule: Option<RuleHit>,
    /// True when an alert is generated (a rule matched with level > 0).
    pub alert: bool,
}
