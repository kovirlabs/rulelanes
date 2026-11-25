//! Decoding: choose the decoder and extract fields.
//!
//! Order of evaluation, as observed against `wazuh-logtest`:
//! - An event with a program name is tried only against top-level decoders
//!   that declare `program_name`; an event without one only against those
//!   that do not.
//! - The first top-level decoder whose `program_name` and `prematch` pass
//!   is taken. Its children are tried in load order; the first child whose
//!   `prematch` passes (or that has none) is taken.
//! - The taken decoder's regex extracts fields; sibling decoders that share
//!   its name then run their regexes in turn (multi-regex decoders).

use std::fmt::Write as _;

use rulelanes_model::event::{DecodedEvent, DecoderRef, StaticField};
use rulelanes_model::ruleset::{Decoder, Offset, OrderField, Plugin};
use rulelanes_model::{Event, RuleSet};

/// Buffers that decoding reuses from one event to the next. One per
/// thread; [`decode_into`] with the same `Scratch` and the same output
/// allocates nothing once the buffers have grown (R8), except where a
/// pattern or plugin does (PCRE2 captures and the JSON plugin, see the M2
/// status file).
#[derive(Debug, Default)]
pub struct Scratch {
    caps: Vec<(usize, usize)>,
    key: String,
    text: String,
}

pub fn decode(set: &RuleSet, ev: &Event) -> DecodedEvent {
    let mut out = DecodedEvent::default();
    decode_into(set, ev, &mut out, &mut Scratch::default());
    out
}

/// [`decode`] into `out` (cleared first), reusing its buffers and `sc`.
pub fn decode_into(set: &RuleSet, ev: &Event, out: &mut DecodedEvent, sc: &mut Scratch) {
    out.clear();
    let log = ev.log();
    let program_name = ev.program_name();
    let tops = if program_name.is_some() {
        &set.top_with_program
    } else {
        &set.top_without_program
    };
    for &top in tops {
        let d = &set.decoders[top];
        // Offset (into `log`) just after the parent's match.
        let mut pmatch = 0usize;
        if let Some(pn) = program_name {
            match &d.program_name {
                Some(p) if p.pattern.is_match(pn) => {}
                _ => continue,
            }
        }
        if let Some(pre) = &d.prematch {
            match pre.pattern.exec_into(log, &mut sc.caps) {
                Some((_, end)) => pmatch = end,
                None => continue,
            }
        }
        set_decoder(out, set, top);

        let children = &set.decoder_children[top];
        let (mut current, cmatch) = if children.is_empty() {
            (top, pmatch)
        } else {
            let mut chosen: Option<(usize, usize)> = None;
            let mut k = 0;
            while k < children.len() {
                let c = children[k];
                let cd = &set.decoders[c];
                match &cd.prematch {
                    Some(pre) => {
                        let base = if cd.prematch_offset == Offset::AfterParent {
                            pmatch
                        } else {
                            0
                        };
                        if let Some((_, end)) = pre.pattern.exec_into(&log[base..], &mut sc.caps) {
                            set_decoder(out, set, c);
                            chosen = Some((k, base + end));
                            break;
                        }
                    }
                    None => {
                        chosen = Some((k, pmatch));
                        break;
                    }
                }
                // Skip the rest of a chain of same-named siblings.
                if cd.get_next {
                    while k < children.len() && set.decoders[children[k]].get_next {
                        k += 1;
                    }
                    if k >= children.len() {
                        return;
                    }
                }
                k += 1;
            }
            match chosen {
                Some((k, cm)) => (k_index(children, k), cm),
                None => return,
            }
        };

        // Regex phase, following same-named siblings.
        let mut regex_prev: Option<usize> = None;
        let mut child_pos = children.iter().position(|&c| c == current);
        loop {
            let d = &set.decoders[current];
            if let Some((Plugin::Json, off)) = d.plugin {
                let start = match off {
                    Offset::AfterParent => pmatch,
                    Offset::AfterPrematch => cmatch,
                    _ => 0,
                };
                json_fields(out, sc, &log[start.min(log.len())..]);
            } else if let Some(re) = &d.regex {
                let base = match d.regex_offset {
                    Offset::None => 0,
                    Offset::AfterParent => pmatch,
                    Offset::AfterPrematch => cmatch,
                    Offset::AfterRegex => regex_prev.unwrap_or(cmatch),
                };
                let base = base.min(log.len());
                let subject = &log[base..];
                match re.pattern.exec_into(subject, &mut sc.caps) {
                    None => {
                        if d.get_next
                            && let Some(next) = next_sibling(children, &mut child_pos)
                        {
                            current = next;
                            continue;
                        }
                        return;
                    }
                    Some((_, end)) => {
                        regex_prev = Some(base + end);
                        assign(out, d, subject, &sc.caps);
                    }
                }
            } else {
                return;
            }
            if d.get_next
                && let Some(next) = next_sibling(children, &mut child_pos)
            {
                current = next;
                continue;
            }
            return;
        }
    }
}

fn k_index(children: &[usize], k: usize) -> usize {
    children[k]
}

fn next_sibling(children: &[usize], pos: &mut Option<usize>) -> Option<usize> {
    let p = (*pos)? + 1;
    *pos = Some(p);
    children.get(p).copied()
}

fn set_decoder(out: &mut DecodedEvent, set: &RuleSet, id: usize) {
    let d = &set.decoders[id];
    out.decoder = Some(DecoderRef {
        name: d.name.clone(),
        parent: d.parent.clone(),
    });
    // Both are `Arc<str>`: the clones above copy no text.
    out.decoder_index = Some(id);
    out.category = d.category;
}

fn assign(out: &mut DecodedEvent, d: &Decoder, subject: &str, caps: &[(usize, usize)]) {
    for (i, &(a, b)) in caps.iter().enumerate() {
        let Some(field) = d.order.get(i) else { break };
        let v = subject.get(a..b).unwrap_or("");
        match field {
            OrderField::Static(f) => out.set_static(*f, v),
            OrderField::Dynamic(k) => out.push_dynamic(k, v),
        }
    }
}

/// The JSON decoder plugin: object keys are flattened with `.`; strings
/// are taken as they are, numbers and booleans as their JSON text, arrays
/// as their JSON text. Static field names fill the static fields.
///
/// Parsing builds a `serde_json::Value`, so this path allocates per event
/// (R8); the flattening itself reuses `sc`.
fn json_fields(out: &mut DecodedEvent, sc: &mut Scratch, text: &str) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text.trim()) else {
        return;
    };
    let serde_json::Value::Object(map) = value else {
        return;
    };
    sc.key.clear();
    flatten(out, &mut sc.key, &mut sc.text, &map);
}

fn flatten(
    out: &mut DecodedEvent,
    key: &mut String,
    text: &mut String,
    map: &serde_json::Map<String, serde_json::Value>,
) {
    for (k, v) in map {
        let len = key.len();
        if len > 0 {
            key.push('.');
        }
        key.push_str(k);
        let value: &str = match v {
            serde_json::Value::Object(inner) => {
                flatten(out, key, text, inner);
                key.truncate(len);
                continue;
            }
            serde_json::Value::String(s) => s,
            serde_json::Value::Null => "null",
            other => {
                text.clear();
                // `Display` for a `Value` writes its compact JSON text, the
                // same text `to_string` gives.
                let _ = write!(text, "{other}");
                text
            }
        };
        match StaticField::ALL
            .into_iter()
            .find(|f| f.key() == key.as_str())
        {
            Some(f) => out.set_static(f, value),
            None => out.push_dynamic(key, value),
        }
        key.truncate(len);
    }
}
