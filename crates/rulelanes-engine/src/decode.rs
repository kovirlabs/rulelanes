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

use rulelanes_model::event::{DecodedEvent, DecoderRef, StaticField};
use rulelanes_model::ruleset::{Decoder, Offset, OrderField, Plugin};
use rulelanes_model::{Event, RuleSet};

pub fn decode(set: &RuleSet, ev: &Event) -> DecodedEvent {
    let mut out = DecodedEvent::default();
    let log = ev.log();
    let tops = if ev.program_name.is_some() {
        &set.top_with_program
    } else {
        &set.top_without_program
    };
    for &top in tops {
        let d = &set.decoders[top];
        // Offset (into `log`) just after the parent's match.
        let mut pmatch = 0usize;
        if let Some(pn) = &ev.program_name {
            match &d.program_name {
                Some(p) if p.pattern.is_match(pn) => {}
                _ => continue,
            }
        }
        if let Some(pre) = &d.prematch {
            match pre.pattern.exec(log) {
                Some(m) => pmatch = m.end,
                None => continue,
            }
        }
        set_decoder(&mut out, set, top);

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
                        if let Some(m) = pre.pattern.exec(&log[base..]) {
                            set_decoder(&mut out, set, c);
                            chosen = Some((k, base + m.end));
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
                        return out;
                    }
                }
                k += 1;
            }
            match chosen {
                Some((k, cm)) => (k_index(children, k), cm),
                None => return out,
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
                json_fields(&mut out, &log[start.min(log.len())..]);
            } else if let Some(re) = &d.regex {
                let base = match d.regex_offset {
                    Offset::None => 0,
                    Offset::AfterParent => pmatch,
                    Offset::AfterPrematch => cmatch,
                    Offset::AfterRegex => regex_prev.unwrap_or(cmatch),
                };
                let base = base.min(log.len());
                let subject = &log[base..];
                match re.pattern.exec(subject) {
                    None => {
                        if d.get_next
                            && let Some(next) = next_sibling(children, &mut child_pos)
                        {
                            current = next;
                            continue;
                        }
                        return out;
                    }
                    Some(m) => {
                        regex_prev = Some(base + m.end);
                        assign(&mut out, d, subject, &m.captures);
                    }
                }
            } else {
                return out;
            }
            if d.get_next
                && let Some(next) = next_sibling(children, &mut child_pos)
            {
                current = next;
                continue;
            }
            return out;
        }
    }
    out
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
    out.decoder_index = Some(id);
    out.category = d.category;
}

fn assign(out: &mut DecodedEvent, d: &Decoder, subject: &str, caps: &[(usize, usize)]) {
    for (i, &(a, b)) in caps.iter().enumerate() {
        let Some(field) = d.order.get(i) else { break };
        let v = subject.get(a..b).unwrap_or("").to_string();
        match field {
            OrderField::Static(f) => out.set_static(*f, v),
            OrderField::Dynamic(k) => out.push_dynamic(k.clone(), v),
        }
    }
}

/// The JSON decoder plugin: object keys are flattened with `.`; strings
/// are taken as they are, numbers and booleans as their JSON text, arrays
/// as their JSON text. Static field names fill the static fields.
fn json_fields(out: &mut DecodedEvent, text: &str) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text.trim()) else {
        return;
    };
    let serde_json::Value::Object(map) = value else {
        return;
    };
    flatten(out, "", &map);
}

fn flatten(out: &mut DecodedEvent, prefix: &str, map: &serde_json::Map<String, serde_json::Value>) {
    for (k, v) in map {
        let key = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        let text = match v {
            serde_json::Value::Object(inner) => {
                flatten(out, &key, inner);
                continue;
            }
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => "null".to_string(),
            other => other.to_string(),
        };
        match StaticField::ALL.into_iter().find(|f| f.key() == key) {
            Some(f) => out.set_static(f, text),
            None => out.push_dynamic(key, text),
        }
    }
}
