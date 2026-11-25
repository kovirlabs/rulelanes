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
    /// JSON keys seen in the event, by path, to find duplicates.
    seen: Vec<String>,
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
            match pre.pattern.find_end(log) {
                Some(end) => pmatch = end,
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
                        if let Some(end) = pre.pattern.find_end(&log[base..]) {
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
/// The reference behaviour is [`json_fields_value`]: parse into a
/// `serde_json::Value` (with `preserve_order`), then flatten. That builds
/// a tree per event, so the plugin instead checks the text once
/// ([`json::check`]: valid, an object, no duplicate key) and then streams
/// it straight into `out` ([`json::write`]), which allocates nothing once
/// the buffers have grown. Two cases still take the `Value` path or build
/// a `Value`: an object with a duplicate key (a `preserve_order` map keeps
/// the first position and the last value, which streaming cannot know in
/// advance), and an array (its JSON text is printed from a `Value`).
fn json_fields(out: &mut DecodedEvent, sc: &mut Scratch, text: &str) {
    let text = text.trim();
    match json::check(text, &mut sc.key, &mut sc.seen) {
        json::Shape::NotObject => {}
        json::Shape::Object {
            duplicate_key: true,
        } => json_fields_value(out, sc, text),
        json::Shape::Object {
            duplicate_key: false,
        } => {
            sc.key.clear();
            json::write(text, out, &mut sc.key, &mut sc.text);
        }
    }
}

/// The JSON plugin through a `serde_json::Value` (the reference; used for
/// objects with duplicate keys).
fn json_fields_value(out: &mut DecodedEvent, sc: &mut Scratch, text: &str) {
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
        set_json_field(out, key, value);
        key.truncate(len);
    }
}

fn set_json_field(out: &mut DecodedEvent, key: &str, value: &str) {
    match StaticField::ALL.into_iter().find(|f| f.key() == key) {
        Some(f) => out.set_static(f, value),
        None => out.push_dynamic(key, value),
    }
}

/// Streaming JSON for the plugin, on `serde_json`'s own parser so that
/// validity and number text are the same as through a `Value`.
mod json {
    use std::fmt::{self, Write as _};

    use serde::Deserialize as _;
    use serde::de::{
        DeserializeSeed, Deserializer, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor,
    };

    use super::{DecodedEvent, set_json_field};

    pub enum Shape {
        /// Invalid JSON, or valid but not an object: the plugin sets
        /// nothing.
        NotObject,
        Object {
            duplicate_key: bool,
        },
    }

    /// Validates `text` as one JSON object and looks for a key that appears
    /// twice in the same object. `path` and `seen` are reused buffers.
    pub fn check(text: &str, path: &mut String, seen: &mut Vec<String>) -> Shape {
        path.clear();
        let mut c = Check {
            path,
            seen,
            used: 0,
            duplicate: false,
        };
        let mut de = serde_json::Deserializer::from_str(text);
        match Top(&mut c).deserialize(&mut de) {
            Ok(true) if de.end().is_ok() => Shape::Object {
                duplicate_key: c.duplicate,
            },
            _ => Shape::NotObject,
        }
    }

    /// Flattens `text`, which [`check`] has accepted, into `out`.
    pub fn write(text: &str, out: &mut DecodedEvent, key: &mut String, buf: &mut String) {
        let mut w = Write { out, key, buf };
        let mut de = serde_json::Deserializer::from_str(text);
        // `check` accepted the same text with the same parser.
        let _ = (&mut de).deserialize_map(WriteValue(&mut w));
    }

    struct Check<'a> {
        /// Keys from the top object down, each preceded by NUL, so that
        /// the key `a.b` and the key `b` inside `a` differ.
        path: &'a mut String,
        seen: &'a mut Vec<String>,
        used: usize,
        duplicate: bool,
    }

    impl Check<'_> {
        /// Records the current path; notes a duplicate if it was seen.
        fn note(&mut self) {
            if self.seen[..self.used].iter().any(|s| s == self.path) {
                self.duplicate = true;
            }
            if self.used == self.seen.len() {
                self.seen.push(String::new());
            }
            let slot = &mut self.seen[self.used];
            slot.clear();
            slot.push_str(self.path);
            self.used += 1;
        }

        fn walk_map<'de, A: MapAccess<'de>>(&mut self, mut map: A) -> Result<(), A::Error> {
            loop {
                let len = self.path.len();
                self.path.push('\0');
                if map.next_key_seed(KeyInto(self.path))?.is_none() {
                    self.path.truncate(len);
                    return Ok(());
                }
                self.note();
                map.next_value_seed(CheckValue(self))?;
                self.path.truncate(len);
            }
        }
    }

    /// The top value: true when it is an object (walked); false otherwise.
    struct Top<'s, 'a>(&'s mut Check<'a>);

    impl<'de> DeserializeSeed<'de> for Top<'_, '_> {
        type Value = bool;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<bool, D::Error> {
            d.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for Top<'_, '_> {
        type Value = bool;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON value")
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<bool, A::Error> {
            self.0.walk_map(map)?;
            Ok(true)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<bool, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(false)
        }
        fn visit_str<E>(self, _: &str) -> Result<bool, E> {
            Ok(false)
        }
        fn visit_bool<E>(self, _: bool) -> Result<bool, E> {
            Ok(false)
        }
        fn visit_i64<E>(self, _: i64) -> Result<bool, E> {
            Ok(false)
        }
        fn visit_u64<E>(self, _: u64) -> Result<bool, E> {
            Ok(false)
        }
        fn visit_f64<E>(self, _: f64) -> Result<bool, E> {
            Ok(false)
        }
        fn visit_unit<E>(self) -> Result<bool, E> {
            Ok(false)
        }
    }

    struct CheckValue<'s, 'a>(&'s mut Check<'a>);

    impl<'de> DeserializeSeed<'de> for CheckValue<'_, '_> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for CheckValue<'_, '_> {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON value")
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<(), A::Error> {
            self.0.walk_map(map)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
            // Arrays are printed from a `Value`, which handles duplicate
            // keys inside them itself.
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(())
        }
        fn visit_str<E>(self, _: &str) -> Result<(), E> {
            Ok(())
        }
        fn visit_bool<E>(self, _: bool) -> Result<(), E> {
            Ok(())
        }
        fn visit_i64<E>(self, _: i64) -> Result<(), E> {
            Ok(())
        }
        fn visit_u64<E>(self, _: u64) -> Result<(), E> {
            Ok(())
        }
        fn visit_f64<E>(self, _: f64) -> Result<(), E> {
            Ok(())
        }
        fn visit_unit<E>(self) -> Result<(), E> {
            Ok(())
        }
    }

    /// Appends a key (borrowed or unescaped by the parser) to a buffer.
    struct KeyInto<'a>(&'a mut String);

    impl<'de> DeserializeSeed<'de> for KeyInto<'_> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_str(self)
        }
    }

    impl<'de> Visitor<'de> for KeyInto<'_> {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string key")
        }
        fn visit_str<E>(self, v: &str) -> Result<(), E> {
            self.0.push_str(v);
            Ok(())
        }
    }

    struct Write<'a> {
        out: &'a mut DecodedEvent,
        /// The flattened key, `.`-joined.
        key: &'a mut String,
        /// Text of the current number or array.
        buf: &'a mut String,
    }

    impl Write<'_> {
        fn set(&mut self, value: &str) {
            set_json_field(self.out, self.key, value);
        }

        fn set_display(&mut self, v: impl fmt::Display) {
            self.buf.clear();
            let _ = write!(self.buf, "{v}");
            set_json_field(self.out, self.key, self.buf);
        }
    }

    struct WriteValue<'s, 'a>(&'s mut Write<'a>);

    impl<'de> DeserializeSeed<'de> for WriteValue<'_, '_> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for WriteValue<'_, '_> {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON value")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            let w = self.0;
            loop {
                let len = w.key.len();
                if len > 0 {
                    w.key.push('.');
                }
                if map.next_key_seed(KeyInto(w.key))?.is_none() {
                    w.key.truncate(len);
                    return Ok(());
                }
                map.next_value_seed(WriteValue(w))?;
                w.key.truncate(len);
            }
        }
        fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<(), A::Error> {
            // The array's JSON text, as `Value` prints it. Allocates.
            let v =
                serde_json::Value::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
                    .map_err(A::Error::custom)?;
            self.0.set_display(v);
            Ok(())
        }
        fn visit_str<E>(self, v: &str) -> Result<(), E> {
            self.0.set(v);
            Ok(())
        }
        fn visit_bool<E>(self, v: bool) -> Result<(), E> {
            self.0.set(if v { "true" } else { "false" });
            Ok(())
        }
        // Numbers are printed as `serde_json::Number`, as through a `Value`.
        fn visit_i64<E>(self, v: i64) -> Result<(), E> {
            self.0.set_display(serde_json::Number::from(v));
            Ok(())
        }
        fn visit_u64<E>(self, v: u64) -> Result<(), E> {
            self.0.set_display(serde_json::Number::from(v));
            Ok(())
        }
        fn visit_f64<E>(self, v: f64) -> Result<(), E> {
            match serde_json::Number::from_f64(v) {
                Some(n) => self.0.set_display(n),
                None => self.0.set("null"),
            }
            Ok(())
        }
        fn visit_unit<E>(self) -> Result<(), E> {
            self.0.set("null");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn both(text: &str) -> (DecodedEvent, DecodedEvent) {
        let mut sc = Scratch::default();
        let mut streamed = DecodedEvent::default();
        json_fields(&mut streamed, &mut sc, text);
        let mut reference = DecodedEvent::default();
        json_fields_value(&mut reference, &mut sc, text);
        (streamed, reference)
    }

    #[test]
    fn json_streaming_equals_value_path_on_cases() {
        let cases = [
            r#"{"a":1,"b":"x","c":{"d":true,"e":null}}"#,
            r#"{"srcip":"10.0.0.1","dstport":443,"nested":{"srcuser":"u"}}"#,
            r#"{"n":-1,"f":1.5,"g":1e3,"h":-0,"i":18446744073709551615,"j":1e400}"#,
            r#"{"arr":[1,"two",{"three":3},[4]],"x":"y"}"#,
            r#"{"esc":"a\"b\\c\u00e9\n","k\"ey":"v","a.b":1,"a":{"b":2}}"#,
            r#"{"dup":1,"other":2,"dup":3}"#,
            r#"{"o":{"x":1},"o":{"y":2}}"#,
            r#"{"o":{"x":1,"x":2}}"#,
            r#"{"empty":{},"s":""}"#,
            r#"  {"ws": 1 }  "#,
            r#"[1,2,3]"#,
            r#""just a string""#,
            r#"{"unterminated":"#,
            r#"{"a":1} trailing"#,
            r#""#,
            r#"{"deep":{"a":{"b":{"c":{"d":"e"}}}}}"#,
        ];
        for text in cases {
            let (s, r) = both(text);
            assert_eq!(s, r, "{text}");
        }
    }

    /// Random objects from a fixed seed: keys from a small set (so
    /// duplicates and `a.b` collisions occur), every value kind, escapes.
    #[test]
    fn json_streaming_equals_value_path_generated() {
        let mut state: u64 = 0x5EED_2026_1124;
        let mut next = |n: u64| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) % n
        };
        fn value(next: &mut dyn FnMut(u64) -> u64, depth: u32, out: &mut String) {
            let kind = if depth > 3 { next(6) } else { next(8) };
            match kind {
                0 => out.push_str(["\"s\"", "\"a\\\"q\"", "\"\\u00e9\"", "\"\""][next(4) as usize]),
                1 => out.push_str(&(next(2000) as i64 - 1000).to_string()),
                2 => out.push_str(["1.25", "-0.5", "1e2", "3E-2", "0.1"][next(5) as usize]),
                3 => out.push_str(["true", "false"][next(2) as usize]),
                4 => out.push_str("null"),
                5 => out.push_str("[1,\"x\",null]"),
                _ => object(next, depth + 1, out),
            }
        }
        fn object(next: &mut dyn FnMut(u64) -> u64, depth: u32, out: &mut String) {
            out.push('{');
            let n = next(5);
            for i in 0..n {
                if i > 0 {
                    out.push(',');
                }
                let key = ["a", "b", "a.b", "srcip", "id", "k\\\"q", "data"][next(7) as usize];
                out.push('"');
                out.push_str(key);
                out.push_str("\":");
                value(next, depth, out);
            }
            out.push('}');
        }
        for _ in 0..5000 {
            let mut text = String::new();
            object(&mut next, 0, &mut text);
            let (s, r) = both(&text);
            assert_eq!(s, r, "{text}");
        }
    }
}
