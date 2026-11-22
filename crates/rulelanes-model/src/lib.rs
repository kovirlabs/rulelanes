//! Types shared by the rulelanes crates: events, decoded fields, outcomes,
//! and compiled decoders, rules and patterns. No I/O.
#![forbid(unsafe_code)]

pub mod event;
pub mod pattern;
pub mod ruleset;

pub use event::{DecodedEvent, DecoderRef, Event, Outcome, RuleHit, StaticField};
pub use pattern::{Expr, MatchResult, OsMatch, OsRegex, Pattern, Pcre2};
pub use ruleset::{
    Category, Conditions, Decoder, DecoderId, Offset, OrderField, Plugin, Rule, RuleNode, RuleSet,
};
