//! Rule matching over the rule tree.
//!
//! Top-level rules are tried in order (only those whose category equals the
//! decoder type). A rule that passes tries its children in order (highest
//! level first, level 0 before all); the first child that matches wins,
//! otherwise the rule itself is the result unless it is `noalert`. The
//! first top-level rule that gives a result ends the search; level 0 means
//! "no alert".

use rulelanes_model::event::{DecodedEvent, RuleHit, StaticField};
use rulelanes_model::pattern::Expr;
use rulelanes_model::ruleset::Rule;
use rulelanes_model::{Event, RuleSet};

/// `alert_level` is the manager's `<alerts><log_alert_level>`: a matched rule
/// below it is reported but generates no alert.
pub fn match_rules(
    set: &RuleSet,
    ev: &Event,
    de: &DecodedEvent,
    alert_level: u8,
) -> (Option<RuleHit>, bool) {
    for &root in &set.roots {
        let rule = &set.rules[set.nodes[root].rule];
        if rule.category != de.category {
            continue;
        }
        if let Some(r) = check(set, root, ev, de) {
            let rule = &set.rules[r];
            let hit = RuleHit {
                id: rule.id,
                level: rule.level,
                description: describe(&rule.description, ev, de),
                groups: rule.groups(),
            };
            let alert = rule.level > 0 && rule.level >= alert_level;
            return (Some(hit), alert);
        }
    }
    (None, false)
}

fn check(set: &RuleSet, node: usize, ev: &Event, de: &DecodedEvent) -> Option<usize> {
    let r = set.nodes[node].rule;
    if !conditions(set, &set.rules[r], ev, de) {
        return None;
    }
    for &c in &set.nodes[node].children {
        if let Some(hit) = check(set, c, ev, de) {
            return Some(hit);
        }
    }
    if set.rules[r].noalert {
        return None;
    }
    Some(r)
}

fn opt_passes(e: &Option<Expr>, value: Option<&str>) -> bool {
    match e {
        None => true,
        Some(e) => match value {
            None => false,
            Some(v) => e.passes(v),
        },
    }
}

fn conditions(set: &RuleSet, rule: &Rule, ev: &Event, de: &DecodedEvent) -> bool {
    if let Some(name) = &rule.decoded_as {
        let Some(idx) = de.decoder_index else {
            return false;
        };
        if &set.decoders[idx].name != name {
            return false;
        }
    }
    let c = &rule.conds;
    let log = ev.log();
    opt_passes(&c.program_name, ev.program_name.as_deref())
        && opt_passes(&c.id, de.get_static(StaticField::Id))
        && opt_passes(&c.match_, Some(log))
        && opt_passes(&c.regex, Some(log))
        && opt_passes(&c.action, de.get_static(StaticField::Action))
        && opt_passes(&c.url, de.get_static(StaticField::Url))
        && opt_passes(&c.location, Some(&ev.location))
        && c.fields
            .iter()
            .all(|(name, e)| de.find_field(name).is_some_and(|v| e.passes(v)))
        && opt_passes(&c.srcip, de.get_static(StaticField::SrcIp))
        && opt_passes(&c.dstip, de.get_static(StaticField::DstIp))
        && opt_passes(&c.srcport, de.get_static(StaticField::SrcPort))
        && opt_passes(&c.dstport, de.get_static(StaticField::DstPort))
        && opt_passes(
            &c.user,
            de.get_static(StaticField::DstUser)
                .or(de.get_static(StaticField::SrcUser)),
        )
        && opt_passes(&c.extra_data, de.get_static(StaticField::ExtraData))
        && opt_passes(&c.hostname, ev.hostname.as_deref())
        && opt_passes(&c.status, de.get_static(StaticField::Status))
}

/// Replace `$(field)` in a description with the field's value.
fn describe(desc: &str, ev: &Event, de: &DecodedEvent) -> String {
    if !desc.contains("$(") {
        return desc.to_string();
    }
    let mut out = String::new();
    let mut rest = desc;
    while let Some(p) = rest.find("$(") {
        out.push_str(&rest[..p]);
        let after = &rest[p + 2..];
        match after.find(')') {
            Some(close) => {
                let name = &after[..close];
                let v = match name {
                    "hostname" => ev.hostname.clone(),
                    "program_name" => ev.program_name.clone(),
                    _ => de.find_field(name).map(str::to_string),
                };
                out.push_str(&v.unwrap_or_default());
                rest = &after[close + 1..];
            }
            None => {
                out.push_str("$(");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}
