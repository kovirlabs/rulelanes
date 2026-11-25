//! Rule XML and the rule tree.

use crate::error::{ErrorKind, LoadError, LoadReport};
use crate::patterns::{self, Kind};
use crate::xml::{self, Node};
use rulelanes_model::pattern::{Expr, Pattern};
use rulelanes_model::ruleset::{Category, Conditions, Rule, RuleSet};
use std::collections::HashMap;

/// Rule elements that are valid in Wazuh 4.x but not supported in M1.
const KNOWN_UNSUPPORTED: &[&str] = &[
    "if_matched_sid",
    "if_matched_group",
    "if_matched_regex",
    "if_level",
    "if_fts",
    "same_source_ip",
    "same_srcip",
    "same_src_port",
    "same_srcport",
    "same_dst_port",
    "same_dstport",
    "same_location",
    "same_user",
    "same_srcuser",
    "same_dstuser",
    "same_id",
    "same_protocol",
    "same_action",
    "same_url",
    "same_data",
    "same_extra_data",
    "same_status",
    "same_system_name",
    "same_srcgeoip",
    "same_dstgeoip",
    "same_field",
    "different_srcip",
    "different_url",
    "different_srcgeoip",
    "different_field",
    "not_same_source_ip",
    "not_same_user",
    "not_same_agent",
    "not_same_id",
    "not_same_field",
    "global_frequency",
    "list",
    "check_diff",
    "check_if_ignored",
    "compiled_rule",
    "ignore",
    "time",
    "weekday",
    "srcgeoip",
    "dstgeoip",
    "system_name",
    "protocol",
    "data",
    "var",
];

/// Accepted and kept out of matching.
const META: &[&str] = &["mitre", "info", "cve"];

/// `options` values accepted in M1 (they only change what is logged).
const OPTIONS: &[&str] = &["no_full_log", "no_email_alert", "alert_by_email"];

struct Ctx<'a> {
    file: &'a str,
    item: String,
}

impl Ctx<'_> {
    fn err(
        &self,
        kind: ErrorKind,
        element: impl Into<String>,
        message: impl Into<String>,
    ) -> LoadError {
        LoadError {
            kind,
            file: self.file.to_string(),
            item: Some(self.item.clone()),
            element: Some(element.into()),
            message: message.into(),
        }
    }
}

pub fn load_text(
    set: &mut RuleSet,
    file: &str,
    text: &str,
    strict: bool,
    report: &mut LoadReport,
) -> Result<(), LoadError> {
    let file_err = |element: Option<String>, message: String| LoadError {
        kind: ErrorKind::Invalid,
        file: file.to_string(),
        item: None,
        element,
        message,
    };
    let roots = match xml::parse(text) {
        Ok(r) => r,
        Err(e) => {
            let err = file_err(None, format!("XML error at line {}: {}", e.line, e.message));
            report.file_errors.push(err.clone());
            return Err(err);
        }
    };
    let mut vars: HashMap<String, String> = HashMap::new();
    for root in &roots {
        match root.name.as_str() {
            "var" => {
                if let Some(n) = root.attr("name") {
                    vars.insert(n.to_string(), root.text.clone());
                }
            }
            "group" => {
                let Some(gname) = root.attr("name") else {
                    let err = file_err(Some("<group name>".into()), "missing name".into());
                    report.file_errors.push(err.clone());
                    if strict {
                        return Err(err);
                    }
                    continue;
                };
                for rule in &root.children {
                    if rule.name != "rule" {
                        let err = file_err(
                            Some(format!("<{}>", rule.name)),
                            "only <rule> is allowed inside <group>".into(),
                        );
                        report.file_errors.push(err.clone());
                        if strict {
                            return Err(err);
                        }
                        continue;
                    }
                    report.rules_total += 1;
                    match load_one(set, file, gname, rule, &vars) {
                        Ok(Added::Yes) => report.rules_loaded += 1,
                        Ok(Added::Warn(w)) => report.warnings.push(format!("{file}: {w}")),
                        Err(e) => {
                            report.item_errors.push(e.clone());
                            if strict {
                                return Err(e);
                            }
                        }
                    }
                }
            }
            other => {
                let err = file_err(
                    Some(format!("<{other}>")),
                    "only <group> and <var> are allowed at the top of a rule file".into(),
                );
                report.file_errors.push(err.clone());
                if strict {
                    return Err(err);
                }
            }
        }
    }
    Ok(())
}

enum Added {
    Yes,
    /// Skipped with a warning, as Wazuh skips it.
    Warn(String),
}

fn negate_attr(ctx: &Ctx, n: &Node) -> Result<bool, LoadError> {
    match n.attr("negate") {
        None => Ok(false),
        Some("yes") => Ok(true),
        Some("no") => Ok(false),
        Some(v) => Err(ctx.err(
            ErrorKind::Invalid,
            format!("<{} negate>", n.name),
            format!("negate must be yes or no, not '{v}'"),
        )),
    }
}

fn type_attr(ctx: &Ctx, n: &Node, default: Kind) -> Result<Kind, LoadError> {
    match n.attr("type") {
        None => Ok(default),
        Some(t) => Kind::parse(t).ok_or_else(|| {
            ctx.err(
                ErrorKind::Invalid,
                format!("<{} type>", n.name),
                format!("unknown pattern type '{t}'"),
            )
        }),
    }
}

/// Text accumulated for one single-valued element: Wazuh concatenates
/// repeated elements and keeps the attributes of the last one.
#[derive(Default)]
struct Acc {
    text: String,
    kind: Option<Kind>,
    negate: bool,
}

fn load_one(
    set: &mut RuleSet,
    file: &str,
    group_name: &str,
    node: &Node,
    vars: &HashMap<String, String>,
) -> Result<Added, LoadError> {
    let id_text = node.attr("id").unwrap_or("");
    let ctx = Ctx {
        file,
        item: format!("rule {id_text}"),
    };
    let id: u32 = id_text.parse().map_err(|_| {
        ctx.err(
            ErrorKind::Invalid,
            "rule@id",
            format!("bad rule id '{id_text}'"),
        )
    })?;
    let level_text = node.attr("level").unwrap_or("");
    let level: u8 = level_text
        .parse()
        .ok()
        .filter(|l| *l <= 16)
        .ok_or_else(|| {
            ctx.err(
                ErrorKind::Invalid,
                "rule@level",
                format!("bad level '{level_text}'"),
            )
        })?;
    let mut noalert = false;
    let mut overwrite = false;
    for (k, v) in &node.attrs {
        match k.as_str() {
            "id" | "level" => {}
            "noalert" => noalert = v != "0",
            "overwrite" => overwrite = v == "yes",
            "frequency" | "timeframe" | "ignore" | "maxsize" | "accuracy" => {
                return Err(ctx.err(
                    ErrorKind::Unsupported,
                    format!("rule@{k}"),
                    "not in the M1 subset (docs/syntax.md)",
                ));
            }
            _ => {
                return Err(ctx.err(
                    ErrorKind::Invalid,
                    format!("rule@{k}"),
                    "unknown rule attribute",
                ));
            }
        }
    }

    let mut description = String::new();
    let mut groups_raw = group_name.to_string();
    let mut category: Option<Category> = None;
    let mut decoded_as: Option<String> = None;
    let mut if_sid_text: Option<String> = None;
    let mut if_group: Option<String> = None;
    let mut options = Vec::new();
    let mut accs: HashMap<&'static str, Acc> = HashMap::new();
    let mut fields: Vec<(String, Expr)> = Vec::new();

    // Elements that hold a pattern, with their default pattern type.
    const PATTERNED: &[(&str, Kind)] = &[
        ("match", Kind::OsMatch),
        ("regex", Kind::OsRegex),
        ("program_name", Kind::OsMatch),
        ("id", Kind::OsMatch),
        ("action", Kind::Exact),
        ("url", Kind::OsMatch),
        ("location", Kind::OsMatch),
        ("srcport", Kind::OsMatch),
        ("dstport", Kind::OsMatch),
        ("user", Kind::OsMatch),
        ("hostname", Kind::OsMatch),
        ("extra_data", Kind::OsMatch),
        ("status", Kind::OsMatch),
        ("srcip", Kind::Exact),
        ("dstip", Kind::Exact),
    ];

    for el in &node.children {
        let text = xml::apply_vars(&el.text, vars);
        let name = el.name.as_str();
        if let Some(&(key, default)) = PATTERNED.iter().find(|(k, _)| *k == name) {
            let kind = if key == "srcip" || key == "dstip" {
                default
            } else {
                type_attr(&ctx, el, default)?
            };
            let negate = negate_attr(&ctx, el)?;
            let acc = accs.entry(key).or_default();
            acc.text.push_str(&text);
            acc.kind = Some(kind);
            acc.negate = negate;
            continue;
        }
        match name {
            "description" => description.push_str(&text),
            "group" => groups_raw.push_str(&text),
            "category" => {
                category = Some(Category::parse(text.trim()).ok_or_else(|| {
                    ctx.err(
                        ErrorKind::Invalid,
                        "<category>",
                        format!("invalid category '{text}'"),
                    )
                })?);
            }
            "decoded_as" => decoded_as = Some(text),
            "if_sid" => if_sid_text.get_or_insert_with(String::new).push_str(&text),
            "if_group" => if_group.get_or_insert_with(String::new).push_str(&text),
            "options" => {
                for o in text.split(',').map(str::trim).filter(|o| !o.is_empty()) {
                    if OPTIONS.contains(&o) {
                        options.push(o.to_string());
                    } else {
                        return Err(ctx.err(
                            ErrorKind::Unsupported,
                            format!("<options>{o}"),
                            "option not in the M1 subset",
                        ));
                    }
                }
            }
            "field" => {
                let fname = el.attr("name").unwrap_or("").to_string();
                if fname.is_empty() {
                    return Err(ctx.err(ErrorKind::Invalid, "<field name>", "missing name"));
                }
                // Wazuh refuses static field names here (checked against
                // wazuh-logtest 4.14.10: "Field 'protocol' is static").
                const STATIC: &[&str] = &[
                    "srcip",
                    "dstip",
                    "srcgeoip",
                    "dstgeoip",
                    "srcport",
                    "dstport",
                    "user",
                    "srcuser",
                    "dstuser",
                    "url",
                    "id",
                    "data",
                    "extra_data",
                    "status",
                    "protocol",
                    "system_name",
                    "action",
                ];
                if STATIC.iter().any(|s| s.eq_ignore_ascii_case(&fname)) {
                    return Err(ctx.err(
                        ErrorKind::Invalid,
                        format!("<field name=\"{fname}\">"),
                        "a static field cannot be used in <field>",
                    ));
                }
                let kind = type_attr(&ctx, el, Kind::OsRegex)?;
                let negate = negate_attr(&ctx, el)?;
                let pattern = patterns::compile(kind, &text).map_err(|m| {
                    ctx.err(
                        pattern_error_kind(kind, &m),
                        "<field>",
                        format!("pattern '{text}': {m}"),
                    )
                })?;
                fields.push((fname, Expr { pattern, negate }));
            }
            m if META.contains(&m) => {}
            u if KNOWN_UNSUPPORTED.contains(&u) => {
                return Err(ctx.err(
                    ErrorKind::Unsupported,
                    format!("<{u}>"),
                    "not in the M1 subset (docs/syntax.md)",
                ));
            }
            other => {
                return Err(ctx.err(
                    ErrorKind::Invalid,
                    format!("<{other}>"),
                    "not a Wazuh rule element",
                ));
            }
        }
    }

    let mut conds = Conditions {
        fields,
        ..Conditions::default()
    };
    for (key, acc) in accs {
        let kind = acc.kind.unwrap_or(Kind::OsMatch);
        let pattern = if key == "srcip" || key == "dstip" {
            Pattern::IpList(
                patterns::ip_list(&acc.text)
                    .map_err(|m| ctx.err(ErrorKind::Unsupported, format!("<{key}>"), m))?,
            )
        } else {
            patterns::compile(kind, &acc.text).map_err(|m| {
                ctx.err(
                    pattern_error_kind(kind, &m),
                    format!("<{key}>"),
                    format!("pattern '{}': {m}", acc.text),
                )
            })?
        };
        let e = Some(Expr {
            pattern,
            negate: acc.negate,
        });
        match key {
            "match" => conds.match_ = e,
            "regex" => conds.regex = e,
            "program_name" => conds.program_name = e,
            "id" => conds.id = e,
            "action" => conds.action = e,
            "url" => conds.url = e,
            "location" => conds.location = e,
            "srcport" => conds.srcport = e,
            "dstport" => conds.dstport = e,
            "user" => conds.user = e,
            "hostname" => conds.hostname = e,
            "extra_data" => conds.extra_data = e,
            "status" => conds.status = e,
            "srcip" => conds.srcip = e,
            "dstip" => conds.dstip = e,
            _ => unreachable!("every PATTERNED key is handled"),
        }
    }

    let mut if_sid = Vec::new();
    if let Some(t) = &if_sid_text {
        for part in t.split([',', ' ']).filter(|p| !p.is_empty()) {
            if_sid.push(part.trim().parse::<u32>().map_err(|_| {
                ctx.err(
                    ErrorKind::Invalid,
                    "<if_sid>",
                    format!("'{part}' is not a rule id"),
                )
            })?);
        }
    }
    if let Some(d) = &decoded_as
        && !set.decoders.iter().any(|x| &x.own_name == d)
    {
        return Err(ctx.err(
            ErrorKind::Invalid,
            "<decoded_as>",
            format!("no decoder named '{d}'"),
        ));
    }

    let rule = Rule {
        id,
        level,
        noalert,
        description,
        groups: Rule::split_groups(&groups_raw),
        groups_raw,
        category: category.unwrap_or_default(),
        decoded_as,
        if_sid,
        if_group,
        conds,
        options,
        file: file.to_string(),
    };

    // Duplicate ids and overwrite.
    if let Some(existing) = set.rule_by_id(id) {
        if overwrite {
            let keep_category = set.rules[existing].category;
            set.rules[existing] = Rule {
                category: keep_category,
                ..rule
            };
            return Ok(Added::Yes);
        }
        return Ok(Added::Warn(format!(
            "rule {id}: duplicate id without overwrite=\"yes\"; skipped"
        )));
    }

    add_to_tree(set, rule)
}

fn pattern_error_kind(kind: Kind, message: &str) -> ErrorKind {
    if kind == Kind::Pcre2 || message.contains("not supported") {
        ErrorKind::Unsupported
    } else {
        ErrorKind::Invalid
    }
}

/// Place a new rule in the tree the way Wazuh 4.x does.
fn add_to_tree(set: &mut RuleSet, mut rule: Rule) -> Result<Added, LoadError> {
    let id = rule.id;
    if id < 10 {
        set.rules.push(rule);
        let r = set.rules.len() - 1;
        set.insert_sorted(None, r);
        return Ok(Added::Yes);
    }
    if !rule.if_sid.is_empty() {
        let sids = rule.if_sid.clone();
        // Category comes from the parent; take it from the first parent found.
        let mut targets: Vec<Vec<usize>> = Vec::new();
        for &sid in &sids {
            let mut found = Vec::new();
            let roots = set.roots.clone();
            find_sid(set, &roots, sid, &mut found);
            targets.push(found);
        }
        if targets.iter().all(|t| t.is_empty()) {
            return Ok(Added::Warn(format!(
                "rule {id}: no rule matches if_sid {sids:?}; skipped"
            )));
        }
        if let Some(&first) = targets.iter().flatten().next() {
            rule.category = set.rules[set.nodes[first].rule].category;
        }
        set.rules.push(rule);
        let r = set.rules.len() - 1;
        for node in targets.into_iter().flatten() {
            set.insert_sorted(Some(node), r);
        }
        return Ok(Added::Yes);
    }
    if let Some(group) = rule.if_group.clone() {
        set.rules.push(rule);
        let r = set.rules.len() - 1;
        let roots = set.roots.clone();
        let added = add_under_group(set, &roots, &group, id, r);
        if !added {
            set.rules.pop();
            return Ok(Added::Warn(format!(
                "rule {id}: no rule has group '{group}'; skipped"
            )));
        }
        return Ok(Added::Yes);
    }
    // No parent given: child of the first top-level rule of its category.
    let cat = rule.category;
    let Some(&root) = set
        .roots
        .iter()
        .find(|&&n| set.rules[set.nodes[n].rule].category == cat)
    else {
        return Ok(Added::Warn(format!(
            "rule {id}: no top-level rule with its category; skipped"
        )));
    };
    set.rules.push(rule);
    let r = set.rules.len() - 1;
    set.insert_sorted(Some(root), r);
    Ok(Added::Yes)
}

/// Every node for rule `sid`, searching siblings in order and descending
/// into children of nodes that are not `sid` itself.
fn find_sid(set: &RuleSet, list: &[usize], sid: u32, out: &mut Vec<usize>) {
    for &n in list {
        if set.rules[set.nodes[n].rule].id == sid {
            out.push(n);
            return;
        }
        let children = set.nodes[n].children.clone();
        find_sid(set, &children, sid, out);
    }
}

fn group_matches(group: &str, groups_raw: &str) -> bool {
    groups_raw
        .split(',')
        .any(|g| g.trim().eq_ignore_ascii_case(group.trim()))
}

fn add_under_group(set: &mut RuleSet, list: &[usize], group: &str, id: u32, r: usize) -> bool {
    let mut added = false;
    for &n in list {
        let rule = &set.rules[set.nodes[n].rule];
        if group_matches(group, &rule.groups_raw) && rule.id != id {
            set.insert_sorted(Some(n), r);
            added = true;
        }
        let children = set.nodes[n].children.clone();
        if !children.is_empty() && add_under_group(set, &children, group, id, r) {
            added = true;
        }
    }
    added
}
