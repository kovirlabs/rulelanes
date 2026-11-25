//! Decoder XML.

use crate::error::{ErrorKind, LoadError, LoadReport};
use crate::patterns::{self, Kind};
use crate::xml::{self, Node};
use rulelanes_model::event::StaticField;
use rulelanes_model::pattern::Expr;
use rulelanes_model::ruleset::{Category, Decoder, Offset, OrderField, Plugin, RuleSet};
use std::collections::HashMap;

/// Valid Wazuh decoder elements that M1 does not support.
const UNSUPPORTED: &[&str] = &[
    "fts",
    "ftscomment",
    "accumulate",
    "json_null_field",
    "json_array_structure",
];

struct Ctx<'a> {
    file: &'a str,
    item: String,
}

impl Ctx<'_> {
    fn err(
        &self,
        kind: ErrorKind,
        element: Option<String>,
        message: impl Into<String>,
    ) -> LoadError {
        LoadError {
            kind,
            file: self.file.to_string(),
            item: Some(self.item.clone()),
            element,
            message: message.into(),
        }
    }
}

/// Load the decoders in one file into `set`. With `strict`, the first error
/// is returned; otherwise failing decoders are skipped and recorded.
pub fn load_text(
    set: &mut RuleSet,
    file: &str,
    text: &str,
    strict: bool,
    report: &mut LoadReport,
) -> Result<(), LoadError> {
    let roots = match xml::parse(text) {
        Ok(r) => r,
        Err(e) => {
            let err = LoadError {
                kind: ErrorKind::Invalid,
                file: file.to_string(),
                item: None,
                element: None,
                message: format!("XML error at line {}: {}", e.line, e.message),
            };
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
            "decoder" => {
                report.decoders_total += 1;
                match load_one(set, file, root, &vars) {
                    Ok(()) => report.decoders_loaded += 1,
                    Err(e) => {
                        report.item_errors.push(e.clone());
                        if strict {
                            return Err(e);
                        }
                    }
                }
            }
            other => {
                let err = LoadError {
                    kind: ErrorKind::Invalid,
                    file: file.to_string(),
                    item: None,
                    element: Some(format!("<{other}>")),
                    message: "only <decoder> and <var> are allowed at the top of a decoder file"
                        .into(),
                };
                report.file_errors.push(err.clone());
                if strict {
                    return Err(err);
                }
            }
        }
    }
    Ok(())
}

fn offset_attr(ctx: &Ctx, n: &Node) -> Result<Offset, LoadError> {
    match n.attr("offset") {
        None => Ok(Offset::None),
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "after_parent" => Ok(Offset::AfterParent),
            "after_prematch" => Ok(Offset::AfterPrematch),
            "after_regex" => Ok(Offset::AfterRegex),
            _ => Err(ctx.err(
                ErrorKind::Invalid,
                Some(format!("<{} offset>", n.name)),
                format!("unknown offset '{v}'"),
            )),
        },
    }
}

fn load_one(
    set: &mut RuleSet,
    file: &str,
    node: &Node,
    vars: &HashMap<String, String>,
) -> Result<(), LoadError> {
    let name = node.attr("name").unwrap_or("").to_string();
    let ctx = Ctx {
        file,
        item: format!("decoder '{name}'"),
    };
    if name.is_empty() {
        return Err(ctx.err(
            ErrorKind::Invalid,
            Some("<decoder name>".into()),
            "missing name",
        ));
    }
    for (k, _) in &node.attrs {
        if k != "name" {
            return Err(ctx.err(
                ErrorKind::Invalid,
                Some(format!("<decoder {k}>")),
                "only the name attribute is allowed",
            ));
        }
    }
    let mut parent: Option<String> = None;
    let mut program_name: Option<(String, Kind)> = None;
    let mut prematch: Option<(String, Kind)> = None;
    let mut prematch_offset = Offset::None;
    let mut regex: Option<(String, Kind)> = None;
    let mut regex_offset = Offset::None;
    let mut order: Option<Vec<OrderField>> = None;
    let mut plugin: Option<(Plugin, Offset)> = None;
    let mut category = Category::Syslog;
    let mut use_own_name = false;

    let type_attr = |n: &Node, default: Kind, allowed: &[Kind]| -> Result<Kind, LoadError> {
        let Some(t) = n.attr("type") else {
            return Ok(default);
        };
        match Kind::parse(t) {
            Some(k) if allowed.contains(&k) => Ok(k),
            // Wazuh warns and falls back to the default for a known type
            // that the element does not take.
            Some(_) => Ok(default),
            None => Err(ctx.err(
                ErrorKind::Invalid,
                Some(format!("<{} type>", n.name)),
                format!("unknown pattern type '{t}'"),
            )),
        }
    };

    for el in &node.children {
        let text = xml::apply_vars(&el.text, vars);
        let elname = el.name.as_str();
        match elname {
            "parent" => parent = Some(text),
            "program_name" => {
                let k = type_attr(
                    el,
                    Kind::OsMatch,
                    &[Kind::OsMatch, Kind::OsRegex, Kind::Pcre2],
                )?;
                let prev = program_name.map(|p| p.0).unwrap_or_default();
                program_name = Some((prev + &text, k));
            }
            "prematch" => {
                let k = type_attr(el, Kind::OsRegex, &[Kind::OsRegex, Kind::Pcre2])?;
                let off = offset_attr(&ctx, el)?;
                if off != Offset::None {
                    if prematch.is_some() {
                        return Err(ctx.err(
                            ErrorKind::Invalid,
                            Some("<prematch offset>".into()),
                            "only the first prematch may have an offset",
                        ));
                    }
                    prematch_offset = off;
                }
                let prev = prematch.map(|p| p.0).unwrap_or_default();
                prematch = Some((prev + &text, k));
            }
            "regex" => {
                let k = type_attr(el, Kind::OsRegex, &[Kind::OsRegex, Kind::Pcre2])?;
                let off = offset_attr(&ctx, el)?;
                if off != Offset::None && regex.is_none() {
                    regex_offset = off;
                }
                let prev = regex.map(|p| p.0).unwrap_or_default();
                regex = Some((prev + &text, k));
            }
            "order" => {
                let mut fields = Vec::new();
                for w in text.split(',') {
                    let w = w.trim_start_matches(' ');
                    let w = w.split(' ').next().unwrap_or("");
                    if w.is_empty() {
                        return Err(ctx.err(
                            ErrorKind::Invalid,
                            Some("<order>".into()),
                            format!("empty field name in '{text}'"),
                        ));
                    }
                    fields.push(match StaticField::from_order_name(w) {
                        Some(f) => OrderField::Static(f),
                        None => OrderField::Dynamic(w.to_string()),
                    });
                }
                order = Some(fields);
            }
            "type" => {
                category = Category::parse(text.trim()).ok_or_else(|| {
                    ctx.err(
                        ErrorKind::Invalid,
                        Some("<type>".into()),
                        format!("invalid decoder type '{text}'"),
                    )
                })?;
            }
            "use_own_name" => use_own_name = text == "true",
            "plugin_decoder" => {
                let off = offset_attr(&ctx, el)?;
                match text.trim() {
                    "JSON_Decoder" => plugin = Some((Plugin::Json, off)),
                    "PF_Decoder" | "SymantecWS_Decoder" | "SonicWall_Decoder"
                    | "OSSECAlert_Decoder" => {
                        return Err(ctx.err(
                            ErrorKind::Unsupported,
                            Some(format!("<plugin_decoder>{}", text.trim())),
                            "only JSON_Decoder is supported in M1",
                        ));
                    }
                    other => {
                        return Err(ctx.err(
                            ErrorKind::Invalid,
                            Some("<plugin_decoder>".into()),
                            format!("unknown plugin '{other}'"),
                        ));
                    }
                }
            }
            e if UNSUPPORTED.contains(&e) => {
                return Err(ctx.err(
                    ErrorKind::Unsupported,
                    Some(format!("<{e}>")),
                    "not in the M1 subset (docs/syntax.md)",
                ));
            }
            e => {
                return Err(ctx.err(
                    ErrorKind::Invalid,
                    Some(format!("<{e}>")),
                    "not a Wazuh decoder element",
                ));
            }
        }
    }

    // Validation, as Wazuh's loader does it.
    let inv = |el: &str, m: &str| ctx.err(ErrorKind::Invalid, Some(el.to_string()), m.to_string());
    if prematch.is_none() && parent.is_none() && program_name.is_none() {
        return Err(inv(
            "<prematch>",
            "a decoder needs prematch, program_name or parent",
        ));
    }
    if regex.is_some() != order.is_some() {
        return Err(inv("<regex>", "regex and order must be used together"));
    }
    match regex_offset {
        Offset::AfterParent if parent.is_none() => {
            return Err(inv("<regex offset>", "after_parent needs a parent"));
        }
        Offset::AfterPrematch if parent.is_none() => regex_offset = Offset::AfterParent,
        Offset::AfterPrematch if prematch.is_none() => {
            return Err(inv("<regex offset>", "after_prematch needs a prematch"));
        }
        Offset::AfterRegex if parent.is_none() || regex.is_none() => {
            return Err(inv(
                "<regex offset>",
                "after_regex needs a parent and a regex",
            ));
        }
        _ => {}
    }
    match prematch_offset {
        Offset::None => {}
        Offset::AfterParent if parent.is_some() => {}
        _ => {
            return Err(inv(
                "<prematch offset>",
                "prematch takes only after_parent, with a parent",
            ));
        }
    }
    if let Some((_, off)) = plugin {
        if off == Offset::AfterParent && parent.is_none() {
            return Err(inv(
                "<plugin_decoder offset>",
                "after_parent needs a parent",
            ));
        }
        if off == Offset::AfterPrematch && prematch.is_none() {
            return Err(inv(
                "<plugin_decoder offset>",
                "after_prematch needs a prematch",
            ));
        }
        if regex.is_some() || order.is_some() {
            return Err(inv(
                "<plugin_decoder>",
                "a plugin decoder cannot have regex or order",
            ));
        }
    }

    let compile = |el: &str, p: Option<(String, Kind)>| -> Result<Option<Expr>, LoadError> {
        p.map(|(text, k)| {
            patterns::compile(k, &text)
                .map(|pattern| Expr {
                    pattern,
                    negate: false,
                })
                .map_err(|m| {
                    let kind = if k == Kind::Pcre2 || m.contains("not supported") {
                        ErrorKind::Unsupported
                    } else {
                        ErrorKind::Invalid
                    };
                    ctx.err(
                        kind,
                        Some(format!("<{el}>")),
                        format!("pattern '{text}': {m}"),
                    )
                })
        })
        .transpose()
    };
    let program_name = compile("program_name", program_name)?;
    let prematch_has = prematch.is_some();
    let prematch = compile("prematch", prematch)?;
    let regex = compile("regex", regex)?;

    let decoder = Decoder {
        own_name: name.clone(),
        name: name.as_str().into(),
        parent: parent.as_deref().map(Into::into),
        file: file.to_string(),
        program_name,
        prematch,
        prematch_offset,
        regex,
        regex_offset,
        order: order.unwrap_or_default(),
        plugin,
        category,
        use_own_name,
        get_next: false,
    };

    match parent {
        None => {
            let id = push(set, decoder);
            if set.decoders[id].program_name.is_some() {
                set.top_with_program.push(id);
            } else {
                set.top_without_program.push(id);
            }
        }
        Some(pname) => {
            let parents: Vec<usize> = set
                .top_with_program
                .iter()
                .chain(set.top_without_program.iter())
                .copied()
                .filter(|&p| set.decoders[p].own_name == pname)
                .collect();
            if parents.is_empty() {
                return Err(inv(
                    "<parent>",
                    &format!("parent decoder '{pname}' not found"),
                ));
            }
            // Sibling rules for same-named children (multi-regex decoders).
            let mut same_name_with_pattern = false;
            let mut same_name_siblings = Vec::new();
            for &p in &parents {
                for &c in &set.decoder_children[p] {
                    if set.decoders[c].own_name == name {
                        let d = &set.decoders[c];
                        if d.prematch.is_some() || d.regex.is_some() {
                            same_name_with_pattern = true;
                        }
                        same_name_siblings.push(c);
                    }
                }
            }
            if !same_name_siblings.is_empty() {
                if prematch_has {
                    return Err(inv(
                        "<prematch>",
                        "a decoder sharing its name with a sibling cannot have a prematch",
                    ));
                }
                let new_has = decoder.regex.is_some() || decoder.plugin.is_some();
                for &c in &same_name_siblings {
                    let d = &set.decoders[c];
                    if !(new_has && (d.regex.is_some() || d.plugin.is_some())) {
                        return Err(inv("<decoder name>", "duplicate decoder name"));
                    }
                }
            }
            if decoder.regex_offset == Offset::AfterRegex && !same_name_with_pattern {
                return Err(inv(
                    "<regex offset>",
                    "after_regex needs an earlier sibling with the same name",
                ));
            }
            for &c in &same_name_siblings {
                set.decoders[c].get_next = true;
            }
            let mut decoder = decoder;
            if !decoder.use_own_name {
                decoder.name = pname.as_str().into();
            }
            let id = push(set, decoder);
            for p in parents {
                set.decoder_children[p].push(id);
            }
        }
    }
    Ok(())
}

fn push(set: &mut RuleSet, d: Decoder) -> usize {
    set.decoders.push(d);
    set.decoder_children.push(Vec::new());
    set.decoders.len() - 1
}
