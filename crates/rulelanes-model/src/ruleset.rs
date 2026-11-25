//! Compiled decoders and rules, and the trees they form.

use std::sync::Arc;

use crate::event::StaticField;
use crate::pattern::Expr;

/// Decoder `type`, which is also the rule category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum Category {
    #[default]
    Syslog,
    Firewall,
    Ids,
    WebLog,
    Squid,
    Windows,
    HostInformation,
    Ossec,
}

impl Category {
    pub fn parse(s: &str) -> Option<Category> {
        Some(match s {
            "syslog" => Category::Syslog,
            "firewall" => Category::Firewall,
            "ids" => Category::Ids,
            "web-log" => Category::WebLog,
            "squid" => Category::Squid,
            "windows" => Category::Windows,
            "host-information" => Category::HostInformation,
            "ossec" => Category::Ossec,
            _ => return None,
        })
    }
}

/// Where a decoder pattern starts reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Offset {
    /// The start of the message.
    #[default]
    None,
    AfterParent,
    AfterPrematch,
    AfterRegex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plugin {
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderField {
    Static(StaticField),
    Dynamic(String),
}

pub type DecoderId = usize;

#[derive(Debug, Clone)]
pub struct Decoder {
    /// The `name` attribute.
    pub own_name: String,
    /// The name reported in output: the parent's name unless
    /// `use_own_name` is set. Shared, so reporting it copies nothing.
    pub name: Arc<str>,
    pub parent: Option<Arc<str>>,
    pub file: String,
    pub program_name: Option<Expr>,
    pub prematch: Option<Expr>,
    pub prematch_offset: Offset,
    pub regex: Option<Expr>,
    pub regex_offset: Offset,
    pub order: Vec<OrderField>,
    pub plugin: Option<(Plugin, Offset)>,
    pub category: Category,
    pub use_own_name: bool,
    /// Set when a later sibling under the same parent has the same name:
    /// decoding goes on to that sibling's regex.
    pub get_next: bool,
}

/// One node in the rule tree. A rule can sit under several parents
/// (`if_group`, several `if_sid`), so nodes and rules are separate.
#[derive(Debug, Clone)]
pub struct RuleNode {
    pub rule: usize,
    pub children: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct Conditions {
    pub program_name: Option<Expr>,
    pub id: Option<Expr>,
    pub match_: Option<Expr>,
    pub regex: Option<Expr>,
    pub action: Option<Expr>,
    pub url: Option<Expr>,
    pub location: Option<Expr>,
    pub fields: Vec<(String, Expr)>,
    pub srcip: Option<Expr>,
    pub dstip: Option<Expr>,
    pub srcport: Option<Expr>,
    pub dstport: Option<Expr>,
    pub user: Option<Expr>,
    pub hostname: Option<Expr>,
    pub extra_data: Option<Expr>,
    pub status: Option<Expr>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u32,
    pub level: u8,
    pub noalert: bool,
    pub description: String,
    /// The enclosing `<group name>` followed by the rule's `<group>` text,
    /// concatenated as Wazuh does.
    pub groups_raw: String,
    /// `groups_raw` split as reported in output ([`Rule::split_groups`]).
    pub groups: Arc<[String]>,
    pub category: Category,
    pub decoded_as: Option<String>,
    pub if_sid: Vec<u32>,
    pub if_group: Option<String>,
    pub conds: Conditions,
    pub options: Vec<String>,
    pub file: String,
}

impl Rule {
    /// The groups of a `groups_raw` text, as reported in output.
    pub fn split_groups(groups_raw: &str) -> Arc<[String]> {
        groups_raw
            .split(',')
            .map(str::trim)
            .filter(|g| !g.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Children are kept sorted by this key, highest first; level 0 sorts
    /// above everything (Wazuh treats it as 99 while building the tree).
    pub fn sort_level(&self) -> u32 {
        if self.level == 0 {
            99
        } else {
            u32::from(self.level)
        }
    }
}

/// A loaded rule set: decoders, decoder trees, rules and the rule tree.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub decoders: Vec<Decoder>,
    /// Top-level decoders that declare `program_name`, in load order.
    pub top_with_program: Vec<DecoderId>,
    /// Top-level decoders without `program_name`, in load order.
    pub top_without_program: Vec<DecoderId>,
    /// Children of each decoder, in load order (indexed by decoder id).
    pub decoder_children: Vec<Vec<DecoderId>>,
    pub rules: Vec<Rule>,
    pub nodes: Vec<RuleNode>,
    /// Top-level rule nodes (rules with id below 10), sorted by level.
    pub roots: Vec<usize>,
}

impl RuleSet {
    pub fn rule_by_id(&self, id: u32) -> Option<usize> {
        self.rules.iter().position(|r| r.id == id)
    }

    /// Insert a new node for `rule` into a sibling list, before the first
    /// sibling with a lower sort level (stable for equal levels).
    pub fn insert_sorted(&mut self, siblings_of: Option<usize>, rule: usize) -> usize {
        let node = self.nodes.len();
        self.nodes.push(RuleNode {
            rule,
            children: Vec::new(),
        });
        let level = self.rules[rule].sort_level();
        let list: Vec<usize> = match siblings_of {
            Some(p) => self.nodes[p].children.clone(),
            None => self.roots.clone(),
        };
        let at = list
            .iter()
            .position(|&n| level > self.rules[self.nodes[n].rule].sort_level())
            .unwrap_or(list.len());
        match siblings_of {
            Some(p) => self.nodes[p].children.insert(at, node),
            None => self.roots.insert(at, node),
        }
        node
    }
}
