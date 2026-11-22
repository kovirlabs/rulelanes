//! Compiled patterns: Wazuh's `osmatch` and `osregex` languages, PCRE2-style
//! regexes, exact strings and IP lists.
//!
//! `osmatch` and `osregex` are implemented here from their documented and
//! observed behaviour (see `docs/syntax.md` and the M1 status file): both are
//! ASCII case-insensitive for literal characters; `osregex` quantifiers are
//! lazy except when nothing that consumes input follows them in the
//! alternative, in which case they are greedy. Parsing pattern text into
//! these types is done by `rulelanes-syntax`.

use std::net::Ipv4Addr;

/// Result of a successful match: the exclusive end of the match and the
/// byte ranges of the capture groups, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchResult {
    pub start: usize,
    pub end: usize,
    pub captures: Vec<(usize, usize)>,
}

/// A pattern with its `negate` flag.
#[derive(Debug, Clone)]
pub struct Expr {
    pub pattern: Pattern,
    pub negate: bool,
}

impl Expr {
    /// True when the expression passes for `s`, taking `negate` into account.
    pub fn passes(&self, s: &str) -> bool {
        self.pattern.is_match(s) != self.negate
    }
}

#[derive(Debug, Clone)]
pub enum Pattern {
    OsMatch(OsMatch),
    OsRegex(OsRegex),
    Pcre2(Pcre2),
    /// Byte-exact, case-sensitive equality (the default for rule `action`).
    Exact(String),
    /// IPv4 addresses and networks (rule `srcip` and `dstip`).
    IpList(IpList),
}

impl Pattern {
    pub fn is_match(&self, s: &str) -> bool {
        match self {
            Pattern::OsMatch(m) => m.is_match(s),
            Pattern::OsRegex(r) => r.exec(s).is_some(),
            Pattern::Pcre2(p) => p.exec(s).is_some(),
            Pattern::Exact(e) => e == s,
            Pattern::IpList(l) => l.contains(s),
        }
    }

    /// Match and return the end and the captures. `osmatch`, exact and IP
    /// patterns have no captures; their end is the end of the input.
    pub fn exec(&self, s: &str) -> Option<MatchResult> {
        match self {
            Pattern::OsRegex(r) => r.exec(s),
            Pattern::Pcre2(p) => p.exec(s),
            other => other.is_match(s).then(|| MatchResult {
                start: 0,
                end: s.len(),
                captures: Vec::new(),
            }),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Pattern::OsMatch(_) => "osmatch",
            Pattern::OsRegex(_) => "osregex",
            Pattern::Pcre2(_) => "pcre2",
            Pattern::Exact(_) => "string",
            Pattern::IpList(_) => "ip",
        }
    }
}

// ---------------------------------------------------------------- osmatch

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchAnchor {
    /// Anywhere in the input.
    Anywhere,
    /// `^text`
    Prefix,
    /// `text$`
    Suffix,
    /// `^text$`
    Whole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchAlt {
    pub anchor: MatchAnchor,
    /// Lower-cased ASCII bytes.
    pub text: Vec<u8>,
}

/// `osmatch`: alternatives separated by `|`, each a literal with optional
/// `^` and `$`, case-insensitive; a leading `!` negates the whole pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsMatch {
    pub negated: bool,
    pub alts: Vec<MatchAlt>,
}

impl OsMatch {
    pub fn is_match(&self, s: &str) -> bool {
        let hay: Vec<u8> = s.bytes().map(|b| b.to_ascii_lowercase()).collect();
        let hit = self.alts.iter().any(|alt| {
            let t = &alt.text[..];
            match alt.anchor {
                MatchAnchor::Whole => hay == t,
                MatchAnchor::Prefix => hay.starts_with(t),
                MatchAnchor::Suffix => hay.ends_with(t),
                MatchAnchor::Anywhere => t.is_empty() || hay.windows(t.len()).any(|w| w == t),
            }
        });
        hit != self.negated
    }
}

// ---------------------------------------------------------------- osregex

/// Character classes of `osregex`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassKind {
    /// `\d`: 0-9
    Digit,
    /// `\w`: A-Z a-z 0-9 `-` `@` `_`
    Word,
    /// `\s`: the space character only
    Space,
    /// `\p`: punctuation ``! " # $ % & ' ( ) * + , - . : ; < = > ? [ ] { | }``
    Punct,
    /// `\D`
    NotDigit,
    /// `\W`
    NotWord,
    /// `\S`
    NotSpace,
    /// `\.`: any character
    Any,
    /// `\t`: tab
    Tab,
}

impl ClassKind {
    pub fn matches(self, b: u8) -> bool {
        let word = b.is_ascii_alphanumeric() || b == b'-' || b == b'@' || b == b'_';
        match self {
            ClassKind::Digit => b.is_ascii_digit(),
            ClassKind::Word => word,
            ClassKind::Space => b == b' ',
            ClassKind::Punct => matches!(b, 33..=46 | 58..=63 | 91 | 93 | 123..=125),
            ClassKind::NotDigit => !b.is_ascii_digit(),
            ClassKind::NotWord => !word,
            ClassKind::NotSpace => b != b' ',
            ClassKind::Any => true,
            ClassKind::Tab => b == b'\t',
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quant {
    One,
    /// `+`
    Plus,
    /// `*`
    Star,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// A literal byte, lower-cased; compared case-insensitively.
    Lit(u8),
    Class(ClassKind, Quant),
    Open(usize),
    Close(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegexAlt {
    pub begin: bool,
    pub end: bool,
    pub toks: Vec<Tok>,
    pub groups: usize,
}

/// `osregex`: alternatives separated by top-level `|`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsRegex {
    pub alts: Vec<RegexAlt>,
}

impl OsRegex {
    /// First alternative that matches wins; within it, the leftmost start.
    pub fn exec(&self, s: &str) -> Option<MatchResult> {
        let b = s.as_bytes();
        self.alts.iter().find_map(|alt| alt.exec(b))
    }
}

impl RegexAlt {
    fn exec(&self, s: &[u8]) -> Option<MatchResult> {
        let last_start = if self.begin { 0 } else { s.len() };
        let mut caps = vec![(0usize, 0usize); self.groups];
        for start in 0..=last_start {
            if let Some(end) = self.step(s, 0, start, &mut caps) {
                return Some(MatchResult {
                    start,
                    end,
                    captures: caps,
                });
            }
        }
        None
    }

    /// True when no token at or after `ti` consumes input.
    fn trailing(&self, ti: usize) -> bool {
        self.toks[ti..]
            .iter()
            .all(|t| matches!(t, Tok::Open(_) | Tok::Close(_)))
    }

    fn step(&self, s: &[u8], ti: usize, pos: usize, caps: &mut [(usize, usize)]) -> Option<usize> {
        let Some(tok) = self.toks.get(ti) else {
            return (!self.end || pos == s.len()).then_some(pos);
        };
        match *tok {
            Tok::Open(g) => {
                caps[g].0 = pos;
                self.step(s, ti + 1, pos, caps)
            }
            Tok::Close(g) => {
                caps[g].1 = pos;
                self.step(s, ti + 1, pos, caps)
            }
            Tok::Lit(c) => {
                if pos < s.len() && s[pos].to_ascii_lowercase() == c {
                    self.step(s, ti + 1, pos + 1, caps)
                } else {
                    None
                }
            }
            Tok::Class(k, Quant::One) => {
                if pos < s.len() && k.matches(s[pos]) {
                    self.step(s, ti + 1, pos + 1, caps)
                } else {
                    None
                }
            }
            Tok::Class(k, q) => {
                let min = if q == Quant::Plus { 1 } else { 0 };
                let run = s[pos..].iter().take_while(|&&b| k.matches(b)).count();
                if run < min {
                    return None;
                }
                if self.trailing(ti + 1) {
                    // Greedy: nothing after this consumes input.
                    (min..=run)
                        .rev()
                        .find_map(|n| self.step(s, ti + 1, pos + n, caps))
                } else {
                    // Lazy: give the rest of the pattern the earliest chance.
                    (min..=run).find_map(|n| self.step(s, ti + 1, pos + n, caps))
                }
            }
        }
    }
}

// ---------------------------------------------------------------- pcre2

/// A PCRE2-style pattern, run by `fancy-regex` (backtracking, supports
/// look-around and backreferences). Case-sensitive unless the pattern says
/// otherwise, as in PCRE2.
#[derive(Debug, Clone)]
pub struct Pcre2 {
    pub source: String,
    pub regex: fancy_regex::Regex,
}

impl Pcre2 {
    pub fn exec(&self, s: &str) -> Option<MatchResult> {
        let caps = self.regex.captures(s).ok().flatten()?;
        let whole = caps.get(0)?;
        // Wazuh returns groups up to the highest one that took part.
        let highest = (1..caps.len())
            .rev()
            .find(|&i| caps.get(i).is_some())
            .unwrap_or(0);
        let captures = (1..=highest)
            .map(|i| caps.get(i).map_or((0, 0), |m| (m.start(), m.end())))
            .collect();
        Some(MatchResult {
            start: whole.start(),
            end: whole.end(),
            captures,
        })
    }
}

// ---------------------------------------------------------------- IP lists

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpNet {
    pub addr: u32,
    pub prefix: u8,
    pub negated: bool,
}

/// A list of IPv4 addresses or networks; matches when any entry contains
/// the address (or, for a `!` entry, does not).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpList {
    pub nets: Vec<IpNet>,
}

impl IpList {
    pub fn contains(&self, s: &str) -> bool {
        let Ok(ip) = s.trim().parse::<Ipv4Addr>() else {
            return false;
        };
        let ip = u32::from(ip);
        self.nets.iter().any(|n| {
            let mask = if n.prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(n.prefix))
            };
            ((ip & mask) == (n.addr & mask)) != n.negated
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alt(begin: bool, end: bool, toks: Vec<Tok>, groups: usize) -> OsRegex {
        OsRegex {
            alts: vec![RegexAlt {
                begin,
                end,
                toks,
                groups,
            }],
        }
    }

    #[test]
    fn lazy_then_greedy_tail() {
        // (\d+)(\d+) on "123" -> "1", "23"
        use Tok::*;
        let r = alt(
            false,
            false,
            vec![
                Open(0),
                Class(ClassKind::Digit, Quant::Plus),
                Close(0),
                Open(1),
                Class(ClassKind::Digit, Quant::Plus),
                Close(1),
            ],
            2,
        );
        let m = r.exec("123").unwrap();
        assert_eq!(m.captures, vec![(0, 1), (1, 3)]);
    }

    #[test]
    fn osmatch_anchors() {
        let m = OsMatch {
            negated: false,
            alts: vec![MatchAlt {
                anchor: MatchAnchor::Prefix,
                text: b"ab".to_vec(),
            }],
        };
        assert!(m.is_match("ABc"));
        assert!(!m.is_match("cab"));
    }
}
