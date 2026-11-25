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
            Pattern::OsRegex(r) => r.is_match(s),
            Pattern::Pcre2(p) => p.is_match(s),
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

    /// Like [`Pattern::exec`], but writes the captures into `caps`
    /// (cleared first) and returns `(start, end)`. Once `caps` has grown to
    /// the largest group count it is reused without allocating; `osregex`,
    /// `osmatch`, exact and IP patterns then allocate nothing (R8).
    pub fn exec_into(&self, s: &str, caps: &mut Vec<(usize, usize)>) -> Option<(usize, usize)> {
        caps.clear();
        match self {
            Pattern::OsRegex(r) => r.exec_into(s, caps),
            Pattern::Pcre2(p) => p.exec_into(s, caps),
            other => other.is_match(s).then_some((0, s.len())),
        }
    }

    /// Where the first match ends, without captures: what `prematch`
    /// needs. Allocates nothing for `osregex` (stack buffer), `osmatch`,
    /// exact and IP patterns, nor for PCRE2 patterns without look-around
    /// or backreferences once the regex's cache has warmed up.
    pub fn find_end(&self, s: &str) -> Option<usize> {
        match self {
            Pattern::OsRegex(r) => r.find_end(s),
            Pattern::Pcre2(p) => p.find_end(s),
            other => other.is_match(s).then_some(s.len()),
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
    /// Compares ASCII case-insensitively in place; allocates nothing.
    pub fn is_match(&self, s: &str) -> bool {
        let hay = s.as_bytes();
        // `t` is already lower-cased.
        let eq = |h: &[u8], t: &[u8]| h.iter().zip(t).all(|(a, b)| a.to_ascii_lowercase() == *b);
        let hit = self.alts.iter().any(|alt| {
            let t = &alt.text[..];
            match alt.anchor {
                MatchAnchor::Whole => hay.len() == t.len() && eq(hay, t),
                MatchAnchor::Prefix => hay.len() >= t.len() && eq(&hay[..t.len()], t),
                MatchAnchor::Suffix => hay.len() >= t.len() && eq(&hay[hay.len() - t.len()..], t),
                MatchAnchor::Anywhere => t.is_empty() || hay.windows(t.len()).any(|w| eq(w, t)),
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
        let mut captures = Vec::new();
        let (start, end) = self.exec_into(s, &mut captures)?;
        Some(MatchResult {
            start,
            end,
            captures,
        })
    }

    /// [`OsRegex::exec`] with the captures written into `caps`; allocates
    /// only while `caps` is smaller than the group count.
    pub fn exec_into(&self, s: &str, caps: &mut Vec<(usize, usize)>) -> Option<(usize, usize)> {
        let b = s.as_bytes();
        self.alts.iter().find_map(|alt| alt.exec_into(b, caps))
    }

    /// True when some alternative matches. Allocates nothing (see
    /// [`OsRegex::find_end`]).
    pub fn is_match(&self, s: &str) -> bool {
        self.find_end(s).is_some()
    }

    /// Where the first match ends. Captures go to a small buffer on the
    /// stack (Wazuh allows few groups); only a pattern with more groups
    /// than that falls back to the heap.
    pub fn find_end(&self, s: &str) -> Option<usize> {
        const STACK: usize = 32;
        let b = s.as_bytes();
        self.alts.iter().find_map(|alt| {
            let found = if alt.groups <= STACK {
                let mut caps = [(0usize, 0usize); STACK];
                alt.find(b, &mut caps[..alt.groups])
            } else {
                let mut caps = vec![(0usize, 0usize); alt.groups];
                alt.find(b, &mut caps)
            };
            found.map(|(_, end)| end)
        })
    }
}

impl RegexAlt {
    fn exec_into(&self, s: &[u8], caps: &mut Vec<(usize, usize)>) -> Option<(usize, usize)> {
        caps.clear();
        caps.resize(self.groups, (0, 0));
        self.find(s, caps)
    }

    fn find(&self, s: &[u8], caps: &mut [(usize, usize)]) -> Option<(usize, usize)> {
        let last_start = if self.begin { 0 } else { s.len() };
        for start in 0..=last_start {
            if let Some(end) = self.step(s, 0, start, caps) {
                return Some((start, end));
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

/// A PCRE2 pattern, run by the PCRE2 C library (the `pcre2` crate), the
/// library Wazuh itself uses. Built the way Wazuh 4.14.10 builds it:
/// `pcre2_compile` with no options, so matching is byte-wise and `\w`,
/// `\d` are ASCII (`rulelanes-syntax` turns JIT on, which PCRE2 documents
/// as giving the same results).
///
/// Each value keeps its own capture buffer, made on first use and reused
/// after, so `exec_into` allocates nothing after warm-up (R8). Cloning
/// gives the clone fresh buffers (and `pcre2` a fresh match-data pool), so
/// each stage's clone of the engine has its own; a value is `Send` but
/// not `Sync`.
pub struct Pcre2 {
    pub source: String,
    pub regex: pcre2::bytes::Regex,
    locs: std::cell::RefCell<Option<pcre2::bytes::CaptureLocations>>,
}

impl Clone for Pcre2 {
    fn clone(&self) -> Pcre2 {
        Pcre2::new(self.source.clone(), self.regex.clone())
    }
}

impl std::fmt::Debug for Pcre2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pcre2")
            .field("source", &self.source)
            .finish()
    }
}

impl Pcre2 {
    pub fn new(source: String, regex: pcre2::bytes::Regex) -> Pcre2 {
        Pcre2 {
            source,
            regex,
            locs: std::cell::RefCell::new(None),
        }
    }

    pub fn exec(&self, s: &str) -> Option<MatchResult> {
        let mut captures = Vec::new();
        let (start, end) = self.exec_into(s, &mut captures)?;
        Some(MatchResult {
            start,
            end,
            captures,
        })
    }

    /// [`Pcre2::exec`] with the captures written into `caps`. A match
    /// error (for example PCRE2's match limit) counts as no match, as in
    /// Wazuh, which tests `pcre2_match`'s result for > 0.
    pub fn exec_into(&self, s: &str, caps: &mut Vec<(usize, usize)>) -> Option<(usize, usize)> {
        let mut slot = self.locs.borrow_mut();
        let locs = slot.get_or_insert_with(|| self.regex.capture_locations());
        let whole = self
            .regex
            .captures_read(locs, s.as_bytes())
            .ok()
            .flatten()?;
        // Wazuh returns groups 1 to rc - 1, where rc is one more than the
        // highest group that took part; a group that did not take part is
        // an empty string.
        let highest = (1..locs.len())
            .rev()
            .find(|&i| locs.get(i).is_some())
            .unwrap_or(0);
        caps.clear();
        caps.extend((1..=highest).map(|i| locs.get(i).unwrap_or((0, 0))));
        Some((whole.start(), whole.end()))
    }

    /// True when the pattern matches anywhere in `s`.
    pub fn is_match(&self, s: &str) -> bool {
        self.regex.is_match(s.as_bytes()).unwrap_or(false)
    }

    /// Where the first match ends, without captures.
    pub fn find_end(&self, s: &str) -> Option<usize> {
        self.regex
            .find(s.as_bytes())
            .ok()
            .flatten()
            .map(|m| m.end())
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
