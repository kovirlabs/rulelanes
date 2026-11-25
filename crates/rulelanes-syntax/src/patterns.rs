//! Parse pattern text into compiled patterns.

use rulelanes_model::pattern::{
    ClassKind, IpList, IpNet, MatchAlt, MatchAnchor, OsMatch, OsRegex, Pattern, Pcre2, Quant,
    RegexAlt, Tok,
};
use std::net::Ipv4Addr;

/// Longest pattern Wazuh accepts (`OS_PATTERN_MAXSIZE`).
const MAX_PATTERN: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    OsMatch,
    OsRegex,
    Pcre2,
    Exact,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        match s.to_ascii_lowercase().as_str() {
            "osmatch" => Some(Kind::OsMatch),
            "osregex" => Some(Kind::OsRegex),
            "pcre2" => Some(Kind::Pcre2),
            _ => None,
        }
    }
}

pub fn compile(kind: Kind, text: &str) -> Result<Pattern, String> {
    Ok(match kind {
        Kind::OsMatch => Pattern::OsMatch(osmatch(text)?),
        Kind::OsRegex => Pattern::OsRegex(osregex(text)?),
        Kind::Pcre2 => Pattern::Pcre2(pcre2(text)?),
        Kind::Exact => Pattern::Exact(text.to_string()),
    })
}

pub fn osmatch(text: &str) -> Result<OsMatch, String> {
    if text.len() > MAX_PATTERN {
        return Err(format!("pattern longer than {MAX_PATTERN} bytes"));
    }
    let (negated, body) = match text.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let alts = body
        .split('|')
        .map(|alt| {
            let lower = alt.to_ascii_lowercase();
            let begin = lower.starts_with('^');
            let inner = if begin { &lower[1..] } else { &lower[..] };
            let end = !alt.is_empty() && alt.ends_with('$') && !inner.is_empty();
            let inner = if end {
                &inner[..inner.len() - 1]
            } else {
                inner
            };
            let anchor = match (begin, end) {
                (true, true) => MatchAnchor::Whole,
                (true, false) => MatchAnchor::Prefix,
                (false, true) => MatchAnchor::Suffix,
                (false, false) => MatchAnchor::Anywhere,
            };
            MatchAlt {
                anchor,
                text: inner.as_bytes().to_vec(),
            }
        })
        .collect();
    Ok(OsMatch { negated, alts })
}

pub fn osregex(text: &str) -> Result<OsRegex, String> {
    if text.len() > MAX_PATTERN {
        return Err(format!("pattern longer than {MAX_PATTERN} bytes"));
    }
    let b = text.as_bytes();
    let mut alts = Vec::new();
    let mut toks: Vec<Tok> = Vec::new();
    // Raw-position flags for anchors: is the first byte of the alternative an
    // unescaped '^', and the last an unescaped '$'.
    let mut alt_first_raw = 0usize;
    let mut groups = 0usize;
    let mut open = false;
    let mut i = 0;
    let mut last_escaped_end = false;
    let finish = |toks: &mut Vec<Tok>,
                  start_raw: usize,
                  end_raw: usize,
                  escaped_end: bool,
                  groups: usize|
     -> RegexAlt {
        let begin = start_raw < end_raw
            && b[start_raw] == b'^'
            && matches!(toks.first(), Some(Tok::Lit(b'^')));
        if begin {
            toks.remove(0);
        }
        let end = end_raw > start_raw
            && b[end_raw - 1] == b'$'
            && !escaped_end
            && matches!(toks.last(), Some(Tok::Lit(b'$')));
        if end {
            toks.pop();
        }
        RegexAlt {
            begin,
            end,
            toks: std::mem::take(toks),
            groups,
        }
    };
    while i < b.len() {
        let c = b[i];
        last_escaped_end = false;
        match c {
            b'\\' => {
                let Some(&e) = b.get(i + 1) else {
                    return Err("pattern ends with a lone backslash".into());
                };
                let class = match e {
                    b'd' => Some(ClassKind::Digit),
                    b'w' => Some(ClassKind::Word),
                    b's' => Some(ClassKind::Space),
                    b'p' => Some(ClassKind::Punct),
                    b'D' => Some(ClassKind::NotDigit),
                    b'W' => Some(ClassKind::NotWord),
                    b'S' => Some(ClassKind::NotSpace),
                    b'.' => Some(ClassKind::Any),
                    b't' => Some(ClassKind::Tab),
                    _ => None,
                };
                i += 2;
                if let Some(k) = class {
                    let q = match b.get(i) {
                        Some(b'+') => {
                            i += 1;
                            Quant::Plus
                        }
                        Some(b'*') => {
                            i += 1;
                            Quant::Star
                        }
                        _ => Quant::One,
                    };
                    toks.push(Tok::Class(k, q));
                } else {
                    let lit = match e {
                        b'(' | b')' | b'\\' | b'$' | b'|' | b'<' => e,
                        other => {
                            return Err(format!("unknown escape \\{}", other as char));
                        }
                    };
                    toks.push(Tok::Lit(lit.to_ascii_lowercase()));
                    last_escaped_end = true;
                }
                continue;
            }
            b'(' => {
                if open {
                    return Err("nested parentheses are not allowed in osregex".into());
                }
                open = true;
                toks.push(Tok::Open(groups));
            }
            b')' => {
                if !open {
                    return Err("unbalanced ')'".into());
                }
                open = false;
                toks.push(Tok::Close(groups));
                groups += 1;
            }
            b'|' => {
                if open {
                    return Err("'|' inside parentheses is not allowed in osregex".into());
                }
                alts.push(finish(&mut toks, alt_first_raw, i, false, groups));
                groups = 0;
                alt_first_raw = i + 1;
            }
            other => toks.push(Tok::Lit(other.to_ascii_lowercase())),
        }
        i += 1;
    }
    if open {
        return Err("unbalanced '('".into());
    }
    alts.push(finish(
        &mut toks,
        alt_first_raw,
        b.len(),
        last_escaped_end,
        groups,
    ));
    // A group that closes right where the next one opens, as in
    // `(\p+)(\w+)`, does not match in Wazuh 4.14.10 (checked against
    // wazuh-logtest in M1): its matcher steps over one parenthesis per
    // input character. Refuse it rather than match where Wazuh does not.
    if alts.iter().any(|a| {
        a.toks
            .windows(2)
            .any(|w| matches!(w, [Tok::Close(_), Tok::Open(_)]))
    }) {
        return Err(
            "a group that starts right after another ends, e.g. `(a)(b)`, is not supported".into(),
        );
    }
    Ok(OsRegex { alts })
}

pub fn pcre2(text: &str) -> Result<Pcre2, String> {
    // Wazuh 4.14.10 calls `pcre2_compile` with no options (checked in its
    // `src/shared/expression.c`); the builder's defaults are the same (no
    // UTF, no UCP, case-sensitive). JIT changes speed, not results.
    let regex = pcre2::bytes::RegexBuilder::new()
        .jit_if_available(true)
        .build(text)
        .map_err(|e| e.to_string())?;
    Ok(Pcre2::new(text.to_string(), regex))
}

/// Parse a `srcip` / `dstip` value: comma- or space-separated IPv4
/// addresses or networks (`a.b.c.d/nn` or `a.b.c.d/m.m.m.m`), each
/// optionally prefixed with `!`.
pub fn ip_list(text: &str) -> Result<IpList, String> {
    let mut nets = Vec::new();
    for part in text
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|p| !p.is_empty())
    {
        let (negated, p) = match part.strip_prefix('!') {
            Some(r) => (true, r),
            None => (false, part),
        };
        let (addr, prefix) = match p.split_once('/') {
            Some((a, m)) => {
                let prefix = if let Ok(n) = m.parse::<u8>() {
                    n
                } else {
                    let mask: Ipv4Addr = m.parse().map_err(|_| format!("bad netmask in {part}"))?;
                    u32::from(mask).count_ones() as u8
                };
                (a, prefix)
            }
            None => (p, 32),
        };
        if prefix > 32 {
            return Err(format!("bad prefix in {part}"));
        }
        let addr: Ipv4Addr = addr.parse().map_err(|_| {
            format!("'{part}' is not an IPv4 address or network (IPv6 is not supported in M1)")
        })?;
        nets.push(IpNet {
            addr: u32::from(addr),
            prefix,
            negated,
        });
    }
    if nets.is_empty() {
        return Err("empty IP list".into());
    }
    Ok(IpList { nets })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(p: &str, s: &str) -> Option<Vec<String>> {
        let r = osregex(p).unwrap();
        r.exec(s).map(|m| {
            m.captures
                .iter()
                .map(|&(a, b)| s[a..b].to_string())
                .collect()
        })
    }

    #[test]
    fn osregex_basics() {
        assert_eq!(
            caps(r"^(\S+) (\d+)$", "abc 123"),
            Some(vec!["abc".into(), "123".into()])
        );
        assert_eq!(
            caps(r"user (\w+) from (\S+)", "Failed user Bob from 1.2.3.4"),
            Some(vec!["Bob".into(), "1.2.3.4".into()])
        );
        assert!(caps(r"^abc|^xyz", "XYZ!").is_some());
        assert!(osregex("(a(b))").is_err());
        assert!(osregex("(a|b)").is_err());
        assert!(osregex(r"\q").is_err());
        assert_eq!(caps(r"a\$", "xa$"), Some(vec![]));
    }

    #[test]
    fn osmatch_forms() {
        let m = osmatch("^abc$|def").unwrap();
        assert!(m.is_match("ABC"));
        assert!(m.is_match("xxdefxx"));
        assert!(!m.is_match("abcd"));
        assert!(osmatch("!foo").unwrap().is_match("bar"));
    }

    #[test]
    fn ips() {
        let l = ip_list("10.0.0.0/8, !192.168.1.1").unwrap();
        assert!(l.contains("10.1.2.3"));
        assert!(l.contains("172.16.0.1"));
    }

    fn pcre2_caps(p: &str, s: &str) -> Option<Vec<String>> {
        let r = pcre2(p).unwrap();
        r.exec(s).map(|m| {
            m.captures
                .iter()
                .map(|&(a, b)| s[a..b].to_string())
                .collect()
        })
    }

    #[test]
    fn pcre2_is_the_real_library() {
        // Branch reset, which fancy-regex lacked.
        assert_eq!(pcre2_caps(r"(?|(a)|(b))", "b"), Some(vec!["b".into()]));
        // `\h` is horizontal space in PCRE2 (a hex digit in fancy-regex).
        assert_eq!(pcre2_caps(r"x\h(y)", "x\ty"), Some(vec!["y".into()]));
        // Look-ahead, as in the test ruleset's key=value decoders.
        assert_eq!(
            pcre2_caps(
                r"\bmsg=(\S.*?)(?=\s+[A-Za-z][A-Za-z0-9_]*=|\s*$)",
                "msg=a b c=d"
            ),
            Some(vec!["a b".into()])
        );
        // No options: case-sensitive and ASCII `\w`.
        assert!(pcre2("abc").unwrap().exec("ABC").is_none());
        assert!(pcre2(r"^\w$").unwrap().exec("é").is_none());
    }

    #[test]
    fn pcre2_groups_up_to_the_highest_that_took_part() {
        // Group 2 does not take part: only group 1 is reported.
        assert_eq!(pcre2_caps(r"(a)(b)?", "a"), Some(vec!["a".into()]));
        // Group 1 does not take part but group 2 does: group 1 is empty.
        assert_eq!(
            pcre2_caps(r"(x)?(b)", "b"),
            Some(vec![String::new(), "b".into()])
        );
    }
}
