//! A small reader for the XML dialect Wazuh uses in decoder and rule files.
//!
//! The files are not always well-formed XML: a file has several root
//! elements, and patterns escape `<` as `\<`. Element text is kept as
//! written (no entity decoding, no trimming), because pattern text is
//! passed to the pattern compilers unchanged.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Node {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Node>,
    pub text: String,
    pub line: usize,
}

impl Node {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlError {
    pub line: usize,
    pub message: String,
}

/// Parse a file into its root elements.
pub fn parse(text: &str) -> Result<Vec<Node>, XmlError> {
    let b = text.as_bytes();
    let mut i = 0;
    let mut line = 1;
    let mut stack: Vec<Node> = Vec::new();
    let mut roots = Vec::new();
    let err = |line, m: &str| XmlError {
        line,
        message: m.to_string(),
    };
    while i < b.len() {
        if b[i] == b'<' && !escaped(b, i) {
            if text[i..].starts_with("<!--") {
                let end = text[i..]
                    .find("-->")
                    .ok_or_else(|| err(line, "unterminated comment"))?;
                line += text[i..i + end].matches('\n').count();
                i += end + 3;
                continue;
            }
            if text[i..].starts_with("<?") || text[i..].starts_with("<!") {
                let end = text[i..]
                    .find('>')
                    .ok_or_else(|| err(line, "unterminated declaration"))?;
                line += text[i..i + end].matches('\n').count();
                i += end + 1;
                continue;
            }
            // Find the end of the tag, respecting quoted attribute values.
            let mut j = i + 1;
            let mut quote: Option<u8> = None;
            while j < b.len() {
                match (quote, b[j]) {
                    (None, b'"') | (None, b'\'') => quote = Some(b[j]),
                    (Some(q), c) if c == q => quote = None,
                    (None, b'>') => break,
                    _ => {}
                }
                j += 1;
            }
            if j >= b.len() {
                return Err(err(line, "unterminated tag"));
            }
            let tag = &text[i + 1..j];
            let tag_line = line;
            line += tag.matches('\n').count();
            i = j + 1;
            if let Some(name) = tag.strip_prefix('/') {
                let name = name.trim();
                let node = stack
                    .pop()
                    .ok_or_else(|| err(tag_line, &format!("unexpected </{name}>")))?;
                if node.name != name {
                    return Err(err(
                        tag_line,
                        &format!("</{name}> does not close <{}>", node.name),
                    ));
                }
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => roots.push(node),
                }
                continue;
            }
            let (body, empty) = match tag.strip_suffix('/') {
                Some(t) => (t, true),
                None => (tag, false),
            };
            let node = parse_tag(body, tag_line).map_err(|m| err(tag_line, &m))?;
            if empty {
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => roots.push(node),
                }
            } else {
                stack.push(node);
            }
        } else {
            let start = i;
            while i < b.len() && !(b[i] == b'<' && !escaped(b, i)) {
                i += 1;
            }
            let chunk = &text[start..i];
            line += chunk.matches('\n').count();
            match stack.last_mut() {
                Some(n) => n.text.push_str(chunk),
                None if chunk.trim().is_empty() => {}
                None => return Err(err(line, "text outside any element")),
            }
        }
    }
    if let Some(n) = stack.last() {
        return Err(err(n.line, &format!("<{}> is not closed", n.name)));
    }
    Ok(roots)
}

fn parse_tag(body: &str, _line: usize) -> Result<Node, String> {
    let body = body.trim();
    let name_end = body.find(|c: char| c.is_whitespace()).unwrap_or(body.len());
    let name = &body[..name_end];
    if name.is_empty() {
        return Err("empty tag name".into());
    }
    let mut attrs = Vec::new();
    let mut rest = body[name_end..].trim_start();
    while !rest.is_empty() {
        let eq = rest
            .find('=')
            .ok_or_else(|| format!("attribute without value in <{name}>"))?;
        let key = rest[..eq].trim().to_string();
        let after = rest[eq + 1..].trim_start();
        let q = after
            .chars()
            .next()
            .filter(|c| *c == '"' || *c == '\'')
            .ok_or_else(|| format!("unquoted attribute {key} in <{name}>"))?;
        let close = after[1..]
            .find(q)
            .ok_or_else(|| format!("unterminated attribute {key} in <{name}>"))?;
        attrs.push((key, after[1..1 + close].to_string()));
        rest = after[close + 2..].trim_start();
    }
    Ok(Node {
        name: name.to_string(),
        attrs,
        children: Vec::new(),
        text: String::new(),
        line: _line,
    })
}

/// Replace `$name` with the value of a file-level `<var name="name">`.
/// Unknown names are left as written.
pub fn apply_vars(s: &str, vars: &HashMap<String, String>) -> String {
    if vars.is_empty() || !s.contains('$') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('$') {
        out.push_str(&rest[..p]);
        let after = &rest[p + 1..];
        let n = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        match vars.get(&after[..n]) {
            Some(v) if n > 0 => {
                out.push_str(v);
                rest = &after[n..];
            }
            _ => {
                out.push('$');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// True when the byte at `i` follows an odd number of backslashes (`\<`
/// is pattern text, `\\<` is an escaped backslash and then a tag).
fn escaped(b: &[u8], i: usize) -> bool {
    b[..i].iter().rev().take_while(|&&c| c == b'\\').count() % 2 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn several_roots_and_escaped_lt() {
        let r = parse("<a x=\"1\"><b>\\<y</b></a>\n<!-- c --><c/>").unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].attr("x"), Some("1"));
        assert_eq!(r[0].children[0].text, "\\<y");
        assert_eq!(r[1].name, "c");
    }

    #[test]
    fn vars() {
        let mut v = HashMap::new();
        v.insert("A".to_string(), "x|y".to_string());
        assert_eq!(apply_vars("^$A$", &v), "^x|y$");
    }

    #[test]
    fn escaped_backslash_before_a_tag() {
        let r = parse("<f>E:\\\\</f>").unwrap();
        assert_eq!(r[0].text, "E:\\\\");
    }
}
