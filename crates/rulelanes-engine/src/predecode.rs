//! Pre-decoding: the syslog-style header (timestamp, hostname, program
//! name).
//!
//! M1 recognises the header forms whose timestamp is one of
//! `Mmm dd hh:mm:ss`, `yyyy Mmm dd hh:mm:ss`, `yyyy-mm-dd hh:mm:ss,mmm`, and
//! the ISO 8601 forms Wazuh lists, followed by a hostname and a program name
//! (`name:`, `name[pid]:` or `name[pid] `), and the hostless `name: ` form.
//! Other header formats Wazuh knows (xferlog, snort, suricata, apache, AIX,
//! macOS ULS) are treated as "no header" and are not part of R1 in M1.

use std::sync::Arc;

use rulelanes_model::Event;

/// Characters Wazuh accepts in a hostname or program name.
fn valid(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'(' | b')' | b'-' | b'.' | b'/' | b'@' | b'_')
}

/// Length of the timestamp prefix including its trailing separator, if the
/// line starts with a recognised timestamp.
fn timestamp_len(p: &[u8]) -> Option<usize> {
    let loglen = p.len() + 1;
    let at = |i: usize| p.get(i).copied().unwrap_or(0);
    if loglen > 17
        && at(3) == b' '
        && at(6) == b' '
        && at(9) == b':'
        && at(12) == b':'
        && at(15) == b' '
    {
        return Some(16);
    }
    if loglen > 24
        && at(4) == b'-'
        && at(7) == b'-'
        && at(10) == b' '
        && at(13) == b':'
        && at(16) == b':'
        && at(19) == b','
    {
        return Some(24);
    }
    if loglen > 33
        && at(4) == b'-'
        && at(7) == b'-'
        && at(10) == b'T'
        && at(13) == b':'
        && at(16) == b':'
    {
        if at(22) == b':' && at(25) == b' ' {
            return Some(26);
        }
        if at(19) == b'.' {
            if at(26) == b':' {
                return Some(30);
            }
            if at(29) == b':' {
                return Some(33);
            }
            return Some(32);
        }
    }
    if loglen > 21
        && at(0).is_ascii_digit()
        && at(4) == b' '
        && at(8) == b' '
        && at(11) == b' '
        && at(14) == b':'
        && at(17) == b':'
        && at(20) == b' '
    {
        return Some(21);
    }
    if loglen > 33
        && at(0).is_ascii_digit()
        && at(4) == b'-'
        && at(7) == b'-'
        && at(10) == b' '
        && at(13) == b':'
        && at(16) == b':'
        && at(19) == b'.'
        && (at(26) == b'-' || at(26) == b'+')
        && at(31) == b' '
    {
        return Some(32);
    }
    None
}

pub fn predecode(line: &str, location: &str) -> Event {
    let mut ev = Event::default();
    predecode_into(&mut ev, line, &Arc::from(location));
    ev
}

/// [`predecode`] into an existing event, reusing its line buffer: no
/// allocation once the buffer fits the line (R8).
pub fn predecode_into(ev: &mut Event, line: &str, location: &Arc<str>) {
    ev.reset(line, location);
    let b = line.as_bytes();
    let Some(ts) = timestamp_len(b) else {
        return;
    };
    if ts > b.len() {
        return;
    }
    ev.timestamp_at = Some(0..ts - 1);
    let mut i = ts;
    if b.get(i) == Some(&b' ') {
        i += 1;
    }
    ev.log_start = i;
    let host_start = i;
    while i < b.len() && valid(b[i]) {
        i += 1;
    }
    let at = |k: usize| b.get(k).copied().unwrap_or(0);
    if at(i) == b':' && at(i + 1) == b' ' {
        // No hostname: the word is the program name.
        ev.program_name_at = Some(host_start..i);
        ev.log_start = i + 2;
        return;
    }
    if at(i) != b' ' {
        // Not a hostname: the message starts after the timestamp.
        return;
    }
    ev.hostname_at = Some(host_start..i);
    i += 1;
    ev.log_start = i;
    let prog_start = i;
    while i < b.len() && valid(b[i]) {
        i += 1;
    }
    let prog_end = i;
    let msg_start = if at(i) == b':' {
        i += 1;
        if at(i) == b' ' {
            i += 1;
        }
        Some(i)
    } else if at(i) == b'[' && at(i + 1).is_ascii_digit() {
        i += 2;
        while at(i).is_ascii_digit() {
            i += 1;
        }
        if at(i) == b']' && at(i + 1) == b':' {
            i += 2;
            if at(i) == b' ' {
                i += 1;
            }
            Some(i)
        } else if at(i) == b']' && at(i + 1) == b' ' {
            Some(i + 2)
        } else {
            None
        }
    } else {
        None
    };
    let Some(mut m) = msg_start else {
        return;
    };
    ev.program_name_at = Some(prog_start..prog_end);
    if line[m..].starts_with("[ID ")
        && let Some(close) = line[m + 4..].find(']')
    {
        m = (m + 4 + close + 2).min(line.len());
    }
    ev.log_start = m.min(line.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bsd_header() {
        let e = predecode(
            "Oct 15 21:07:00 linux-agent sshd[29205]: Invalid user x",
            "l",
        );
        assert_eq!(e.timestamp(), Some("Oct 15 21:07:00"));
        assert_eq!(e.hostname(), Some("linux-agent"));
        assert_eq!(e.program_name(), Some("sshd"));
        assert_eq!(e.log(), "Invalid user x");
    }

    #[test]
    fn no_header() {
        let e = predecode("hello world", "l");
        assert_eq!(e.log(), "hello world");
        assert!(e.program_name().is_none());
    }
}
