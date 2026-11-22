//! What the runner writes: base64 and JSON encoded byte for byte as Node's runner encodes
//! them (`Buffer.toString("base64")` and `JSON.stringify`), since the runner's size budgets
//! are counted on that encoding (the design review's finding 5) and the report frame's MAC is
//! over those bytes.

/// Standard base64 with padding, as `Buffer.toString("base64")`.
pub fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Appends `s` as a JSON string, escaped as `JSON.stringify` escapes it: the quote, the
/// backslash and the control characters below 0x20 (the five with a short form by it,
/// the rest as `\u00xx` in lowercase hex); everything else, DEL and every character past
/// ASCII included, as itself in UTF-8.
pub fn string(out: &mut String, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u00");
                out.push(HEX[(c as usize) >> 4] as char);
                out.push(HEX[(c as usize) & 15] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn boolean(out: &mut String, b: bool) {
    out.push_str(if b { "true" } else { "false" });
}

#[cfg(test)]
mod tests {
    use super::{base64, string};

    #[test]
    fn base64_as_node() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"hi"), "aGk=");
        assert_eq!(base64(b"e\xff"), "Zf8=");
        assert_eq!(base64(b"in\n"), "aW4K");
        assert_eq!(base64(b"abc"), "YWJj");
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
    }

    #[test]
    fn strings_as_json_stringify() {
        let mut s = String::new();
        string(&mut s, "a\"b\\c\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f}<>&\u{e9}\u{2028}\u{1f600}/");
        assert_eq!(s, "\"a\\\"b\\\\c\\b\\f\\n\\r\\t\\u0001\\u001f\u{7f}<>&\u{e9}\u{2028}\u{1f600}/\"");
    }
}
