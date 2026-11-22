//! A strict JSON reader (RFC 8259), small enough to read in one sitting.
//!
//! Copied from the Rust client (clients/rust/src/json.rs, reviewed with it), less its
//! `as_array`; here it reads the runner's plan, which only plimsoll writes (Go's
//! encoding/json, which never writes a lone surrogate or a key twice).
//!
//! In the client it reads what a daemon answers and the shared test files, and nothing else, so it
//! keeps a number as the text it arrived as (a 64-bit integer or a float is converted by
//! the standard library's exact parsers where the field's type is known), refuses a key
//! that appears twice in one object (a daemon's encoder never writes one, and two readers
//! could otherwise believe two different values), refuses a `\u` escape of a lone
//! surrogate (it has no UTF-8 form, so a digest over it could not equal the daemon's),
//! stops at a nesting depth of 64, and stops at [`MAX_VALUES`] values, so the memory one
//! answer can take is bounded by that count rather than by its size alone.

use std::fmt;

/// The deepest nesting the reader accepts. The deepest plimsoll answer nests 5 levels.
pub const MAX_DEPTH: usize = 64;

/// The most values (numbers, strings, lists, objects, literals) one text may hold. A value
/// takes about 32 bytes here plus its text, so this bounds one answer's memory near 70 MB
/// plus its own size; no answer this client reads holds more than a few thousand (a
/// project's steps and artifacts are the longest lists, and this client sends no module
/// run, whose answer is the one shape that grows with its input).
pub const MAX_VALUES: usize = 1 << 21;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// A number, as its JSON text.
    Number(String),
    String(String),
    Array(Vec<Value>),
    /// An object's members in the order they arrived; no key appears twice.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// The member `key` of an object, or None (also for a value that is not an object).
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// What kind of JSON value this is, for error messages.
    pub fn kind(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "a boolean",
            Value::Number(_) => "a number",
            Value::String(_) => "a string",
            Value::Array(_) => "a list",
            Value::Object(_) => "an object",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub offset: usize,
    pub what: &'static str,
    /// True when this reader refuses what Go's `encoding/json` reads: text that is not
    /// UTF-8 (Go reads a replacement character), a lone surrogate (the same), a key twice
    /// (Go keeps the last), or nesting past [`MAX_DEPTH`] (Go allows 10,000). The error
    /// reader takes such a refusal as an answer it cannot read the way Go does, and believes
    /// nothing in it, not even the header's mark.
    pub stricter_than_go: bool,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JSON at byte {}: {}", self.offset, self.what)
    }
}

impl std::error::Error for Error {}

/// Reads one JSON value that fills `text`, with only whitespace around it.
pub fn parse(text: &str) -> Result<Value, Error> {
    let mut p = Parser { b: text.as_bytes(), i: 0, values: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return Err(p.err("text after the value"));
    }
    Ok(v)
}

/// Reads JSON from bytes, which must be UTF-8.
pub fn parse_bytes(bytes: &[u8]) -> Result<Value, Error> {
    let text = std::str::from_utf8(bytes).map_err(|e| Error {
        offset: e.valid_up_to(),
        what: "not UTF-8",
        stricter_than_go: true,
    })?;
    parse(text)
}

const LONE: &str = "a lone surrogate, which has no UTF-8 form";

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    values: usize,
}

impl Parser<'_> {
    fn err(&self, what: &'static str) -> Error {
        Error { offset: self.i, what, stricter_than_go: false }
    }

    fn stricter(at: usize, what: &'static str) -> Error {
        Error { offset: at, what, stricter_than_go: true }
    }

    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.b.get(self.i) {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &[u8]) -> bool {
        if self.b[self.i..].starts_with(lit) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Self::stricter(self.i, "nested too deeply"));
        }
        self.values += 1;
        if self.values > MAX_VALUES {
            return Err(self.err("more values than one answer may hold"));
        }
        match self.b.get(self.i) {
            None => Err(self.err("end of text where a value belongs")),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') if self.eat(b"true") => Ok(Value::Bool(true)),
            Some(b'f') if self.eat(b"false") => Ok(Value::Bool(false)),
            Some(b'n') if self.eat(b"null") => Ok(Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.err("not the start of a value")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, Error> {
        let start = self.i;
        self.i += 1;
        let mut members: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.eat(b"}") {
            return Ok(Value::Object(members));
        }
        loop {
            self.ws();
            if self.b.get(self.i) != Some(&b'"') {
                return Err(self.err("an object key must be a string"));
            }
            let at = self.i;
            let key = self.string()?;
            // A short object is checked as it grows; a long one once, sorted, at its end,
            // so the check costs n log n and not n squared.
            if members.len() < 16 && members.iter().any(|(k, _)| *k == key) {
                return Err(Self::stricter(at, "a key appears twice in one object"));
            }
            self.ws();
            if !self.eat(b":") {
                return Err(self.err("expected ':' after an object key"));
            }
            self.ws();
            let v = self.value(depth + 1)?;
            members.push((key, v));
            self.ws();
            if self.eat(b",") {
                continue;
            }
            if self.eat(b"}") {
                if members.len() > 16 {
                    let mut keys: Vec<&str> = members.iter().map(|(k, _)| k.as_str()).collect();
                    keys.sort_unstable();
                    if keys.windows(2).any(|w| w[0] == w[1]) {
                        return Err(Self::stricter(start, "a key appears twice in one object"));
                    }
                }
                return Ok(Value::Object(members));
            }
            return Err(self.err("expected ',' or '}' in an object"));
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, Error> {
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.eat(b"]") {
            return Ok(Value::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            if self.eat(b",") {
                continue;
            }
            if self.eat(b"]") {
                return Ok(Value::Array(items));
            }
            return Err(self.err("expected ',' or ']' in a list"));
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while let Some(b'0'..=b'9') = self.b.get(self.i) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<Value, Error> {
        let start = self.i;
        self.eat(b"-");
        match self.b.get(self.i) {
            Some(b'0') => {
                self.i += 1;
                if let Some(b'0'..=b'9') = self.b.get(self.i) {
                    return Err(self.err("a number with a leading zero"));
                }
            }
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.err("a number without digits")),
        }
        if self.eat(b".") && self.digits() == 0 {
            return Err(self.err("a fraction without digits"));
        }
        if let Some(b'e' | b'E') = self.b.get(self.i) {
            self.i += 1;
            if let Some(b'+' | b'-') = self.b.get(self.i) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(self.err("an exponent without digits"));
            }
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).expect("a number is ASCII");
        Ok(Value::Number(text.to_owned()))
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let Some(h) = self.b.get(self.i..self.i + 4) else {
            return Err(self.err("a \\u escape needs four hex digits"));
        };
        let mut v = 0u32;
        for &c in h {
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(self.err("a \\u escape needs four hex digits")),
            };
            v = v * 16 + u32::from(d);
        }
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, Error> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let start = self.i;
            while let Some(&c) = self.b.get(self.i) {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            // The input is a &str, so any run of bytes between ASCII delimiters is UTF-8.
            out.push_str(std::str::from_utf8(&self.b[start..self.i]).expect("input is UTF-8"));
            match self.b.get(self.i) {
                None => return Err(self.err("a string with no closing quote")),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let Some(&e) = self.b.get(self.i) else {
                        return Err(self.err("a string with no closing quote"));
                    };
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let c = match hi {
                                0xd800..=0xdbff => {
                                    if !self.eat(b"\\u") {
                                        return Err(Self::stricter(self.i, LONE));
                                    }
                                    let lo = self.hex4()?;
                                    if !(0xdc00..=0xdfff).contains(&lo) {
                                        return Err(Self::stricter(self.i, LONE));
                                    }
                                    0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                                }
                                0xdc00..=0xdfff => return Err(Self::stricter(self.i, LONE)),
                                c => c,
                            };
                            out.push(char::from_u32(c).expect("a scalar value"));
                        }
                        _ => return Err(self.err("an unknown escape")),
                    }
                }
                Some(_) => return Err(self.err("a control character in a string")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Value, parse};

    #[test]
    fn reads_values() {
        let v = parse(r#" {"a": [1, -0.5e3, true, null, "x\u00e9\ud83d\ude00\n"], "b": {}} "#).unwrap();
        let Some(Value::Array(a)) = v.get("a") else { panic!("a is not a list") };
        assert_eq!(a[0], Value::Number("1".into()));
        assert_eq!(a[1], Value::Number("-0.5e3".into()));
        assert_eq!(a[2], Value::Bool(true));
        assert_eq!(a[3], Value::Null);
        assert_eq!(a[4].as_str(), Some("x\u{e9}\u{1f600}\n"));
        assert_eq!(v.get("b"), Some(&Value::Object(vec![])));
    }

    #[test]
    fn refuses_what_rfc_8259_or_this_reader_refuses() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "01",
            "1.",
            ".5",
            "-",
            "1e",
            "+1",
            "\"\\x\"",
            "\"a",
            "\"\u{1}\"",
            "{\"a\":1 \"b\":2}",
            "{\"a\":1,\"a\":2}",
            "\"\\ud800\"",
            "\"\\udc00\"",
            "\"\\ud800\\u0041\"",
            "tru",
            "nul",
            "1 2",
            "[1] x",
            "NaN",
            "'a'",
            "{1:2}",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} was read");
        }
        let deep = "[".repeat(66) + &"]".repeat(66);
        assert!(parse(&deep).is_err());
        let ok = "[".repeat(60) + &"]".repeat(60);
        assert!(parse(&ok).is_ok());
    }
}
