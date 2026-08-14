//! JSON parse/serialize matching C++ `tao::json` semantics.
//!
//! Differences from stock `serde_json` that matter for wire and storage
//! compatibility with strfry:
//!
//! - `parse_strict` rejects duplicate object keys (`tao::json::from_string`
//!   throws `duplicate JSON object key`); serde_json silently keeps the last.
//! - `to_tao_string` escapes U+007F as `` (tao escapes all control
//!   characters `< 0x20` *and* `0x7F`); serde_json emits `0x7F` raw.
//! - Both sides otherwise agree: sorted object keys, no whitespace, UTF-8
//!   passthrough, shortest-round-trip ryu float formatting.
//!
//! The event id hash preimage and the normalized stored JSON must match the
//! C++ byte output exactly, so always use `to_tao_string` for those.

use serde_json::{Map, Value};

use crate::EventError;

/// Maximum nesting depth accepted by the parser. Matches serde_json's
/// default recursion limit (128). C++ tao has no built-in limit; wok keeps
/// the cap as DoS hardening (documented in docs/known-differences.md).
const MAX_DEPTH: usize = 128;

pub fn parse_strict(text: &str) -> Result<Value, EventError> {
    let mut p = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let v = p.parse_value(0)?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(p.err("unexpected trailing characters"));
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, msg: &str) -> EventError {
        EventError::msg(format!("{msg} at byte {}", self.pos))
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, s: &'static str) -> Result<(), EventError> {
        if self.bytes[self.pos..].starts_with(s.as_bytes()) {
            self.pos += s.len();
            Ok(())
        } else {
            Err(self.err(&format!("expected {s}")))
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value, EventError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b't') => {
                self.expect("true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.expect("false")?;
                Ok(Value::Bool(false))
            }
            Some(b'n') => {
                self.expect("null")?;
                Ok(Value::Null)
            }
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(_) => Err(self.err("unexpected character")),
            None => Err(self.err("unexpected end of input")),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Value, EventError> {
        self.bump(); // {
        let mut map = Map::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected object key string"));
            }
            let key = self.parse_string()?;
            // tao::json throws on duplicate object keys; match it.
            if map.contains_key(&key) {
                return Err(self.err(&format!("duplicate JSON object key {key:?}")));
            }
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err(self.err("expected ':'"));
            }
            self.skip_ws();
            let value = self.parse_value(depth + 1)?;
            map.insert(key, value);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
        Ok(Value::Object(map))
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, EventError> {
        self.bump(); // [
        let mut arr = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(Value::Array(arr));
        }
        loop {
            self.skip_ws();
            arr.push(self.parse_value(depth + 1)?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => break,
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
        Ok(Value::Array(arr))
    }

    fn parse_string(&mut self) -> Result<String, EventError> {
        self.bump(); // opening quote
        let mut out = String::new();
        loop {
            let c = self.bump().ok_or_else(|| self.err("unterminated string"))?;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.bump().ok_or_else(|| self.err("unterminated escape"))?;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.parse_hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                // High surrogate: require a low surrogate pair.
                                if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                                    return Err(self.err("unpaired surrogate"));
                                }
                                let lo = self.parse_hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err("unpaired surrogate"));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(self.err("unpaired surrogate"));
                            } else {
                                hi
                            };
                            out.push(
                                char::from_u32(cp).ok_or_else(|| self.err("invalid codepoint"))?,
                            );
                        }
                        _ => return Err(self.err("invalid escape")),
                    }
                }
                0x00..=0x1F => return Err(self.err("unescaped control character in string")),
                _ => {
                    // Collect one UTF-8 codepoint (input is &str, so raw bytes
                    // are valid UTF-8; copy the full sequence).
                    let start = self.pos - 1;
                    let len = utf8_len(c);
                    if len > 1 {
                        let end = start + len;
                        if end > self.bytes.len() {
                            return Err(self.err("truncated UTF-8"));
                        }
                        let s = std::str::from_utf8(&self.bytes[start..end])
                            .map_err(|_| self.err("invalid UTF-8"))?;
                        out.push_str(s);
                        self.pos = end;
                    } else {
                        out.push(c as char);
                    }
                }
            }
        }
        Ok(out)
    }

    fn parse_hex4(&mut self) -> Result<u32, EventError> {
        if self.pos + 4 > self.bytes.len() {
            return Err(self.err("truncated \\u escape"));
        }
        let mut v = 0u32;
        for _ in 0..4 {
            let c = self.bump().unwrap();
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(self.err("invalid hex digit in \\u escape")),
            };
            v = v * 16 + d as u32;
        }
        Ok(v)
    }

    fn parse_number(&mut self) -> Result<Value, EventError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
            }
            Some(b'1'..=b'9') => self.consume_digits(),
            _ => return Err(self.err("invalid number")),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("invalid number"));
            }
            self.consume_digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("invalid number"));
            }
            self.consume_digits();
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.err("invalid number"))?;
        let n = if is_float {
            serde_json::Number::from_f64(
                text.parse::<f64>()
                    .map_err(|_| self.err("invalid number"))?,
            )
            .ok_or_else(|| self.err("number out of range"))?
        } else if let Ok(u) = text.parse::<u64>() {
            serde_json::Number::from(u)
        } else if let Ok(i) = text.parse::<i64>() {
            serde_json::Number::from(i)
        } else {
            // Larger than u64/i64: both tao and serde_json fall back to double.
            serde_json::Number::from_f64(
                text.parse::<f64>()
                    .map_err(|_| self.err("invalid number"))?,
            )
            .ok_or_else(|| self.err("number out of range"))?
        };
        Ok(Value::Number(n))
    }

    fn consume_digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first < 0xE0 {
        2
    } else if first < 0xF0 {
        3
    } else {
        4
    }
}

/// Serialize like C++ `tao::json::to_string`: compact, sorted object keys,
/// and tao's string escaping (control chars and 0x7F escaped).
pub fn to_tao_string(v: &Value) -> String {
    let mut out = String::new();
    write_tao(v, &mut out);
    out
}

pub(crate) fn write_tao(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_u64() || n.is_i64() {
                out.push_str(&n.to_string());
            } else {
                out.push_str(&format_tao_f64(n.as_f64().unwrap_or_default()));
            }
        }
        Value::String(s) => write_tao_string(s, out),
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_tao(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            // serde_json's Map is sorted (BTreeMap) in this workspace; sort
            // explicitly so the output is stable regardless of features.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_tao_string(k, out);
                out.push(':');
                write_tao(&map[*k], out);
            }
            out.push('}');
        }
    }
}

/// tao::json string escaping: `"` and `\` escaped; bytes `< 0x20` and `0x7F`
/// become `\b \f \n \r \t` or `\u00xx`; everything else passes through raw.
fn write_tao_string(s: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7F => {
                let b = c as u32 as usize;
                out.push_str("\\u00");
                out.push(HEX[(b & 0xf0) >> 4] as char);
                out.push(HEX[b & 0x0f] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// tao::json f64 formatting (bundled ryu `d2s_finite`): shortest-round-trip
/// digits; decimal notation when `-6 < exp < 22` (value = D x 10^(exp-L) for
/// digit string D of length L), scientific `d.ddde<exp-1>` otherwise, with a
/// lowercase `e` and no `+`. serde_json emits the same digits but switches to
/// scientific earlier and writes `e+X`; transform its output into tao's form.
fn format_tao_f64(f: f64) -> String {
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0" } else { "0.0" }.to_string();
    }
    let s = serde_json::Number::from_f64(f)
        .map(|n| n.to_string())
        .unwrap_or_default();
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.as_str()),
    };
    // Extract significant digits D (no trailing zeros) and normalized
    // exponent E where value = D[0].D[1..] x 10^E.
    let (digits, exp10): (String, i32) = if let Some(epos) = s.find(['e', 'E']) {
        let mantissa: String = s[..epos].chars().filter(|c| *c != '.').collect();
        let e: i32 = s[epos + 1..].parse().unwrap_or(0);
        (mantissa, e)
    } else if let Some(dot) = s.find('.') {
        let int_part = &s[..dot];
        let frac_part = &s[dot + 1..];
        if int_part != "0" {
            (format!("{int_part}{frac_part}"), int_part.len() as i32 - 1)
        } else {
            let zeros = frac_part.bytes().take_while(|b| *b == b'0').count();
            (frac_part[zeros..].to_string(), -(zeros as i32) - 1)
        }
    } else {
        (s.to_string(), s.len() as i32 - 1)
    };
    let mut digits = digits;
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    let exp = exp10 + 1; // tao's exp: digits before the point in decimal form
    let l = digits.len() as i32;
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if (-6 < exp) && (exp < 22) {
        if exp <= 0 {
            out.push_str("0.");
            for _ in 0..-exp {
                out.push('0');
            }
            out.push_str(&digits);
        } else if exp >= l {
            out.push_str(&digits);
            for _ in 0..exp - l {
                out.push('0');
            }
            out.push_str(".0");
        } else {
            out.push_str(&digits[..exp as usize]);
            out.push('.');
            out.push_str(&digits[exp as usize..]);
        }
    } else {
        out.push(digits.as_bytes()[0] as char);
        if l > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push_str(&exp10.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_duplicate_keys() {
        assert!(parse_strict(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse_strict(r#"{"a":{"b":1,"b":2}}"#).is_err());
        assert!(parse_strict(r#"{"a":1,"b":2}"#).is_ok());
    }

    #[test]
    fn parses_scalars_and_containers() {
        assert_eq!(parse_strict("null").unwrap(), Value::Null);
        assert_eq!(parse_strict("true").unwrap(), Value::Bool(true));
        assert_eq!(parse_strict("[1,2]").unwrap(), json!([1, 2]));
        assert_eq!(parse_strict(r#"{"k":"v"}"#).unwrap(), json!({"k": "v"}));
        assert!(parse_strict("{").is_err());
        assert!(parse_strict("[1,]").is_err());
        assert!(parse_strict("").is_err());
        assert!(parse_strict("[1] trailing").is_err());
    }

    #[test]
    fn string_escapes() {
        assert_eq!(
            parse_strict(r#""a\nbé""#).unwrap(),
            Value::String("a\nbé\u{80}".into())
        );
        assert_eq!(parse_strict(r#""/""#).unwrap(), Value::String("/".into()));
        // surrogate pair
        assert_eq!(
            parse_strict(r#""\ud83d\ude00""#).unwrap(),
            Value::String("😀".into())
        );
        // lone surrogates rejected like tao/serde
        assert!(parse_strict(r#""\ud800""#).is_err());
        assert!(parse_strict(r#""\udc00""#).is_err());
        assert!(parse_strict(r#""\ud800x""#).is_err());
        // raw control char rejected
        assert!(parse_strict("\"a\u{0001}b\"").is_err());
    }

    #[test]
    fn numbers() {
        assert_eq!(parse_strict("0").unwrap(), json!(0));
        assert_eq!(parse_strict("-5").unwrap(), json!(-5));
        assert_eq!(
            parse_strict("18446744073709551615").unwrap(),
            json!(u64::MAX)
        );
        assert_eq!(
            parse_strict("-9223372036854775808").unwrap(),
            json!(i64::MIN)
        );
        // beyond u64: f64 fallback like tao
        assert_eq!(
            parse_strict("18446744073709551616").unwrap(),
            json!(18446744073709551616f64)
        );
        assert_eq!(parse_strict("1.5").unwrap(), json!(1.5));
        assert_eq!(parse_strict("1e2").unwrap(), json!(100.0));
        assert!(parse_strict("01x").is_err());
        assert!(parse_strict("-").is_err());
        assert!(parse_strict("1.").is_err());
        assert!(parse_strict("1e").is_err());
    }

    #[test]
    fn depth_limit() {
        let deep = "[".repeat(200) + &"]".repeat(200);
        assert!(parse_strict(&deep).is_err());
        let ok = "[".repeat(100) + &"]".repeat(100);
        assert!(parse_strict(&ok).is_ok());
    }

    #[test]
    fn tao_serialization_matches_cpp() {
        // Values verified against tao::json::to_string from the vendored
        // tao copy in the strfry tree.
        let arr = json!([1.5f64, 1000.0f64, 0.1f64, 1e300f64]);
        assert_eq!(to_tao_string(&arr), "[1.5,1000.0,0.1,1e300]");
        let s = Value::String("a\u{7f}b".into());
        assert_eq!(to_tao_string(&s), "\"a\\u007fb\"");
        let obj = json!({"b": 1, "a": [true, null, "x"]});
        assert_eq!(to_tao_string(&obj), r#"{"a":[true,null,"x"],"b":1}"#);
    }

    #[test]
    #[allow(clippy::approx_constant, clippy::excessive_precision)]
    fn tao_f64_formatting_matches_cpp() {
        // Expected strings captured from tao::json::to_string (d2s_finite).
        let cases: &[(f64, &str)] = &[
            (1.5, "1.5"),
            (1000.0, "1000.0"),
            (0.1, "0.1"),
            (1e300, "1e300"),
            (1e-300, "1e-300"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e308"),
            (123456.789, "123456.789"),
            (0.000001, "0.000001"),
            (0.0000001, "1e-7"),
            (1e21, "1e21"),
            (1e22, "1e22"),
            (123456789012345680000.0, "123456789012345680000.0"),
            (-0.0, "-0.0"),
            (0.0, "0.0"),
            (2.5, "2.5"),
            (3.141592653589793, "3.141592653589793"),
            (1e15, "1000000000000000.0"),
            (1e16, "10000000000000000.0"),
            (1e17, "100000000000000000.0"),
            (9.999999999999999e22, "1e23"),
            (1e-5, "0.00001"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (7.038531e-26, "7.038531e-26"),
            (1.0, "1.0"),
            (12.0, "12.0"),
            (0.5, "0.5"),
            (-1234.5678, "-1234.5678"),
            (-1e300, "-1e300"),
        ];
        for (v, want) in cases {
            assert_eq!(format_tao_f64(*v), *want, "value {v}");
            assert_eq!(to_tao_string(&json!(*v)), *want, "value {v} via Value");
        }
    }

    #[test]
    fn tao_roundtrip_parse_serialize() {
        let src =
            r#"{"content":"héllo","created_at":1700000000,"tags":[["e","abc"],["x",1.5,-3]]}"#;
        let v = parse_strict(src).unwrap();
        assert_eq!(to_tao_string(&v), src);
    }
}
