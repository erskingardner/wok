//! The client address a reverse proxy passes in `relay.real_ip_header`.
//! Every per-address budget and NIP-86 IP block keys on it.

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The client a request's `relay.real_ip_header` names.
#[derive(Debug, PartialEq)]
pub enum Forwarded {
    /// The request has no such header.
    Absent,
    Client(IpAddr),
    /// The header's last entry, which names no address.
    Unparsed(String),
}

/// The client in the last entry of the header `name`, the one the proxy in
/// front of Wok wrote: a proxy that appends to the client's own header, or
/// adds its own line after it, leaves the client's entries in front. The
/// header's lines form one comma-separated list (RFC 9110 §5.3), so the
/// last entry is on the last line. `Forwarded` is read as RFC 7239 defines
/// it, by its name rather than its content, so what a client sends cannot
/// choose the syntax. Any other header is a list of addresses, each of
/// which may carry a port.
pub fn client(headers: &hyper::HeaderMap, name: &str) -> Forwarded {
    let Some(line) = headers.get_all(name).iter().next_back() else {
        return Forwarded::Absent;
    };
    let line = String::from_utf8_lossy(line.as_bytes());
    if name.eq_ignore_ascii_case("forwarded") {
        last_forwarded_element(&line)
    } else {
        last_list_entry(&line)
    }
}

/// The client in the last entry of an address list, such as
/// X-Forwarded-For.
fn last_list_entry(line: &str) -> Forwarded {
    let entry = line.rsplit(',').next().unwrap_or_default().trim();
    entry
        .parse::<IpAddr>()
        .or_else(|_| entry.parse::<SocketAddr>().map(|addr| addr.ip()))
        .map_or_else(
            |_| Forwarded::Unparsed(entry.to_string()),
            Forwarded::Client,
        )
}

/// The client in the `for` parameter of the last element of an RFC 7239
/// `Forwarded` line. The element must be well formed, with exactly one
/// `for`, naming an address; anything ahead of it may be anything.
fn last_forwarded_element(line: &str) -> Forwarded {
    let element = last_element(line).trim_matches(is_ows);
    match element_for(element).as_deref().and_then(node_address) {
        Some(ip) => Forwarded::Client(ip),
        None => Forwarded::Unparsed(element.to_string()),
    }
}

/// The text after the last comma of `line` that is outside a quoted string.
/// It is found from the right, so text ahead of the proxy's element, which
/// the client may have written, cannot move where that element starts, not
/// even an unterminated quoted string. Inside a quoted string, a quote
/// after an odd run of backslashes is escaped.
fn last_element(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut quoted = false;
    for at in (0..bytes.len()).rev() {
        match bytes[at] {
            b'"' if quoted => {
                let backslashes = bytes[..at].iter().rev().take_while(|&&b| b == b'\\');
                quoted = backslashes.count() % 2 == 1;
            }
            b'"' => quoted = true,
            b',' if !quoted => return &line[at + 1..],
            _ => {}
        }
    }
    line
}

/// The `for` value of a forwarded-element: `;`-separated pairs, each a
/// token, `=`, and a token or a quoted string (RFC 7239 §4), where empty
/// pairs and space around a pair are allowed. Parameter names are compared
/// without case. A value a token cannot hold, such as an IPv6 address, is
/// accepted unquoted too. None when a pair is malformed, or when the
/// element has no `for` or more than one.
fn element_for(element: &str) -> Option<Cow<'_, str>> {
    let mut found = None;
    let mut rest = element;
    loop {
        rest = rest.trim_start_matches(is_ows);
        if rest.is_empty() {
            return found;
        }
        if let Some(after) = rest.strip_prefix(';') {
            rest = after;
            continue;
        }
        let (name, after) = rest.split_once('=')?;
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return None;
        }
        let (value, after) = match after.strip_prefix('"') {
            Some(quoted) => quoted_string(quoted)?,
            None => {
                let end = after.find(';').unwrap_or(after.len());
                let (value, after) = after.split_at(end);
                (Cow::Borrowed(value.trim_end_matches(is_ows)), after)
            }
        };
        rest = after.trim_start_matches(is_ows);
        if !(rest.is_empty() || rest.starts_with(';')) {
            return None;
        }
        if name.eq_ignore_ascii_case("for") && found.replace(value).is_some() {
            return None;
        }
    }
}

/// The quoted string whose opening quote `text` follows, unescaped, and the
/// text after its closing quote. None when it is not closed.
fn quoted_string(text: &str) -> Option<(Cow<'_, str>, &str)> {
    let mut unescaped: Option<String> = None;
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => {
                let value = unescaped.map_or(Cow::Borrowed(&text[..at]), Cow::Owned);
                return Some((value, &text[at + 1..]));
            }
            '\\' => {
                let (_, escaped) = chars.next()?;
                unescaped
                    .get_or_insert_with(|| text[..at].to_string())
                    .push(escaped);
            }
            c => {
                if let Some(unescaped) = &mut unescaped {
                    unescaped.push(c);
                }
            }
        }
    }
    None
}

/// The address of an RFC 7239 node (§6): an IPv4 address, or an IPv6
/// address in brackets, with an optional port, which may be obfuscated.
/// `unknown` and obfuscated identifiers name no address, and neither does
/// an IPv6 address without brackets, whose last group could be a port.
fn node_address(node: &str) -> Option<IpAddr> {
    let (ip, port) = match node.strip_prefix('[') {
        Some(bracketed) => {
            let (ip, port) = bracketed.split_once(']')?;
            (IpAddr::V6(ip.parse::<Ipv6Addr>().ok()?), port)
        }
        None => {
            let (ip, port) = node.split_at(node.find(':').unwrap_or(node.len()));
            (IpAddr::V4(ip.parse::<Ipv4Addr>().ok()?), port)
        }
    };
    match port.strip_prefix(':') {
        None if port.is_empty() => Some(ip),
        Some(port) if is_node_port(port) => Some(ip),
        _ => None,
    }
}

/// An RFC 7239 node-port: one to five digits, or `_` and an obfuscated
/// name.
fn is_node_port(port: &str) -> bool {
    let digits = (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit());
    let obfuscated = port.strip_prefix('_').is_some_and(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    });
    digits || obfuscated
}

/// An RFC 9110 token character.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// RFC 9110 optional whitespace.
fn is_ows(c: char) -> bool {
    c == ' ' || c == '\t'
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client in a header `name` with one line per entry of `lines`.
    fn read(name: &str, lines: &[&str]) -> Forwarded {
        let mut headers = hyper::HeaderMap::new();
        for line in lines {
            headers.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(line).unwrap(),
            );
        }
        client(&headers, name)
    }

    fn forwarded(lines: &[&str]) -> Forwarded {
        read("x-forwarded-for", lines)
    }

    /// As the setting names it, in any case.
    fn rfc7239(lines: &[&str]) -> Forwarded {
        read("Forwarded", lines)
    }

    fn unparsed(entry: &str) -> Forwarded {
        Forwarded::Unparsed(entry.to_string())
    }

    fn at(ip: &str) -> Forwarded {
        Forwarded::Client(ip.parse().unwrap())
    }

    #[test]
    fn the_forwarded_client_is_the_last_entry() {
        assert_eq!(forwarded(&[]), Forwarded::Absent);
        assert_eq!(forwarded(&["203.0.113.7"]), at("203.0.113.7"));
        assert_eq!(forwarded(&[" 203.0.113.7 "]), at("203.0.113.7"));
        // Appended to the client's own header.
        assert_eq!(forwarded(&["198.51.100.9, 203.0.113.7"]), at("203.0.113.7"));
        assert_eq!(forwarded(&["198.51.100.9,203.0.113.7"]), at("203.0.113.7"));
        // A line of the proxy's own after the client's.
        assert_eq!(
            forwarded(&["198.51.100.9", "203.0.113.7"]),
            at("203.0.113.7")
        );
        assert_eq!(
            forwarded(&["192.0.2.1, 198.51.100.9", "203.0.113.7"]),
            at("203.0.113.7")
        );
        // Entries with a port, and IPv6.
        assert_eq!(forwarded(&["203.0.113.7:4711"]), at("203.0.113.7"));
        assert_eq!(forwarded(&["2001:db8::1"]), at("2001:db8::1"));
        assert_eq!(forwarded(&["[2001:db8::1]:4711"]), at("2001:db8::1"));
    }

    #[test]
    fn a_last_entry_that_is_not_an_address_is_unparsed() {
        assert_eq!(forwarded(&["203.0.113.7, unknown"]), unparsed("unknown"));
        assert_eq!(forwarded(&["203.0.113.7,"]), unparsed(""));
        assert_eq!(forwarded(&["203.0.113.7", ""]), unparsed(""));
        // RFC 7239 Forwarded syntax is not an address list.
        assert_eq!(
            forwarded(&["for=192.0.2.60;proto=https"]),
            unparsed("for=192.0.2.60;proto=https")
        );
        // A client's address in front does not rescue the proxy's entry.
        assert_eq!(forwarded(&["203.0.113.7", "_hidden"]), unparsed("_hidden"));
    }

    #[test]
    fn the_forwarded_client_is_the_for_of_the_last_element() {
        assert_eq!(rfc7239(&[]), Forwarded::Absent);
        assert_eq!(rfc7239(&["for=192.0.2.60"]), at("192.0.2.60"));
        assert_eq!(
            rfc7239(&["for=192.0.2.60;proto=https;by=203.0.113.43"]),
            at("192.0.2.60")
        );
        assert_eq!(rfc7239(&["proto=https;for=192.0.2.60"]), at("192.0.2.60"));
        // Parameter names are case-insensitive.
        assert_eq!(rfc7239(&["For=192.0.2.60"]), at("192.0.2.60"));
        assert_eq!(rfc7239(&["FOR=192.0.2.60"]), at("192.0.2.60"));
        // Quoted values, with a port, and IPv6 in brackets.
        assert_eq!(rfc7239(&[r#"for="192.0.2.60""#]), at("192.0.2.60"));
        assert_eq!(rfc7239(&[r#"for="192.0.2.60:4711""#]), at("192.0.2.60"));
        assert_eq!(rfc7239(&[r#"for="[2001:db8::1]""#]), at("2001:db8::1"));
        assert_eq!(rfc7239(&[r#"for="[2001:db8::1]:4711""#]), at("2001:db8::1"));
        // Unquoted, though a token cannot hold them.
        assert_eq!(rfc7239(&["for=192.0.2.60:4711"]), at("192.0.2.60"));
        assert_eq!(rfc7239(&["for=[2001:db8::1]:4711"]), at("2001:db8::1"));
        // An obfuscated port still comes with the address.
        assert_eq!(rfc7239(&[r#"for="192.0.2.60:_eth0""#]), at("192.0.2.60"));
        // A quoted pair stands for its character.
        assert_eq!(rfc7239(&[r#"for="192.0.2.\60""#]), at("192.0.2.60"));
        // Appended to the client's own header, or a line of the proxy's own
        // after the client's.
        assert_eq!(
            rfc7239(&["for=198.51.100.9, for=192.0.2.60"]),
            at("192.0.2.60")
        );
        assert_eq!(
            rfc7239(&["for=198.51.100.9,for=192.0.2.60"]),
            at("192.0.2.60")
        );
        assert_eq!(
            rfc7239(&["for=198.51.100.9", "for=192.0.2.60;proto=https"]),
            at("192.0.2.60")
        );
        // Empty pairs, and space around a pair.
        assert_eq!(
            rfc7239(&[";for=192.0.2.60;; proto=https;"]),
            at("192.0.2.60")
        );
    }

    #[test]
    fn what_the_client_sent_cannot_move_the_proxys_element() {
        // An unterminated quoted string ahead of the proxy's element.
        assert_eq!(
            rfc7239(&[r#"for="198.51.100.9, for=192.0.2.60"#]),
            at("192.0.2.60")
        );
        assert_eq!(
            rfc7239(&[r#"for="198.51.100.9"#, "for=192.0.2.60"]),
            at("192.0.2.60")
        );
        assert_eq!(
            rfc7239(&[r#"\";;==,,"\, for=192.0.2.60"#]),
            at("192.0.2.60")
        );
        // A quoted value of the proxy's own may hold a comma, a `for`, or an
        // escaped quote.
        assert_eq!(
            rfc7239(&[r#"for=192.0.2.60;host="a, for=198.51.100.9""#]),
            at("192.0.2.60")
        );
        assert_eq!(
            rfc7239(&[r#"host="a\", for=198.51.100.9";for=192.0.2.60"#]),
            at("192.0.2.60")
        );
        assert_eq!(rfc7239(&[r#"host="a\\";for=192.0.2.60"#]), at("192.0.2.60"));
    }

    #[test]
    fn a_last_element_that_names_no_address_is_unparsed() {
        // Hidden clients.
        assert_eq!(rfc7239(&["for=unknown"]), unparsed("for=unknown"));
        assert_eq!(rfc7239(&["for=_hidden"]), unparsed("for=_hidden"));
        assert_eq!(
            rfc7239(&[r#"for="_hidden:4711""#]),
            unparsed(r#"for="_hidden:4711""#)
        );
        // No client, an empty one, or two.
        assert_eq!(rfc7239(&["proto=https"]), unparsed("proto=https"));
        assert_eq!(rfc7239(&["for="]), unparsed("for="));
        assert_eq!(rfc7239(&[r#"for="""#]), unparsed(r#"for="""#));
        assert_eq!(
            rfc7239(&["for=192.0.2.60;for=198.51.100.9"]),
            unparsed("for=192.0.2.60;for=198.51.100.9")
        );
        // An empty last element.
        assert_eq!(rfc7239(&["for=192.0.2.60,"]), unparsed(""));
        assert_eq!(rfc7239(&["for=192.0.2.60", ""]), unparsed(""));
        // A client's element in front does not rescue the proxy's.
        assert_eq!(
            rfc7239(&["for=192.0.2.60, for=unknown"]),
            unparsed("for=unknown")
        );
        assert_eq!(rfc7239(&["for=192.0.2.60", "_hidden"]), unparsed("_hidden"));
        // Malformed pairs and values.
        for element in [
            "192.0.2.60",
            "for",
            "=192.0.2.60",
            "f r=192.0.2.60",
            "for =192.0.2.60",
            r#"for="192.0.2.60"x"#,
            r#"for="192.0.2.60"#,
            r#"for=" 192.0.2.60""#,
            r#"for="192.0.2.60:""#,
            r#"for="192.0.2.60:123456""#,
            r#"for="192.0.2.60:_""#,
            "for=300.0.2.60",
            "for=192.0.2.060",
            // IPv6 without brackets: its last group could be a port.
            r#"for="2001:db8::1""#,
            r#"for="[2001:db8::1""#,
            r#"for="[2001:db8::1]4711""#,
            r#"for="[fe80::1%25eth0]""#,
            r#"for="[192.0.2.60]""#,
        ] {
            assert_eq!(rfc7239(&[element]), unparsed(element), "{element}");
        }
    }
}
