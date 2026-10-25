//! The client address a reverse proxy passes in `relay.real_ip_header`.
//! Every per-address budget and NIP-86 IP block keys on it.

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use wok_relay::config::IpRange;

/// The client a request's `relay.real_ip_header` names.
#[derive(Debug, PartialEq)]
pub enum Forwarded {
    /// The request has no such header.
    Absent,
    /// The connection is not from one of `relay.trusted_proxies`, so its
    /// header, if any, is ignored.
    Untrusted,
    Client(IpAddr),
    /// The entry where the client's address should be, which names no
    /// address.
    Unparsed(String),
}

/// The client that the header `name` names on a connection from `peer`.
///
/// Without `trusted` proxies it is the header's last entry, the one the
/// proxy in front of Wok wrote: a proxy that appends to the client's own
/// header, or adds its own line after it, leaves the client's entries in
/// front. With them, only a connection from one of them may name a client,
/// and the client is the first address from the header's end that is not
/// one of them. Each proxy appends the address it was reached from, so every
/// entry after the client's was written by a trusted proxy, and whatever the
/// client sent stays ahead of its address. When every address is a proxy's,
/// the first is the client.
///
/// The header's lines form one comma-separated list (RFC 9110 §5.3).
/// `Forwarded` is read as RFC 7239 defines it, by its name rather than its
/// content, so what a client sends cannot choose the syntax. Any other
/// header is a list of addresses, each of which may carry a port.
pub fn client(
    headers: &hyper::HeaderMap,
    name: &str,
    peer: IpAddr,
    trusted: &[IpRange],
) -> Forwarded {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|range| range.contains(ip));
    if !trusted.is_empty() && !is_trusted(peer) {
        return Forwarded::Untrusted;
    }
    let rfc7239 = name.eq_ignore_ascii_case("forwarded");
    let mut first = Forwarded::Absent;
    for line in headers.get_all(name).iter().rev() {
        let line = String::from_utf8_lossy(line.as_bytes());
        let mut rest = Some(line.as_ref());
        while let Some(text) = rest {
            let (entry, ahead) = if rfc7239 {
                split_last_element(text)
            } else {
                split_last_entry(text)
            };
            let address = if rfc7239 {
                element_for(entry).as_deref().and_then(node_address)
            } else {
                list_entry_address(entry)
            };
            let Some(ip) = address else {
                return Forwarded::Unparsed(entry.to_string());
            };
            if !is_trusted(ip) {
                return Forwarded::Client(ip);
            }
            first = Forwarded::Client(ip);
            rest = ahead;
        }
    }
    first
}

/// The last entry of an address list, such as X-Forwarded-For, and the text
/// ahead of it, if any.
fn split_last_entry(line: &str) -> (&str, Option<&str>) {
    match line.rsplit_once(',') {
        Some((ahead, entry)) => (entry.trim(), Some(ahead)),
        None => (line.trim(), None),
    }
}

/// The address of an address-list entry, with or without a port.
fn list_entry_address(entry: &str) -> Option<IpAddr> {
    entry
        .parse::<IpAddr>()
        .or_else(|_| entry.parse::<SocketAddr>().map(|addr| addr.ip()))
        .ok()
}

/// The last element of an RFC 7239 `Forwarded` line, after its last comma
/// outside a quoted string, and the text ahead of it, if any. Elements are
/// found from the right, so text ahead of the ones the proxies wrote, which
/// the client may have written, cannot move where they start, not even an
/// unterminated quoted string. Inside a quoted string, a quote after an odd
/// run of backslashes is escaped.
fn split_last_element(line: &str) -> (&str, Option<&str>) {
    let bytes = line.as_bytes();
    let mut quoted = false;
    for at in (0..bytes.len()).rev() {
        match bytes[at] {
            b'"' if quoted => {
                let backslashes = bytes[..at].iter().rev().take_while(|&&b| b == b'\\');
                quoted = backslashes.count() % 2 == 1;
            }
            b'"' => quoted = true,
            b',' if !quoted => {
                return (line[at + 1..].trim_matches(is_ows), Some(&line[..at]));
            }
            _ => {}
        }
    }
    (line.trim_matches(is_ows), None)
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
    use wok_relay::config::IpRange;

    /// The client in a header `name` with one line per entry of `lines`,
    /// on a connection from `peer`, behind `trusted` proxies.
    fn read_from(peer: &str, trusted: &[&str], name: &str, lines: &[&str]) -> Forwarded {
        let mut headers = hyper::HeaderMap::new();
        for line in lines {
            headers.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(line).unwrap(),
            );
        }
        let trusted: Vec<IpRange> = trusted.iter().map(|range| range.parse().unwrap()).collect();
        client(&headers, name, peer.parse().unwrap(), &trusted)
    }

    /// Without trusted proxies, from any connection.
    fn read(name: &str, lines: &[&str]) -> Forwarded {
        read_from("203.0.113.200", &[], name, lines)
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

    /// The local proxy in front of Wok, and the CDN in front of it.
    const PROXIES: &[&str] = &["127.0.0.1", "192.0.2.0/24"];

    /// The client in X-Forwarded-For lines from the local proxy.
    fn behind(lines: &[&str]) -> Forwarded {
        read_from("127.0.0.1", PROXIES, "x-forwarded-for", lines)
    }

    /// The client in Forwarded lines from the local proxy.
    fn rfc7239_behind(lines: &[&str]) -> Forwarded {
        read_from("127.0.0.1", PROXIES, "forwarded", lines)
    }

    #[test]
    fn trusted_proxies_are_skipped_from_the_right() {
        // The local proxy appends the CDN edge's address to the CDN's list.
        assert_eq!(behind(&["203.0.113.7, 192.0.2.10"]), at("203.0.113.7"));
        assert_eq!(behind(&["203.0.113.7:4711, 192.0.2.10"]), at("203.0.113.7"));
        // What the client sent stays ahead of its address.
        assert_eq!(
            behind(&["198.51.100.9, 203.0.113.7, 192.0.2.10"]),
            at("203.0.113.7")
        );
        assert_eq!(
            behind(&["198.51.100.9", "203.0.113.7, 192.0.2.10"]),
            at("203.0.113.7")
        );
        // The CDN appends to the client's line, the local proxy adds its own.
        assert_eq!(
            behind(&["198.51.100.9, 203.0.113.7", "192.0.2.10"]),
            at("203.0.113.7")
        );
        // A client past the CDN that claims a CDN address is its own address.
        assert_eq!(behind(&["192.0.2.10, 203.0.113.7"]), at("203.0.113.7"));
        // An IPv4-mapped address is its IPv4 address.
        assert_eq!(
            behind(&["203.0.113.7, ::ffff:192.0.2.10"]),
            at("203.0.113.7")
        );
        // When every address is a proxy, the first is the client.
        assert_eq!(behind(&["192.0.2.11, 192.0.2.10"]), at("192.0.2.11"));
        assert_eq!(behind(&["192.0.2.11", "192.0.2.10"]), at("192.0.2.11"));
        // Forwarded, element by element.
        assert_eq!(
            rfc7239_behind(&[
                r#"for=198.51.100.9, for="203.0.113.7:4711", for=192.0.2.10;proto=https"#
            ]),
            at("203.0.113.7")
        );
        assert_eq!(
            rfc7239_behind(&[r#"for="198.51.100.9, for=203.0.113.7"#, "for=192.0.2.10"]),
            at("203.0.113.7")
        );
        assert_eq!(
            rfc7239_behind(&[r#"for="[2001:db8::7]";host="a, b", For=192.0.2.10"#]),
            at("2001:db8::7")
        );
    }

    #[test]
    fn a_connection_from_outside_the_trusted_proxies_is_its_own_address() {
        let direct = |lines: &[&str]| read_from("203.0.113.7", PROXIES, "x-forwarded-for", lines);
        assert_eq!(direct(&["198.51.100.9"]), Forwarded::Untrusted);
        assert_eq!(direct(&["198.51.100.9, 192.0.2.10"]), Forwarded::Untrusted);
        assert_eq!(direct(&["unknown"]), Forwarded::Untrusted);
        assert_eq!(direct(&[]), Forwarded::Untrusted);
        // An IPv4-mapped connection is its IPv4 address.
        assert_eq!(
            read_from(
                "::ffff:127.0.0.1",
                PROXIES,
                "x-forwarded-for",
                &["203.0.113.7"]
            ),
            at("203.0.113.7")
        );
    }

    #[test]
    fn the_walk_stops_at_an_entry_that_names_no_address() {
        assert_eq!(behind(&[]), Forwarded::Absent);
        assert_eq!(
            behind(&["203.0.113.7, unknown, 192.0.2.10"]),
            unparsed("unknown")
        );
        assert_eq!(behind(&["203.0.113.7, , 192.0.2.10"]), unparsed(""));
        assert_eq!(behind(&["203.0.113.7", "", "192.0.2.10"]), unparsed(""));
        assert_eq!(
            rfc7239_behind(&["for=203.0.113.7, for=_hidden, for=192.0.2.10"]),
            unparsed("for=_hidden")
        );
        // Past the client's address, nothing is read.
        assert_eq!(
            behind(&["unknown, 203.0.113.7, 192.0.2.10"]),
            at("203.0.113.7")
        );
    }
}
