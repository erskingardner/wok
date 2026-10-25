//! The client address header holds whatever a client sent ahead of what the
//! proxies in front of Wok wrote. Whatever the client sends, only the
//! proxies' entries decide the client's address, and no header panics the
//! parser.

use proptest::prelude::*;
use std::net::{IpAddr, Ipv6Addr};
use wok_relay::config::IpRange;
use wok_ws::forwarded::{client, Forwarded};

/// A header `name` with one line per entry of `lines`, leaving out a line
/// hyper would refuse.
fn headers(name: &'static str, lines: &[String]) -> hyper::HeaderMap {
    let mut headers = hyper::HeaderMap::new();
    for line in lines {
        if let Ok(value) = hyper::header::HeaderValue::from_str(line) {
            headers.append(name, value);
        }
    }
    headers
}

/// The client in `lines` of the header `name`, without trusted proxies.
fn read(name: &'static str, lines: &[String]) -> Forwarded {
    client(
        &headers(name, lines),
        name,
        IpAddr::from([203, 0, 113, 200]),
        &[],
    )
}

/// The local proxy in front of Wok, and a CDN's ranges in front of it.
fn proxies() -> Vec<IpRange> {
    ["127.0.0.1", "192.0.2.0/24", "2001:db8::/32"]
        .iter()
        .map(|range| range.parse().unwrap())
        .collect()
}

/// An address in one of the CDN's ranges.
fn cdn_address() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<u8>().prop_map(|host| IpAddr::from([192, 0, 2, host])),
        any::<u128>()
            .prop_map(|host| IpAddr::V6(Ipv6Addr::from((0x2001_0db8 << 96) | (host >> 32)))),
    ]
}

/// Header text a client could send, heavy in the characters both formats
/// give meaning to.
fn sent() -> impl Strategy<Value = String> {
    let piece = prop_oneof![
        Just("\"".to_string()),
        Just("\\".to_string()),
        Just(",".to_string()),
        Just(";".to_string()),
        Just("=".to_string()),
        Just(" ".to_string()),
        Just("for".to_string()),
        Just("[".to_string()),
        Just("]".to_string()),
        Just(":".to_string()),
        Just("198.51.100.9".to_string()),
        Just("2001:db8::9".to_string()),
        Just("unknown".to_string()),
        Just("_hidden".to_string()),
        "[ -~]{0,4}",
        "\\PC",
    ];
    proptest::collection::vec(piece, 0..24).prop_map(|pieces| pieces.concat())
}

/// An RFC 7239 node for `ip`, as a proxy writes it: IPv6 in brackets, and
/// quoted when it holds a character a token may not.
fn node(ip: IpAddr, port: Option<u16>) -> String {
    match (ip, port) {
        (IpAddr::V4(ip), None) => ip.to_string(),
        (IpAddr::V4(ip), Some(port)) => format!("\"{ip}:{port}\""),
        (IpAddr::V6(ip), None) => format!("\"[{ip}]\""),
        (IpAddr::V6(ip), Some(port)) => format!("\"[{ip}]:{port}\""),
    }
}

/// Parameters other than `for` a proxy may add, a quoted value holding
/// anything, escaped.
fn others() -> impl Strategy<Value = Vec<String>> {
    let value = prop_oneof![
        "[a-z0-9.]{1,8}",
        "\\PC{0,12}"
            .prop_map(|text| format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))),
    ];
    proptest::collection::vec(("proto|by|host|x-[a-z]{1,3}", value), 0..3).prop_map(|pairs| {
        pairs
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect()
    })
}

/// `sent`, with `entry` appended to its last line or on a line of its own.
fn behind(mut sent: Vec<String>, entry: &str, appended: bool) -> Vec<String> {
    match sent.pop() {
        Some(last) if appended => sent.push(format!("{last}, {entry}")),
        last => {
            sent.extend(last);
            sent.push(entry.to_string());
        }
    }
    sent
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// No header panics the parser, in either format.
    #[test]
    fn no_header_panics(lines in proptest::collection::vec(sent(), 0..4)) {
        for name in ["forwarded", "x-forwarded-for"] {
            let _ = read(name, &lines);
        }
    }

    /// Behind a proxy that writes RFC 7239, the client is the `for` of the
    /// proxy's element, whatever the client sent ahead of it and whatever
    /// the proxy's other parameters hold.
    #[test]
    fn the_proxys_forwarded_element_names_the_client(
        sent in proptest::collection::vec(sent(), 0..3),
        ip in any::<IpAddr>(),
        port in proptest::option::of(any::<u16>()),
        before in others(),
        after in others(),
        name in "[fF][oO][rR]",
        appended in any::<bool>(),
    ) {
        let mut pairs = before;
        pairs.push(format!("{name}={}", node(ip, port)));
        pairs.extend(after);
        let lines = behind(sent, &pairs.join(";"), appended);
        prop_assert_eq!(read("forwarded", &lines), Forwarded::Client(ip));
    }

    /// A proxy's element that names no address leaves the client unparsed:
    /// an address the client sent ahead of it never stands in.
    #[test]
    fn a_forwarded_element_without_an_address_is_unparsed(
        sent in proptest::collection::vec(sent(), 0..3),
        element in prop_oneof![
            Just("for=unknown"),
            Just("for=_hidden"),
            Just("for=\"_hidden:4711\""),
            Just("proto=https"),
            Just(""),
        ],
        appended in any::<bool>(),
    ) {
        let lines = behind(sent, element, appended);
        let got = read("forwarded", &lines);
        prop_assert!(matches!(got, Forwarded::Unparsed(_)), "{:?}", got);
    }

    /// Behind a proxy that writes an address list, the client is its last
    /// entry, whatever the client sent ahead of it.
    #[test]
    fn the_proxys_list_entry_names_the_client(
        sent in proptest::collection::vec(sent(), 0..3),
        ip in any::<IpAddr>(),
        port in proptest::option::of(any::<u16>()),
        appended in any::<bool>(),
    ) {
        let entry = match port {
            Some(port) => std::net::SocketAddr::new(ip, port).to_string(),
            None => ip.to_string(),
        };
        let lines = behind(sent, &entry, appended);
        prop_assert_eq!(
            read("x-forwarded-for", &lines),
            Forwarded::Client(ip)
        );
    }

    /// Behind trusted proxies, the client is the address the first of them
    /// wrote, whatever the client sent ahead of it and however many proxies
    /// follow, on the client's line or lines of their own.
    #[test]
    fn trusted_proxies_are_skipped(
        sent in proptest::collection::vec(sent(), 0..3),
        ip in any::<IpAddr>(),
        hops in proptest::collection::vec(cdn_address(), 0..4),
        rfc7239 in any::<bool>(),
        appended in any::<bool>(),
        own_lines in any::<bool>(),
    ) {
        let proxies = proxies();
        prop_assume!(!proxies.iter().any(|range| range.contains(ip)));
        let entry = |ip: IpAddr| if rfc7239 { format!("for={}", node(ip, None)) } else { ip.to_string() };
        let written: Vec<String> = std::iter::once(ip).chain(hops).map(entry).collect();
        let lines = if own_lines {
            let mut lines = behind(sent, &written[0], appended);
            lines.extend_from_slice(&written[1..]);
            lines
        } else {
            behind(sent, &written.join(", "), appended)
        };
        let name = if rfc7239 { "forwarded" } else { "x-forwarded-for" };
        let peer = IpAddr::from([127, 0, 0, 1]);
        prop_assert_eq!(client(&headers(name, &lines), name, peer, &proxies), Forwarded::Client(ip));
    }

    /// A connection from outside the trusted proxies is its own address,
    /// whatever its header says.
    #[test]
    fn an_untrusted_connection_is_its_own_address(
        lines in proptest::collection::vec(sent(), 0..3),
        peer in any::<IpAddr>(),
        rfc7239 in any::<bool>(),
    ) {
        let proxies = proxies();
        prop_assume!(!proxies.iter().any(|range| range.contains(peer)));
        let name = if rfc7239 { "forwarded" } else { "x-forwarded-for" };
        prop_assert_eq!(client(&headers(name, &lines), name, peer, &proxies), Forwarded::Untrusted);
    }
}
