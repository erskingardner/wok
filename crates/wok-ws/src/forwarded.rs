//! The client address a reverse proxy passes in `relay.real_ip_header`.
//! Every per-address budget and NIP-86 IP block keys on it.

use std::net::{IpAddr, SocketAddr};

/// The client a request's `relay.real_ip_header` names.
#[derive(Debug, PartialEq)]
pub enum Forwarded {
    /// The request has no such header.
    Absent,
    Client(IpAddr),
    /// The header's last entry, which is not an address.
    Unparsed(String),
}

/// The client in the last entry of a forwarded-address header, the one the
/// proxy in front of Wok wrote: a proxy that appends to the client's own
/// header, or adds its own line after it, leaves the client's entries in
/// front. The header's lines form one comma-separated list (RFC 9110
/// §5.3), and an entry may carry a port.
pub fn client(headers: &hyper::HeaderMap, name: &str) -> Forwarded {
    let Some(line) = headers.get_all(name).iter().next_back() else {
        return Forwarded::Absent;
    };
    let line = String::from_utf8_lossy(line.as_bytes());
    let entry = line.rsplit(',').next().unwrap_or_default().trim();
    entry
        .parse::<IpAddr>()
        .or_else(|_| entry.parse::<SocketAddr>().map(|addr| addr.ip()))
        .map_or_else(
            |_| Forwarded::Unparsed(entry.to_string()),
            Forwarded::Client,
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forwarded(lines: &[&str]) -> Forwarded {
        let mut headers = hyper::HeaderMap::new();
        for line in lines {
            headers.append(
                "x-forwarded-for",
                hyper::header::HeaderValue::from_str(line).unwrap(),
            );
        }
        client(&headers, "x-forwarded-for")
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
        let unparsed = |entry: &str| Forwarded::Unparsed(entry.to_string());
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
}
