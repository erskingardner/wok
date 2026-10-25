//! IP address ranges in CIDR notation, as `relay.trusted_proxies` lists
//! them.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// The addresses that share an address's leading `prefix_len` bits, written
/// `address/prefix_len`, or as a bare address for that address alone. An
/// IPv4-mapped IPv6 address is matched as its IPv4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IpRange {
    /// The first address of the range: the address with its other bits
    /// cleared.
    network: IpAddr,
    prefix_len: u8,
}

impl IpRange {
    /// Whether `ip` is in the range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            ip => ip,
        };
        masked(ip, self.prefix_len) == Some(self.network)
    }
}

/// `ip` with all but its leading `prefix_len` bits cleared; None when the
/// prefix is longer than the address.
fn masked(ip: IpAddr, prefix_len: u8) -> Option<IpAddr> {
    let prefix_len = u32::from(prefix_len);
    match ip {
        IpAddr::V4(v4) if prefix_len <= 32 => {
            let mask = u32::MAX.checked_shl(32 - prefix_len).unwrap_or(0);
            Some(IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask)))
        }
        IpAddr::V6(v6) if prefix_len <= 128 => {
            let mask = u128::MAX.checked_shl(128 - prefix_len).unwrap_or(0);
            Some(IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask)))
        }
        _ => None,
    }
}

impl FromStr for IpRange {
    type Err = String;

    fn from_str(range: &str) -> Result<Self, String> {
        let (address, prefix_len) = match range.split_once('/') {
            Some((address, prefix_len)) => (address, Some(prefix_len)),
            None => (range, None),
        };
        let address: IpAddr = address
            .parse()
            .map_err(|_| format!("{range:?} is not an IP address or a CIDR range"))?;
        if let IpAddr::V6(v6) = address {
            if v6.to_ipv4_mapped().is_some() {
                return Err(format!(
                    "{range:?} is an IPv4-mapped address: write it as IPv4"
                ));
            }
        }
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let prefix_len = match prefix_len {
            None => bits,
            Some(prefix_len) => prefix_len
                .parse::<u8>()
                .ok()
                .filter(|&prefix_len| prefix_len <= bits)
                .ok_or_else(|| format!("{range:?} needs a prefix length from 1 to {bits}"))?,
        };
        if prefix_len == 0 {
            return Err(format!(
                "{range:?} holds every address, so any client could name its own address"
            ));
        }
        let network = masked(address, prefix_len).expect("prefix fits the address");
        Ok(Self {
            network,
            prefix_len,
        })
    }
}

impl TryFrom<String> for IpRange {
    type Error = String;

    fn try_from(range: String) -> Result<Self, String> {
        range.parse()
    }
}

impl From<IpRange> for String {
    fn from(range: IpRange) -> Self {
        range.to_string()
    }
}

/// A bare address for a range of one address, as it is usually written.
impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = if self.network.is_ipv4() { 32 } else { 128 };
        if self.prefix_len == bits {
            write!(f, "{}", self.network)
        } else {
            write!(f, "{}/{}", self.network, self.prefix_len)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(text: &str) -> IpRange {
        text.parse().unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_range_holds_the_addresses_that_share_its_prefix() {
        let cdn = range("192.0.2.0/24");
        assert!(cdn.contains(ip("192.0.2.0")));
        assert!(cdn.contains(ip("192.0.2.255")));
        assert!(!cdn.contains(ip("192.0.3.0")));
        assert!(!cdn.contains(ip("2001:db8::1")));
        // An IPv4-mapped address is its IPv4 address.
        assert!(cdn.contains(ip("::ffff:192.0.2.10")));
        let v6 = range("2001:db8::/32");
        assert!(v6.contains(ip("2001:db8:ffff::1")));
        assert!(!v6.contains(ip("2001:db9::1")));
        assert!(!v6.contains(ip("192.0.2.10")));
        // A bare address is that address alone.
        assert!(range("127.0.0.1").contains(ip("127.0.0.1")));
        assert!(!range("127.0.0.1").contains(ip("127.0.0.2")));
        assert!(range("::1").contains(ip("::1")));
        assert!(range("10.0.0.0/1").contains(ip("127.255.255.255")));
        assert!(!range("10.0.0.0/1").contains(ip("128.0.0.0")));
    }

    #[test]
    fn a_range_is_written_from_its_first_address() {
        for (written, shown) in [
            ("192.0.2.77/24", "192.0.2.0/24"),
            ("127.0.0.1", "127.0.0.1"),
            ("127.0.0.1/32", "127.0.0.1"),
            ("2001:db8::1/32", "2001:db8::/32"),
            ("::1/128", "::1"),
        ] {
            assert_eq!(range(written).to_string(), shown);
        }
    }

    #[test]
    fn a_range_that_is_not_one_is_refused() {
        for (written, reason) in [
            ("0.0.0.0/0", "every address"),
            ("::/0", "every address"),
            ("10.0.0.0/33", "from 1 to 32"),
            ("2001:db8::/129", "from 1 to 128"),
            ("10.0.0.0/", "prefix length"),
            ("10.0.0.0/eight", "prefix length"),
            ("10.0.0.0/-8", "prefix length"),
            ("relay.example", "not an IP address"),
            ("10.0.0.0/8/8", "prefix length"),
            ("::ffff:10.0.0.0/104", "write it as IPv4"),
            ("", "not an IP address"),
        ] {
            let error = written.parse::<IpRange>().unwrap_err();
            assert!(error.contains(reason), "{written:?}: {error}");
        }
    }
}
