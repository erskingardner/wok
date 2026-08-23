use std::net::IpAddr;

/// Transport metadata for one relay connection.
///
/// A FIPS node key is an abuse/logging principal only. It is deliberately a
/// separate variant from authenticated Nostr identity, which is established
/// exclusively by NIP-42 inside the relay protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TransportSource {
    Ip(IpAddr),
    Unix,
    Fips { public_key: [u8; 32], port: u16 },
}

impl TransportSource {
    pub fn ip_address(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map_or(Self::Ip(IpAddr::V6(ip)), |ip| Self::Ip(IpAddr::V4(ip))),
            ip => Self::Ip(ip),
        }
    }

    pub const fn transport(&self) -> &'static str {
        match self {
            Self::Ip(_) => "websocket",
            Self::Unix => "unix",
            Self::Fips { .. } => "fips",
        }
    }

    pub const fn plugin_type(&self) -> &'static str {
        match self {
            Self::Ip(IpAddr::V4(_)) => "IP4",
            Self::Ip(IpAddr::V6(_)) => "IP6",
            Self::Unix => "unix",
            Self::Fips { .. } => "fips",
        }
    }

    pub fn plugin_info(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::Unix => String::new(),
            Self::Fips { public_key, port } => {
                format!("{}:{port}", hex::encode(public_key))
            }
        }
    }

    pub const fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(*ip),
            Self::Unix | Self::Fips { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_ipv6_is_normalized_for_moderation_and_plugins() {
        let source = TransportSource::ip_address("::ffff:203.0.113.7".parse().unwrap());
        assert_eq!(source.plugin_type(), "IP4");
        assert_eq!(source.plugin_info(), "203.0.113.7");
    }
}
