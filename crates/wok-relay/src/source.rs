use std::net::IpAddr;

/// Transport metadata for one relay connection, kept separate from the
/// authenticated Nostr identity established by NIP-42.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TransportSource {
    Ip(IpAddr),
    Unix,
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
        }
    }

    pub const fn plugin_type(&self) -> &'static str {
        match self {
            Self::Ip(IpAddr::V4(_)) => "IP4",
            Self::Ip(IpAddr::V6(_)) => "IP6",
            Self::Unix => "unix",
        }
    }

    pub fn plugin_info(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::Unix => String::new(),
        }
    }

    pub const fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(*ip),
            Self::Unix => None,
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
