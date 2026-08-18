//! NIP-45 HyperLogLog registers for mergeable COUNT responses.

use crate::NostrFilter;

/// NIP-45 fixes the precision at 8 bits: 256 one-byte registers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HyperLogLog {
    offset: usize,
    registers: [u8; 256],
}

impl HyperLogLog {
    pub fn for_filter(filter: &NostrFilter) -> Option<Self> {
        Some(Self {
            offset: offset_for_filter(filter)?,
            registers: [0; 256],
        })
    }

    pub fn add_pubkey(&mut self, pubkey: &[u8]) {
        let Some(window) = pubkey
            .get(self.offset..self.offset.saturating_add(8))
            .filter(|window| window.len() == 8)
        else {
            return;
        };
        let register = window[0] as usize;
        let mut value = 0u64;
        for byte in &window[1..] {
            value = (value << 8) | u64::from(*byte);
        }
        // `value` occupies the low 56 bits. Remove the eight padding zeroes
        // counted by u64::leading_zeros, then add one as specified by NIP-45.
        let rank = value.leading_zeros().saturating_sub(8).saturating_add(1) as u8;
        self.registers[register] = self.registers[register].max(rank);
    }

    pub fn encode_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(512);
        for register in self.registers {
            encoded.push(HEX[(register >> 4) as usize] as char);
            encoded.push(HEX[(register & 0x0f) as usize] as char);
        }
        encoded
    }

    #[cfg(test)]
    fn registers(&self) -> &[u8; 256] {
        &self.registers
    }
}

/// Canonical HLL requests count one target. Multiple tag names or target
/// values have ambiguous merge semantics, so callers deliberately omit HLL
/// for those shapes.
pub fn offset_for_filter(filter: &NostrFilter) -> Option<usize> {
    if !filter.and_tags.is_empty() || filter.tags.len() != 1 {
        return None;
    }
    let (tag, values) = filter.tags.first_key_value()?;
    if values.size() != 1 {
        return None;
    }
    let value = values.at(0);
    let seed: [u8; 32] = if matches!(tag, 'e' | 'p') {
        value.try_into().ok()?
    } else if value.len() == 64 {
        match std::str::from_utf8(value)
            .ok()
            .and_then(|hex| wok_event::from_lower_hex_exact(hex).ok())
        {
            Some(bytes) => bytes.try_into().ok()?,
            None => wok_event::sha256(value),
        }
    } else if let Some(pubkey) = std::str::from_utf8(value)
        .ok()
        .and_then(|address| wok_event::parse_a_tag(address).ok())
        .map(|(_, pubkey, _)| pubkey)
    {
        pubkey
    } else {
        wok_event::sha256(value)
    };
    Some(usize::from(seed[16] >> 4) + 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn filter(value: serde_json::Value) -> NostrFilter {
        NostrFilter::parse(&value, 500, 3, 16).unwrap()
    }

    #[test]
    fn offset_covers_hex_address_and_hashed_values() {
        let hex = format!("{}f{}", "0".repeat(32), "0".repeat(31));
        assert_eq!(offset_for_filter(&filter(json!({"#e":[hex]}))), Some(23));

        let pubkey = format!("{}a{}", "0".repeat(32), "0".repeat(31));
        let address = format!("30023:{pubkey}:profile");
        assert_eq!(
            offset_for_filter(&filter(json!({"#a":[address]}))),
            Some(18)
        );

        let seed = wok_event::sha256(b"arbitrary-target");
        assert_eq!(
            offset_for_filter(&filter(json!({"#t":["arbitrary-target"]}))),
            Some(usize::from(seed[16] >> 4) + 8)
        );
    }

    #[test]
    fn sketch_matches_the_fixed_precision_bit_rules() {
        let mut hll = HyperLogLog {
            offset: 8,
            registers: [0; 256],
        };
        let mut pubkey = [0u8; 32];
        hll.add_pubkey(&pubkey);
        assert_eq!(hll.registers()[0], 57);

        pubkey[8] = 7;
        pubkey[9] = 0x10;
        hll.add_pubkey(&pubkey);
        assert_eq!(hll.registers()[7], 4);
        assert_eq!(hll.encode_hex().len(), 512);
    }

    #[test]
    fn ambiguous_filter_shapes_do_not_get_a_sketch() {
        assert!(offset_for_filter(&filter(json!({"kinds":[7]}))).is_none());
        assert!(
            offset_for_filter(&filter(json!({"#e":["00".repeat(32), "11".repeat(32)]}))).is_none()
        );
        assert!(offset_for_filter(&filter(json!({
            "#e":["00".repeat(32)],
            "#p":["11".repeat(32)]
        })))
        .is_none());
        assert!(offset_for_filter(&filter(json!({
            "&p":["11".repeat(32)],
            "#p":["11".repeat(32)]
        })))
        .is_none());
    }
}
