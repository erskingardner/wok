//! Kind classification following pinned NIP-01.

use crate::EventError;

/// NIP-01 replaceable kinds: 0, 3 and 10000 <= n < 20000. Kind 41 (NIP-28
/// channel metadata) is regular, because each channel is named by an `e` tag;
/// the pinned strfry `src/EventUtils.h` replaces it per author.
pub fn is_replaceable_kind(kind: u64) -> bool {
    kind == 0 || kind == 3 || (10_000..20_000).contains(&kind)
}

pub fn is_param_replaceable_kind(kind: u64) -> bool {
    (30_000..40_000).contains(&kind)
}

pub fn is_ephemeral_kind(kind: u64) -> bool {
    (20_000..30_000).contains(&kind)
}

/// Parse an `a` tag: `kind:pubkey_hex:d-tag`.
///
/// Returns `(kind, pubkey_raw_32, d_tag)`.
pub fn parse_a_tag(input: &str) -> Result<(u64, [u8; 32], String), EventError> {
    let first = input
        .find(':')
        .ok_or_else(|| EventError::msg("parse error"))?;
    let kind_str = &input[..first];
    if kind_str.is_empty() || !kind_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(EventError::msg("parse error"));
    }
    let kind = kind_str
        .parse::<u64>()
        .map_err(|_| EventError::msg("parse error"))?;
    if kind > u16::MAX as u64 {
        return Err(EventError::msg("parse error"));
    }

    let rest = &input[first + 1..];
    let second = rest
        .find(':')
        .ok_or_else(|| EventError::msg("parse error"))?;
    let pubkey_str = &rest[..second];
    if pubkey_str.len() != 64 {
        return Err(EventError::msg("parse error"));
    }
    let pubkey = crate::from_lower_hex_exact(pubkey_str)?;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pubkey);
    let d_tag = rest[second + 1..].to_string();
    Ok((kind, pk, d_tag))
}

/// Parse an `a` tag like [`parse_a_tag`], with the kind also written in
/// canonical decimal, without leading zeros. Wok tombstones an address by the
/// hash of its canonical spelling, so a deletion naming `030000:<pubkey>:<d>`
/// would delete the stored versions but not refuse later ones.
pub fn parse_canonical_a_tag(input: &str) -> Result<(u64, [u8; 32], String), EventError> {
    let address = parse_a_tag(input)?;
    if input.starts_with('0') && !input.starts_with("0:") {
        return Err(EventError::msg("a tag kind has leading zeros"));
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_ranges() {
        assert!(is_replaceable_kind(0));
        assert!(is_replaceable_kind(3));
        assert!(!is_replaceable_kind(41));
        assert!(is_replaceable_kind(10_000));
        assert!(!is_replaceable_kind(20_000));
        assert!(is_param_replaceable_kind(30_000));
        assert!(!is_param_replaceable_kind(40_000));
        assert!(is_ephemeral_kind(20_000));
        assert!(!is_ephemeral_kind(30_000));
    }

    #[test]
    fn a_tag_roundtrip() {
        let pk = "aa".repeat(32);
        let (kind, pubkey, d) = parse_a_tag(&format!("30000:{pk}:hello")).unwrap();
        assert_eq!(kind, 30_000);
        assert_eq!(hex::encode(pubkey), pk);
        assert_eq!(d, "hello");
    }

    #[test]
    fn a_tag_empty_d() {
        let pk = "bb".repeat(32);
        let (kind, _, d) = parse_a_tag(&format!("30023:{pk}:")).unwrap();
        assert_eq!(kind, 30023);
        assert_eq!(d, "");
    }

    #[test]
    fn a_tag_kind_and_pubkey_are_strict_nip01_values() {
        let pk = "aa".repeat(32);
        assert!(parse_a_tag(&format!("+30023:{pk}:")).is_err());
        assert!(parse_a_tag(&format!(" 30023:{pk}:")).is_err());
        assert!(parse_a_tag(&format!("65536:{pk}:")).is_err());
        assert!(parse_a_tag(&format!("30023:{}:", pk.to_uppercase())).is_err());
    }

    #[test]
    fn canonical_a_tag_kinds_have_no_leading_zeros() {
        let pk = "aa".repeat(32);
        for address in [
            format!("0:{pk}:"),
            format!("10002:{pk}:"),
            format!("30023:{pk}:d"),
        ] {
            assert_eq!(
                parse_canonical_a_tag(&address).unwrap(),
                parse_a_tag(&address).unwrap()
            );
        }
        for address in [
            format!("00:{pk}:"),
            format!("010002:{pk}:"),
            format!("030023:{pk}:d"),
        ] {
            assert!(parse_a_tag(&address).is_ok());
            assert!(parse_canonical_a_tag(&address).is_err(), "{address}");
        }
        assert!(parse_canonical_a_tag(&format!("+30023:{pk}:")).is_err());
    }
}
