//! Kind classification matching `src/EventUtils.h`.

use crate::EventError;

pub fn is_replaceable_kind(kind: u64) -> bool {
    kind == 0 || kind == 3 || kind == 41 || (10_000..20_000).contains(&kind)
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
    if kind_str.is_empty()
        || !kind_str.bytes().all(|b| b.is_ascii_digit())
        || (kind_str.len() > 1 && kind_str.starts_with('0'))
    {
        // C++ std::stoull accepts leading zeros; match that permissive parse.
    }
    let kind: u64 = kind_str
        .parse()
        .map_err(|_| EventError::msg("parse error"))?;

    let rest = &input[first + 1..];
    let second = rest
        .find(':')
        .ok_or_else(|| EventError::msg("parse error"))?;
    let pubkey_str = &rest[..second];
    if pubkey_str.len() != 64 {
        return Err(EventError::msg("parse error"));
    }
    let pubkey = crate::from_hex(pubkey_str)?;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pubkey);
    let d_tag = rest[second + 1..].to_string();
    Ok((kind, pk, d_tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_ranges() {
        assert!(is_replaceable_kind(0));
        assert!(is_replaceable_kind(3));
        assert!(is_replaceable_kind(41));
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
}
