//! Minimal bech32 (NIP-19 `npub`) decoding, matching C++ `decodeBech32Simple`:
//! plain bech32 only (bech32m rejected), 5->8 bit conversion without padding,
//! exactly 32 bytes of payload.

use crate::EventError;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn polymod(vals: &[u8]) -> u32 {
    let mut chk = 1u32;
    for &v in vals {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn charset_rev(c: u8) -> Result<u8, EventError> {
    CHARSET
        .iter()
        .position(|&x| x == c)
        .map(|p| p as u8)
        .ok_or_else(|| EventError::msg("invalid bech32 character"))
}

/// Decode a NIP-19 `npub1...` string to its 32-byte pubkey.
pub fn decode_npub(input: &str) -> Result<[u8; 32], EventError> {
    let err = || EventError::msg("invalid bech32");
    if input.len() > 5000 {
        return Err(err());
    }
    let bytes = input.as_bytes();
    let has_lower = bytes.iter().any(|b| b.is_ascii_lowercase());
    let has_upper = bytes.iter().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(err());
    }
    let lower = input.to_ascii_lowercase();
    let lb = lower.as_bytes();
    let pos = lb.iter().rposition(|&c| c == b'1').ok_or_else(err)?;
    if pos == 0 || pos + 7 > lb.len() {
        return Err(err());
    }
    let hrp = &lower[..pos];
    if hrp != "npub" {
        return Err(err());
    }
    let mut vals: Vec<u8> = Vec::with_capacity(8 + lb.len());
    for &c in hrp.as_bytes() {
        vals.push(c >> 5);
    }
    vals.push(0);
    for &c in hrp.as_bytes() {
        vals.push(c & 31);
    }
    for &c in &lb[pos + 1..] {
        vals.push(charset_rev(c)?);
    }
    if polymod(&vals) != 1 {
        // Note: bech32m (polymod 0x2bc830a3) is rejected here, like C++.
        return Err(err());
    }
    let payload = &vals[2 * hrp.len() + 1..vals.len() - 6];
    // convertbits 5 -> 8, no padding
    let mut out = Vec::with_capacity(payload.len() * 5 / 8);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &v in payload {
        acc = (acc << 5) | v as u32;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits >= 5 || ((acc << (8 - bits)) & 0xff) != 0 {
        return Err(EventError::msg("convertbits failed"));
    }
    let arr: [u8; 32] = out
        .try_into()
        .map_err(|_| EventError::msg("unexpected size from bech32"))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_npub() {
        let pk =
            decode_npub("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6").unwrap();
        assert_eq!(
            hex::encode(pk),
            "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode_npub("npub1qqqqqqqqqqqq").is_err());
        assert!(decode_npub("").is_err());
        assert!(
            decode_npub("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w7").is_err()
        );
    }
}
