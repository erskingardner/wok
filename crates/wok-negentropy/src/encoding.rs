//! Negentropy varint and byte parsing matching `external/negentropy/cpp/negentropy/encoding.h`.

use crate::error::NegError;

pub fn get_byte(encoded: &mut &[u8]) -> Result<u8, NegError> {
    if encoded.is_empty() {
        return Err(NegError::msg("parse ends prematurely"));
    }
    let b = encoded[0];
    *encoded = &encoded[1..];
    Ok(b)
}

pub fn get_bytes(encoded: &mut &[u8], n: usize) -> Result<Vec<u8>, NegError> {
    if encoded.len() < n {
        return Err(NegError::msg("parse ends prematurely"));
    }
    let out = encoded[..n].to_vec();
    *encoded = &encoded[n..];
    Ok(out)
}

pub fn decode_varint(encoded: &mut &[u8]) -> Result<u64, NegError> {
    let mut res = 0u64;
    loop {
        if encoded.is_empty() {
            return Err(NegError::msg("premature end of varint"));
        }
        let byte = encoded[0] as u64;
        *encoded = &encoded[1..];
        res = (res << 7) | (byte & 0b0111_1111);
        if (byte & 0b1000_0000) == 0 {
            break;
        }
    }
    Ok(res)
}

pub fn encode_varint(mut n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![0];
    }
    let mut o = Vec::new();
    while n != 0 {
        o.push((n & 0x7F) as u8);
        n >>= 7;
    }
    o.reverse();
    let last = o.len() - 1;
    for b in o.iter_mut().take(last) {
        *b |= 0x80;
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for n in [0u64, 1, 127, 128, 255, 300, 16_384, u64::MAX] {
            let enc = encode_varint(n);
            let mut s = enc.as_slice();
            assert_eq!(decode_varint(&mut s).unwrap(), n, "n={n}");
            assert!(s.is_empty());
        }
    }

    #[test]
    fn varint_128_matches_cpp() {
        assert_eq!(encode_varint(128), vec![0x81, 0x00]);
    }
}
