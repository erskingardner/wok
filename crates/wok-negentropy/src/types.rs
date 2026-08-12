//! Types matching `external/negentropy/cpp/negentropy/types.h`.

use crate::encoding::encode_varint;
use sha2::{Digest, Sha256};

pub const ID_SIZE: usize = 32;
pub const FINGERPRINT_SIZE: usize = 16;
pub const PROTOCOL_VERSION: u8 = 0x61;
pub const MAX_U64: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Skip = 0,
    Fingerprint = 1,
    IdList = 2,
}

impl TryFrom<u64> for Mode {
    type Error = crate::error::NegError;
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Skip),
            1 => Ok(Self::Fingerprint),
            2 => Ok(Self::IdList),
            _ => Err(crate::error::NegError::msg("unexpected mode")),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Item {
    pub timestamp: u64,
    pub id: [u8; ID_SIZE],
}

impl Default for Item {
    fn default() -> Self {
        Self {
            timestamp: 0,
            id: [0u8; ID_SIZE],
        }
    }
}

impl Item {
    pub fn new(timestamp: u64, id: &[u8]) -> Result<Self, crate::error::NegError> {
        if id.len() != ID_SIZE {
            return Err(crate::error::NegError::msg("bad id size for Item"));
        }
        let mut out = Self {
            timestamp,
            id: [0u8; ID_SIZE],
        };
        out.id.copy_from_slice(id);
        Ok(out)
    }

    pub fn get_id(&self) -> &[u8] {
        &self.id
    }
}

impl PartialEq for Item {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp && self.id == other.id
    }
}

impl Eq for Item {}

impl PartialOrd for Item {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Item {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.id.cmp(&other.id))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bound {
    pub item: Item,
    pub id_len: usize,
}

impl Bound {
    pub fn timestamp(timestamp: u64) -> Self {
        Self {
            item: Item {
                timestamp,
                id: [0u8; ID_SIZE],
            },
            id_len: 0,
        }
    }

    pub fn with_id_prefix(timestamp: u64, id: &[u8]) -> Result<Self, crate::error::NegError> {
        if id.len() > ID_SIZE {
            return Err(crate::error::NegError::msg("bad id size for Bound"));
        }
        let mut item = Item {
            timestamp,
            id: [0u8; ID_SIZE],
        };
        item.id[..id.len()].copy_from_slice(id);
        Ok(Self {
            item,
            id_len: id.len(),
        })
    }

    pub fn from_item(item: Item) -> Self {
        Self {
            item,
            id_len: ID_SIZE,
        }
    }
}

impl Default for Bound {
    fn default() -> Self {
        Self::timestamp(0)
    }
}

impl PartialOrd for Bound {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Bound {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.item.cmp(&other.item)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Accumulator {
    pub buf: [u8; ID_SIZE],
}

impl Default for Accumulator {
    fn default() -> Self {
        Self {
            buf: [0u8; ID_SIZE],
        }
    }
}

impl Accumulator {
    pub fn set_to_zero(&mut self) {
        self.buf = [0u8; ID_SIZE];
    }

    pub fn add_item(&mut self, item: &Item) {
        self.add_bytes(&item.id);
    }

    pub fn add_acc(&mut self, other: &Accumulator) {
        self.add_bytes(&other.buf);
    }

    pub fn add_bytes(&mut self, other: &[u8; ID_SIZE]) {
        let mut curr_carry = 0u64;
        for i in 0..4 {
            let orig = u64::from_le_bytes(self.buf[i * 8..i * 8 + 8].try_into().unwrap());
            let other_v = u64::from_le_bytes(other[i * 8..i * 8 + 8].try_into().unwrap());
            let (n1, c1) = orig.overflowing_add(curr_carry);
            let (n2, c2) = n1.overflowing_add(other_v);
            self.buf[i * 8..i * 8 + 8].copy_from_slice(&n2.to_le_bytes());
            curr_carry = u64::from(c1 || c2);
        }
    }

    pub fn negate(&mut self) {
        for b in &mut self.buf {
            *b = !*b;
        }
        let mut one = Accumulator::default();
        one.buf[0] = 1;
        let one_buf = one.buf;
        self.add_bytes(&one_buf);
    }

    pub fn sub_bytes(&mut self, other: &[u8; ID_SIZE]) {
        let mut neg = Accumulator { buf: *other };
        neg.negate();
        let buf = neg.buf;
        self.add_bytes(&buf);
    }

    pub fn sub_item(&mut self, item: &Item) {
        self.sub_bytes(&item.id);
    }

    pub fn sub_acc(&mut self, other: &Accumulator) {
        self.sub_bytes(&other.buf);
    }

    pub fn get_fingerprint(&self, n: u64) -> [u8; FINGERPRINT_SIZE] {
        let mut input = Vec::with_capacity(ID_SIZE + 16);
        input.extend_from_slice(&self.buf);
        input.extend_from_slice(&encode_varint(n));
        let hash = Sha256::digest(&input);
        let mut out = [0u8; FINGERPRINT_SIZE];
        out.copy_from_slice(&hash[..FINGERPRINT_SIZE]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_order() {
        let a = Item::new(1, &[1u8; 32]).unwrap();
        let b = Item::new(2, &[0u8; 32]).unwrap();
        assert!(a < b);
        let c = Item::new(1, &[2u8; 32]).unwrap();
        assert!(a < c);
    }

    #[test]
    fn accum_add_sub() {
        let mut a = Accumulator::default();
        let item = Item::new(1, &[7u8; 32]).unwrap();
        a.add_item(&item);
        a.sub_item(&item);
        assert_eq!(a.buf, [0u8; 32]);
    }
}
