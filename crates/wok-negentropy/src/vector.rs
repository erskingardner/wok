//! In-memory Vector storage matching `negentropy/storage/Vector.h`.

use crate::error::NegError;
use crate::storage::{Fingerprint, Storage};
use crate::types::{Accumulator, Bound, Item, ID_SIZE};

#[derive(Clone, Debug, Default)]
pub struct Vector {
    items: Vec<Item>,
    sealed: bool,
}

impl Vector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, created_at: u64, id: &[u8]) -> Result<(), NegError> {
        if self.sealed {
            return Err(NegError::msg("already sealed"));
        }
        if id.len() != ID_SIZE {
            return Err(NegError::msg("bad id size for added item"));
        }
        self.items.push(Item::new(created_at, id)?);
        Ok(())
    }

    pub fn seal(&mut self) -> Result<(), NegError> {
        if self.sealed {
            return Err(NegError::msg("already sealed"));
        }
        self.sealed = true;
        self.items.sort();
        for i in 1..self.items.len() {
            if self.items[i - 1] == self.items[i] {
                return Err(NegError::msg("duplicate item inserted"));
            }
        }
        Ok(())
    }

    pub fn unseal(&mut self) {
        self.sealed = false;
    }

    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    fn check_sealed(&self) -> Result<(), NegError> {
        if !self.sealed {
            return Err(NegError::msg("not sealed"));
        }
        Ok(())
    }

    fn check_bounds(&self, begin: usize, end: usize) -> Result<(), NegError> {
        if begin > end || end > self.items.len() {
            return Err(NegError::msg("bad range"));
        }
        Ok(())
    }
}

impl Storage for Vector {
    fn size(&mut self) -> u64 {
        self.items.len() as u64
    }

    fn get_item(&mut self, i: usize) -> Item {
        self.items[i]
    }

    fn iterate<F: FnMut(&Item, usize) -> bool>(&mut self, begin: usize, end: usize, mut cb: F) {
        for i in begin..end {
            if !cb(&self.items[i], i) {
                break;
            }
        }
    }

    fn find_lower_bound(&mut self, begin: usize, end: usize, bound: &Bound) -> usize {
        begin + self.items[begin..end].partition_point(|item| *item < bound.item)
    }

    fn fingerprint(&mut self, begin: usize, end: usize) -> Fingerprint {
        let mut out = Accumulator::default();
        for item in &self.items[begin..end] {
            out.add_item(item);
        }
        out.get_fingerprint((end - begin) as u64)
    }
}

impl Vector {
    pub fn size_checked(&self) -> Result<u64, NegError> {
        self.check_sealed()?;
        Ok(self.items.len() as u64)
    }

    pub fn find_lower_bound_checked(
        &self,
        begin: usize,
        end: usize,
        bound: &Bound,
    ) -> Result<usize, NegError> {
        self.check_sealed()?;
        self.check_bounds(begin, end)?;
        Ok(begin + self.items[begin..end].partition_point(|item| *item < bound.item))
    }
}

/// SubRange wrapper matching `negentropy/storage/SubRange.h`.
pub struct SubRange<'a, S: Storage> {
    base: &'a mut S,
    sub_begin: usize,
    sub_size: usize,
}

impl<'a, S: Storage> SubRange<'a, S> {
    pub fn new(base: &'a mut S, lower: &Bound, upper: &Bound) -> Self {
        let base_size = base.size() as usize;
        let sub_begin = if *lower == Bound::timestamp(0) {
            0
        } else {
            base.find_lower_bound(0, base_size, lower)
        };
        let mut sub_end = if *upper == Bound::timestamp(crate::types::MAX_U64) {
            base_size
        } else {
            base.find_lower_bound(sub_begin, base_size, upper)
        };
        if sub_end != base_size && Bound::from_item(base.get_item(sub_end)) == *upper {
            sub_end += 1;
        }
        Self {
            base,
            sub_begin,
            sub_size: sub_end - sub_begin,
        }
    }
}

impl<S: Storage> Storage for SubRange<'_, S> {
    fn size(&mut self) -> u64 {
        self.sub_size as u64
    }

    fn get_item(&mut self, i: usize) -> Item {
        self.base.get_item(self.sub_begin + i)
    }

    fn iterate<F: FnMut(&Item, usize) -> bool>(&mut self, begin: usize, end: usize, mut cb: F) {
        let sub_begin = self.sub_begin;
        self.base
            .iterate(sub_begin + begin, sub_begin + end, |item, index| {
                cb(item, index - sub_begin)
            });
    }

    fn find_lower_bound(&mut self, begin: usize, end: usize, bound: &Bound) -> usize {
        let sub_begin = self.sub_begin;
        let sub_size = self.sub_size;
        (self
            .base
            .find_lower_bound(sub_begin + begin, sub_begin + end, bound)
            .saturating_sub(sub_begin))
        .min(sub_size)
    }

    fn fingerprint(&mut self, begin: usize, end: usize) -> Fingerprint {
        let sub_begin = self.sub_begin;
        self.base.fingerprint(sub_begin + begin, sub_begin + end)
    }
}
