use crate::types::{Bound, Item, FINGERPRINT_SIZE};

pub type Fingerprint = [u8; FINGERPRINT_SIZE];

pub trait Storage {
    fn size(&mut self) -> u64;
    fn get_item(&mut self, i: usize) -> Item;
    fn iterate<F: FnMut(&Item, usize) -> bool>(&mut self, begin: usize, end: usize, cb: F);
    fn find_lower_bound(&mut self, begin: usize, end: usize, bound: &Bound) -> usize;
    fn fingerprint(&mut self, begin: usize, end: usize) -> Fingerprint;
}
