use crate::error::NegError;
use crate::types::{Bound, Item, FINGERPRINT_SIZE};

pub type Fingerprint = [u8; FINGERPRINT_SIZE];

/// All methods are fallible like the C++ reference (which throws): a storage
/// error must abort the reconcile session rather than substitute a default
/// value and silently produce wrong results.
pub trait Storage {
    fn size(&mut self) -> Result<u64, NegError>;
    fn get_item(&mut self, i: usize) -> Result<Item, NegError>;
    fn iterate<F: FnMut(&Item, usize) -> bool>(
        &mut self,
        begin: usize,
        end: usize,
        cb: F,
    ) -> Result<(), NegError>;
    fn find_lower_bound(
        &mut self,
        begin: usize,
        end: usize,
        bound: &Bound,
    ) -> Result<usize, NegError>;
    fn fingerprint(&mut self, begin: usize, end: usize) -> Result<Fingerprint, NegError>;
}

/// Reconciliation operates on borrowed views (no per-message clones).
impl<S: Storage> Storage for &mut S {
    fn size(&mut self) -> Result<u64, NegError> {
        (**self).size()
    }
    fn get_item(&mut self, i: usize) -> Result<Item, NegError> {
        (**self).get_item(i)
    }
    fn iterate<F: FnMut(&Item, usize) -> bool>(
        &mut self,
        begin: usize,
        end: usize,
        cb: F,
    ) -> Result<(), NegError> {
        (**self).iterate(begin, end, cb)
    }
    fn find_lower_bound(
        &mut self,
        begin: usize,
        end: usize,
        bound: &Bound,
    ) -> Result<usize, NegError> {
        (**self).find_lower_bound(begin, end, bound)
    }
    fn fingerprint(&mut self, begin: usize, end: usize) -> Result<Fingerprint, NegError> {
        (**self).fingerprint(begin, end)
    }
}
