//! Negentropy protocol matching `external/negentropy/cpp/negentropy.h`.

use crate::encoding::{decode_varint, encode_varint, get_byte, get_bytes};
use crate::error::NegError;
use crate::storage::Storage;
use crate::types::{Bound, Item, Mode, FINGERPRINT_SIZE, ID_SIZE, MAX_U64, PROTOCOL_VERSION};

/// Decoded messages larger than this are rejected before any work. The relay
/// WS layer already bounds inbound payloads well below this; the cap protects
/// direct protocol users.
const MAX_RECONCILE_INPUT_BYTES: usize = 1024 * 1024;
/// Maximum bound/mode records processed per reconcile round. Each one can
/// cost a B-tree descent, so unbounded counts let a pathological message pin
/// a worker; legitimate splits produce a small multiple of 16 per round.
const MAX_BOUNDS_PER_ROUND: usize = 4096;

pub struct Negentropy<S> {
    storage: S,
    frame_size_limit: u64,
    is_initiator: bool,
    last_timestamp_in: u64,
    last_timestamp_out: u64,
}

impl<S: Storage> Negentropy<S> {
    pub fn new(storage: S, frame_size_limit: u64) -> Result<Self, NegError> {
        if frame_size_limit != 0 && frame_size_limit < 4096 {
            return Err(NegError::msg("frameSizeLimit too small"));
        }
        Ok(Self {
            storage,
            frame_size_limit,
            is_initiator: false,
            last_timestamp_in: 0,
            last_timestamp_out: 0,
        })
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    pub fn initiate(&mut self) -> Result<Vec<u8>, NegError> {
        if self.is_initiator {
            return Err(NegError::msg("already initiated"));
        }
        self.is_initiator = true;
        let mut output = vec![PROTOCOL_VERSION];
        let size = self.storage.size()? as usize;
        output.extend(self.split_range(0, size, Bound::timestamp(MAX_U64))?);
        Ok(output)
    }

    pub fn set_initiator(&mut self) {
        self.is_initiator = true;
    }

    pub fn reconcile(&mut self, query: &[u8]) -> Result<Vec<u8>, NegError> {
        if self.is_initiator {
            return Err(NegError::msg("initiator not asking for have/need IDs"));
        }
        let mut have = Vec::new();
        let mut need = Vec::new();
        self.reconcile_aux(query, &mut have, &mut need)
    }

    pub fn reconcile_with_ids(
        &mut self,
        query: &[u8],
        have_ids: &mut Vec<Vec<u8>>,
        need_ids: &mut Vec<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, NegError> {
        if !self.is_initiator {
            return Err(NegError::msg("non-initiator asking for have/need IDs"));
        }
        let output = self.reconcile_aux(query, have_ids, need_ids)?;
        if output.len() == 1 {
            Ok(None)
        } else {
            Ok(Some(output))
        }
    }

    fn reconcile_aux(
        &mut self,
        query: &[u8],
        have_ids: &mut Vec<Vec<u8>>,
        need_ids: &mut Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, NegError> {
        if query.len() > MAX_RECONCILE_INPUT_BYTES {
            return Err(NegError::msg("negentropy message too large"));
        }
        self.last_timestamp_in = 0;
        self.last_timestamp_out = 0;
        let mut full_output = vec![PROTOCOL_VERSION];
        let mut query = query;
        let protocol_version = get_byte(&mut query)?;
        if !(0x60..=0x6F).contains(&protocol_version) {
            return Err(NegError::msg("invalid negentropy protocol version byte"));
        }
        if protocol_version != PROTOCOL_VERSION {
            if self.is_initiator {
                return Err(NegError::msg(format!(
                    "unsupported negentropy protocol version requested{}",
                    protocol_version - 0x60
                )));
            }
            return Ok(full_output);
        }

        let storage_size = self.storage.size()? as usize;
        let mut prev_bound = Bound::default();
        let mut prev_index = 0usize;
        let mut skip = false;
        let mut bounds_seen = 0usize;

        while !query.is_empty() {
            bounds_seen += 1;
            if bounds_seen > MAX_BOUNDS_PER_ROUND {
                return Err(NegError::msg("negentropy message has too many bounds"));
            }
            let mut o = Vec::new();
            let curr_bound = self.decode_bound(&mut query)?;
            let mode = Mode::try_from(decode_varint(&mut query)?)?;
            let lower = prev_index;
            let mut upper = self
                .storage
                .find_lower_bound(prev_index, storage_size, &curr_bound)?;
            // Non-monotonic bound sequences: error out like C++ (its
            // fingerprint range check throws) instead of wrapping upper-lower.
            if upper < prev_index {
                return Err(NegError::msg("negentropy bounds out of order"));
            }

            if mode == Mode::Skip {
                skip = true;
            } else if mode == Mode::Fingerprint {
                let their_fp = get_bytes(&mut query, FINGERPRINT_SIZE)?;
                let our_fp = self.storage.fingerprint(lower, upper)?;
                if their_fp.as_slice() != our_fp.as_slice() {
                    if skip {
                        skip = false;
                        o.extend(self.encode_bound(&prev_bound));
                        o.extend(encode_varint(Mode::Skip as u64));
                    }
                    o.extend(self.split_range(lower, upper, curr_bound.clone())?);
                } else {
                    skip = true;
                }
            } else if mode == Mode::IdList {
                let num_ids = decode_varint(&mut query)?;
                let mut their_elems = std::collections::HashSet::new();
                for _ in 0..num_ids {
                    let e = get_bytes(&mut query, ID_SIZE)?;
                    if self.is_initiator {
                        their_elems.insert(e);
                    }
                }
                if self.is_initiator {
                    skip = true;
                    self.storage.iterate(lower, upper, |item, _| {
                        let k = item.get_id().to_vec();
                        if !their_elems.remove(&k) {
                            have_ids.push(k);
                        }
                        true
                    })?;
                    for k in their_elems {
                        need_ids.push(k);
                    }
                } else {
                    if skip {
                        skip = false;
                        o.extend(self.encode_bound(&prev_bound));
                        o.extend(encode_varint(Mode::Skip as u64));
                    }
                    let mut response_ids = Vec::new();
                    let mut num_response_ids = 0u64;
                    let mut end_bound = curr_bound.clone();
                    let frame_limit = self.frame_size_limit;
                    let full_len = full_output.len();
                    self.storage.iterate(lower, upper, |item, index| {
                        if frame_limit != 0
                            && (full_len + response_ids.len()) as u64
                                > frame_limit.saturating_sub(200)
                        {
                            end_bound = Bound::from_item(*item);
                            upper = index;
                            return false;
                        }
                        response_ids.extend_from_slice(item.get_id());
                        num_response_ids += 1;
                        true
                    })?;
                    o.extend(self.encode_bound(&end_bound));
                    o.extend(encode_varint(Mode::IdList as u64));
                    o.extend(encode_varint(num_response_ids));
                    o.extend(response_ids);
                    full_output.extend(std::mem::take(&mut o));
                }
            }

            if self.exceeded_frame_size_limit(full_output.len() + o.len()) {
                let remaining = self.storage.fingerprint(upper, storage_size)?;
                full_output.extend(self.encode_bound(&Bound::timestamp(MAX_U64)));
                full_output.extend(encode_varint(Mode::Fingerprint as u64));
                full_output.extend_from_slice(&remaining);
                break;
            } else {
                full_output.extend(o);
            }
            prev_index = upper;
            prev_bound = curr_bound;
        }
        Ok(full_output)
    }

    fn split_range(
        &mut self,
        lower: usize,
        upper: usize,
        upper_bound: Bound,
    ) -> Result<Vec<u8>, NegError> {
        let mut o = Vec::new();
        let Some(num_elems) = upper.checked_sub(lower).map(|n| n as u64) else {
            return Err(NegError::msg("negentropy bounds out of order"));
        };
        const BUCKETS: u64 = 16;
        if num_elems < BUCKETS * 2 {
            o.extend(self.encode_bound(&upper_bound));
            o.extend(encode_varint(Mode::IdList as u64));
            o.extend(encode_varint(num_elems));
            self.storage.iterate(lower, upper, |item, _| {
                o.extend_from_slice(item.get_id());
                true
            })?;
        } else {
            let items_per_bucket = num_elems / BUCKETS;
            let buckets_with_extra = num_elems % BUCKETS;
            let mut curr = lower;
            for i in 0..BUCKETS {
                let bucket_size = items_per_bucket + u64::from(i < buckets_with_extra);
                let our_fp = self
                    .storage
                    .fingerprint(curr, curr + bucket_size as usize)?;
                curr += bucket_size as usize;
                let next_bound = if curr == upper {
                    upper_bound.clone()
                } else {
                    let mut prev_item = Item::default();
                    let mut curr_item = Item::default();
                    self.storage.iterate(curr - 1, curr + 1, |item, index| {
                        if index == curr - 1 {
                            prev_item = *item;
                        } else {
                            curr_item = *item;
                        }
                        true
                    })?;
                    get_minimal_bound(&prev_item, &curr_item)
                };
                o.extend(self.encode_bound(&next_bound));
                o.extend(encode_varint(Mode::Fingerprint as u64));
                o.extend_from_slice(&our_fp);
            }
        }
        Ok(o)
    }

    fn exceeded_frame_size_limit(&self, n: usize) -> bool {
        self.frame_size_limit != 0 && n as u64 > self.frame_size_limit.saturating_sub(200)
    }

    fn decode_timestamp_in(&mut self, encoded: &mut &[u8]) -> Result<u64, NegError> {
        let mut timestamp = decode_varint(encoded)?;
        timestamp = if timestamp == 0 {
            MAX_U64
        } else {
            timestamp - 1
        };
        timestamp = timestamp.saturating_add(self.last_timestamp_in);
        if timestamp < self.last_timestamp_in {
            timestamp = MAX_U64;
        }
        self.last_timestamp_in = timestamp;
        Ok(timestamp)
    }

    fn decode_bound(&mut self, encoded: &mut &[u8]) -> Result<Bound, NegError> {
        let timestamp = self.decode_timestamp_in(encoded)?;
        let len = decode_varint(encoded)? as usize;
        let id = get_bytes(encoded, len)?;
        Bound::with_id_prefix(timestamp, &id)
    }

    fn encode_timestamp_out(&mut self, timestamp: u64) -> Vec<u8> {
        if timestamp == MAX_U64 {
            self.last_timestamp_out = MAX_U64;
            return encode_varint(0);
        }
        let delta = timestamp.saturating_sub(self.last_timestamp_out);
        self.last_timestamp_out = timestamp;
        encode_varint(delta + 1)
    }

    fn encode_bound(&mut self, bound: &Bound) -> Vec<u8> {
        let mut output = self.encode_timestamp_out(bound.item.timestamp);
        output.extend(encode_varint(bound.id_len as u64));
        output.extend_from_slice(&bound.item.id[..bound.id_len]);
        output
    }
}

fn get_minimal_bound(prev: &Item, curr: &Item) -> Bound {
    if curr.timestamp != prev.timestamp {
        Bound::timestamp(curr.timestamp)
    } else {
        let mut shared = 0usize;
        while shared < ID_SIZE && curr.id[shared] == prev.id[shared] {
            shared += 1;
        }
        // shared+1 can only exceed ID_SIZE for duplicate items, which sealed
        // storage never contains; fall back to a timestamp-only bound (C++
        // substr clamps) rather than panicking.
        Bound::with_id_prefix(curr.timestamp, &curr.id[..(shared + 1).min(ID_SIZE)])
            .unwrap_or_else(|_| Bound::timestamp(curr.timestamp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Fingerprint;
    use crate::vector::Vector;

    fn item(ts: u64, b: u8) -> (u64, [u8; 32]) {
        (ts, [b; 32])
    }

    #[test]
    fn empty_reconcile() {
        let mut v = Vector::new();
        v.seal().unwrap();
        let mut client = Negentropy::new(v.clone(), 0).unwrap();
        let init = client.initiate().unwrap();
        let mut server = Negentropy::new(v, 0).unwrap();
        let resp = server.reconcile(&init).unwrap();
        let mut have = Vec::new();
        let mut need = Vec::new();
        let next = client
            .reconcile_with_ids(&resp, &mut have, &mut need)
            .unwrap();
        assert!(next.is_none());
        assert!(have.is_empty());
        assert!(need.is_empty());
    }

    #[test]
    fn client_needs_server_item() {
        let mut client_store = Vector::new();
        client_store.seal().unwrap();
        let mut server_store = Vector::new();
        let (ts, id) = item(10, 9);
        server_store.insert(ts, &id).unwrap();
        server_store.seal().unwrap();

        let mut client = Negentropy::new(client_store, 0).unwrap();
        let init = client.initiate().unwrap();
        let mut server = Negentropy::new(server_store, 0).unwrap();
        let resp = server.reconcile(&init).unwrap();
        let mut have = Vec::new();
        let mut need = Vec::new();
        client
            .reconcile_with_ids(&resp, &mut have, &mut need)
            .unwrap();
        assert!(have.is_empty());
        assert_eq!(need.len(), 1);
        assert_eq!(need[0], id);
    }

    /// Storage whose lower-bound answers walk backwards (a corrupt tree).
    struct RegressiveStorage {
        calls: usize,
    }

    impl Storage for RegressiveStorage {
        fn size(&mut self) -> Result<u64, NegError> {
            Ok(100)
        }
        fn get_item(&mut self, i: usize) -> Result<Item, NegError> {
            Ok(Item::new(i as u64, &[0; 32]).unwrap())
        }
        fn iterate<F: FnMut(&Item, usize) -> bool>(
            &mut self,
            begin: usize,
            end: usize,
            mut cb: F,
        ) -> Result<(), NegError> {
            for i in begin..end {
                if !cb(&Item::new(i as u64, &[0; 32]).unwrap(), i) {
                    break;
                }
            }
            Ok(())
        }
        fn find_lower_bound(
            &mut self,
            begin: usize,
            _end: usize,
            _bound: &Bound,
        ) -> Result<usize, NegError> {
            self.calls += 1;
            // Legit first answer, then below the requested `begin`.
            Ok(if self.calls == 1 {
                begin + 5
            } else {
                begin - 1
            })
        }
        fn fingerprint(&mut self, _begin: usize, _end: usize) -> Result<Fingerprint, NegError> {
            Ok([0; FINGERPRINT_SIZE])
        }
    }

    fn two_bound_query() -> Vec<u8> {
        // version, then two (timestamp 10, idlen 0) Skip bounds.
        let mut q = vec![PROTOCOL_VERSION];
        for _ in 0..2 {
            q.extend(encode_varint(11)); // timestamp 10 (encoded + 1)
            q.extend(encode_varint(0)); // no id prefix
            q.extend(encode_varint(Mode::Skip as u64));
        }
        q
    }

    #[test]
    fn non_monotonic_bounds_are_rejected() {
        let mut server = Negentropy::new(RegressiveStorage { calls: 0 }, 0).unwrap();
        let err = server.reconcile(&two_bound_query()).unwrap_err();
        assert!(err.to_string().contains("out of order"), "{err}");
    }

    /// Storage that fails mid-reconcile; the error must propagate, not be
    /// substituted with a default value.
    struct FailingStorage;

    impl Storage for FailingStorage {
        fn size(&mut self) -> Result<u64, NegError> {
            Ok(1)
        }
        fn get_item(&mut self, _i: usize) -> Result<Item, NegError> {
            Err(NegError::msg("storage gone"))
        }
        fn iterate<F: FnMut(&Item, usize) -> bool>(
            &mut self,
            _begin: usize,
            _end: usize,
            _cb: F,
        ) -> Result<(), NegError> {
            Err(NegError::msg("storage gone"))
        }
        fn find_lower_bound(
            &mut self,
            _begin: usize,
            _end: usize,
            _bound: &Bound,
        ) -> Result<usize, NegError> {
            Err(NegError::msg("storage gone"))
        }
        fn fingerprint(&mut self, _begin: usize, _end: usize) -> Result<Fingerprint, NegError> {
            Err(NegError::msg("storage gone"))
        }
    }

    #[test]
    fn storage_errors_abort_the_reconcile() {
        let mut server = Negentropy::new(FailingStorage, 0).unwrap();
        let err = server.reconcile(&two_bound_query()).unwrap_err();
        assert!(err.to_string().contains("storage gone"), "{err}");
        assert!(Negentropy::new(FailingStorage, 0)
            .unwrap()
            .initiate()
            .is_err());
    }

    #[test]
    fn too_many_bounds_are_rejected() {
        let mut q = vec![PROTOCOL_VERSION];
        for i in 0..(MAX_BOUNDS_PER_ROUND + 1) {
            q.extend(encode_varint(i as u64 + 2)); // increasing timestamps
            q.extend(encode_varint(0));
            q.extend(encode_varint(Mode::Skip as u64));
        }
        let mut v = Vector::new();
        v.seal().unwrap();
        let mut server = Negentropy::new(v, 0).unwrap();
        let err = server.reconcile(&q).unwrap_err();
        assert!(err.to_string().contains("too many bounds"), "{err}");
    }

    #[test]
    fn oversize_messages_are_rejected() {
        let q = vec![PROTOCOL_VERSION; MAX_RECONCILE_INPUT_BYTES + 1];
        let mut v = Vector::new();
        v.seal().unwrap();
        let mut server = Negentropy::new(v, 0).unwrap();
        let err = server.reconcile(&q).unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }
}
