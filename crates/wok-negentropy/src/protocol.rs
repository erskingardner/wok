//! Negentropy protocol matching `external/negentropy/cpp/negentropy.h`.

use crate::encoding::{decode_varint, encode_varint, get_byte, get_bytes};
use crate::error::NegError;
use crate::storage::Storage;
use crate::types::{Bound, Item, Mode, FINGERPRINT_SIZE, ID_SIZE, MAX_U64, PROTOCOL_VERSION};

/// Decoded messages larger than this are rejected before any work. The relay
/// WS layer already bounds inbound payloads well below this; the cap protects
/// direct protocol users.
const MAX_RECONCILE_INPUT_BYTES: usize = 1024 * 1024;
/// Storage work one reconcile call may do, in B-tree descents: a lower-bound
/// search or an iteration is one, a fingerprint two (it reads the
/// accumulators left of both ends). Every range record costs at least one,
/// so without a ceiling a message of small records pins a worker (#254).
/// Past it, the reply answers the rest of the range with one fingerprint, as
/// the frame-size limit does, and the peer splits that in its next message:
/// a large message takes more rounds instead of being refused (#242). A
/// round that fills a 500,000-byte frame with splits does about 80,000.
const MAX_RECONCILE_WORK: usize = 65_536;

pub struct Negentropy<S> {
    storage: S,
    frame_size_limit: u64,
    is_initiator: bool,
    last_timestamp_in: u64,
    last_timestamp_out: u64,
    /// Storage work the current reconcile call has done, and its ceiling.
    work: usize,
    work_limit: usize,
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
            work: 0,
            work_limit: MAX_RECONCILE_WORK,
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
        self.work = 0;
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

        while !query.is_empty() {
            // Out of work: every range up to `prev_bound` has its answer, so
            // the rest goes back as one fingerprint, after the skip still owed
            // for ranges that matched. A message opens with at most one skip,
            // so its first open range always runs and each round progresses.
            if self.work >= self.work_limit {
                if skip {
                    full_output.extend(self.encode_bound(&prev_bound));
                    full_output.extend(encode_varint(Mode::Skip as u64));
                }
                let remaining = self.storage.fingerprint(prev_index, storage_size)?;
                full_output.extend(self.encode_bound(&Bound::timestamp(MAX_U64)));
                full_output.extend(encode_varint(Mode::Fingerprint as u64));
                full_output.extend_from_slice(&remaining);
                break;
            }
            let mut o = Vec::new();
            let curr_bound = self.decode_bound(&mut query)?;
            let mode = Mode::try_from(decode_varint(&mut query)?)?;
            let lower = prev_index;
            self.work += 1;
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
                self.work += 2;
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
                self.work += 1;
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
            self.work += 1;
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
                self.work += 2;
                let our_fp = self
                    .storage
                    .fingerprint(curr, curr + bucket_size as usize)?;
                curr += bucket_size as usize;
                let next_bound = if curr == upper {
                    upper_bound.clone()
                } else {
                    let mut prev_item = Item::default();
                    let mut curr_item = Item::default();
                    self.work += 1;
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

    fn id(set: u8, i: u64) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update([set]);
        h.update(i.to_le_bytes());
        h.finalize().into()
    }

    type Ids = std::collections::HashSet<Vec<u8>>;

    /// A client's and a relay's sets with `shared` items in common, and the
    /// ids only the client has and only the relay has.
    fn divergent(client: u64, relay: u64, shared: u64) -> (Vector, Vector, Ids, Ids) {
        let (mut c, mut r) = (Vector::new(), Vector::new());
        let (mut have, mut need) = (Ids::new(), Ids::new());
        for i in 0..shared {
            let ts = 1_600_000_000 + (i * 7_919) % 1_000_000;
            c.insert(ts, &id(0, i)).unwrap();
            r.insert(ts, &id(0, i)).unwrap();
        }
        for i in 0..client - shared {
            c.insert(1_600_000_000 + (i * 104_729) % 1_000_000, &id(1, i))
                .unwrap();
            have.insert(id(1, i).to_vec());
        }
        for i in 0..relay - shared {
            r.insert(1_600_000_000 + (i * 15_485_863) % 1_000_000, &id(2, i))
                .unwrap();
            need.insert(id(2, i).to_vec());
        }
        c.seal().unwrap();
        r.seal().unwrap();
        (c, r, have, need)
    }

    /// The range records of a message, as (encoded timestamp, mode).
    fn ranges(msg: &[u8]) -> Vec<(u64, Mode)> {
        let mut m = &msg[1..];
        let mut out = Vec::new();
        while !m.is_empty() {
            let ts = decode_varint(&mut m).unwrap();
            let len = decode_varint(&mut m).unwrap() as usize;
            get_bytes(&mut m, len).unwrap();
            let mode = Mode::try_from(decode_varint(&mut m).unwrap()).unwrap();
            match mode {
                Mode::Skip => {}
                Mode::Fingerprint => {
                    get_bytes(&mut m, FINGERPRINT_SIZE).unwrap();
                }
                Mode::IdList => {
                    let n = decode_varint(&mut m).unwrap() as usize;
                    get_bytes(&mut m, n * ID_SIZE).unwrap();
                }
            }
            out.push((ts, mode));
        }
        out
    }

    struct Synced {
        have: Ids,
        need: Ids,
        rounds: usize,
        /// The most ranges one message held, client's and relay's.
        client_ranges: usize,
        relay_ranges: usize,
    }

    /// Runs a sync to its end with the real protocol on both sides.
    fn sync(mut client: Negentropy<Vector>, mut relay: Negentropy<Vector>) -> Synced {
        let mut msg = client.initiate().unwrap();
        let (mut have, mut need) = (Vec::new(), Vec::new());
        let (mut client_ranges, mut relay_ranges) = (0, 0);
        for rounds in 1..=20_000 {
            client_ranges = client_ranges.max(ranges(&msg).len());
            let reply = relay.reconcile(&msg).unwrap();
            relay_ranges = relay_ranges.max(ranges(&reply).len());
            match client
                .reconcile_with_ids(&reply, &mut have, &mut need)
                .unwrap()
            {
                Some(next) => msg = next,
                None => {
                    return Synced {
                        have: have.into_iter().collect(),
                        need: need.into_iter().collect(),
                        rounds,
                        client_ranges,
                        relay_ranges,
                    }
                }
            }
        }
        panic!("sync did not finish");
    }

    /// #242: the relay answers with 500,000-byte frames, which hold far more
    /// than 4096 ranges. `wok sync`, at its default 60,000-byte frames, must
    /// read them, and the relay must read a client's at its own frame size.
    #[test]
    fn frame_size_messages_reconcile_both_ways() {
        let (c, r, have, need) = divergent(20_000, 200_000, 10_000);
        for client_frame in [60_000, 500_000] {
            let s = sync(
                Negentropy::new(c.clone(), client_frame).unwrap(),
                Negentropy::new(r.clone(), 500_000).unwrap(),
            );
            assert!(s.relay_ranges > 4096, "relay sent {}", s.relay_ranges);
            if client_frame == 500_000 {
                assert!(s.client_ranges > 4096, "client sent {}", s.client_ranges);
            }
            assert!(s.have == have && s.need == need, "frame {client_frame}");
        }
    }

    /// Counts storage work as the budget does, apart from it.
    struct Metered<'a> {
        inner: &'a mut Vector,
        work: usize,
    }

    impl Storage for Metered<'_> {
        fn size(&mut self) -> Result<u64, NegError> {
            self.inner.size()
        }
        fn get_item(&mut self, i: usize) -> Result<Item, NegError> {
            self.inner.get_item(i)
        }
        fn iterate<F: FnMut(&Item, usize) -> bool>(
            &mut self,
            begin: usize,
            end: usize,
            cb: F,
        ) -> Result<(), NegError> {
            self.work += 1;
            self.inner.iterate(begin, end, cb)
        }
        fn find_lower_bound(
            &mut self,
            begin: usize,
            end: usize,
            bound: &Bound,
        ) -> Result<usize, NegError> {
            self.work += 1;
            self.inner.find_lower_bound(begin, end, bound)
        }
        fn fingerprint(&mut self, begin: usize, end: usize) -> Result<Fingerprint, NegError> {
            self.work += 2;
            self.inner.fingerprint(begin, end)
        }
    }

    /// Fingerprint records for consecutive ranges `width` seconds wide, with
    /// the relay's own fingerprints or with ones that never match.
    fn fingerprints(relay: &mut Vector, width: u64, count: u64, matching: bool) -> Vec<u8> {
        let size = relay.size().unwrap() as usize;
        let mut msg = vec![PROTOCOL_VERSION];
        let mut lower = 0;
        for i in 1..=count {
            let bound = Bound::timestamp(1_600_000_000 + width * i);
            let upper = relay.find_lower_bound(lower, size, &bound).unwrap();
            let delta = if i == 1 { bound.item.timestamp } else { width };
            msg.extend(encode_varint(delta + 1));
            msg.extend([0, Mode::Fingerprint as u8]);
            if matching {
                msg.extend(relay.fingerprint(lower, upper).unwrap());
            } else {
                msg.extend([0xAA; FINGERPRINT_SIZE]);
            }
            lower = upper;
        }
        msg
    }

    /// Messages of cheap records, far past the old 4096-range cap, and #254's
    /// fingerprints that never match, cost one work budget and get a reply
    /// that still covers the whole range.
    #[test]
    fn crafted_messages_stop_at_the_work_budget() {
        // One item every 10 seconds on average.
        let (_, mut relay, _, _) = divergent(0, 100_000, 0);
        // About 1 MiB of 3-byte skips, one second apart.
        let mut skips = vec![PROTOCOL_VERSION];
        for i in 0..349_000u64 {
            skips.extend(encode_varint(if i == 0 { 1_600_000_001 } else { 2 }));
            skips.extend([0, Mode::Skip as u8]);
        }
        let matching = fingerprints(&mut relay, 20, 50_000, true);
        assert!(ranges(&skips).len() > 4096 && ranges(&matching).len() > 4096);
        // Ranges of about 40 items, each split in 16: the budget, not the
        // 500,000-byte frame, ends the reply.
        let bogus = fingerprints(&mut relay, 400, 2_500, false);
        for (name, msg) in [("skips", skips), ("matching", matching), ("bogus", bogus)] {
            let mut metered = Metered {
                inner: &mut relay,
                work: 0,
            };
            let reply = Negentropy::new(&mut metered, 500_000)
                .unwrap()
                .reconcile(&msg)
                .unwrap();
            // One record's split and the closing fingerprint may overshoot.
            assert!(
                metered.work <= MAX_RECONCILE_WORK + 52,
                "{name}: {}",
                metered.work
            );
            let last = *ranges(&reply).last().unwrap();
            assert_eq!(last, (0, Mode::Fingerprint), "{name}");
            // A client holding the relay's set finds nothing left to do, so
            // the reply's ranges, the closing one too, cover what they say.
            let mut client = Negentropy::new(relay.clone(), 0).unwrap();
            client.set_initiator();
            let (mut have, mut need) = (Vec::new(), Vec::new());
            let next = client
                .reconcile_with_ids(&reply, &mut have, &mut need)
                .unwrap();
            assert!(
                next.is_none() && have.is_empty() && need.is_empty(),
                "{name}"
            );
        }
    }

    /// Rounds the budget cuts short still find exactly the difference, with
    /// either side cut short and with or without a frame-size limit.
    #[test]
    fn rounds_cut_short_still_reconcile() {
        let (c, r, have, need) = divergent(3_000, 3_000, 1_500);
        let whole = sync(
            Negentropy::new(c.clone(), 0).unwrap(),
            Negentropy::new(r.clone(), 0).unwrap(),
        );
        for limit in [2, 9, 100, 1_000] {
            for frame in [0, 4096] {
                let mut client = Negentropy::new(c.clone(), frame).unwrap();
                let mut relay = Negentropy::new(r.clone(), frame).unwrap();
                client.work_limit = limit;
                relay.work_limit = limit;
                let s = sync(client, relay);
                assert!(
                    s.have == have && s.need == need,
                    "limit {limit} frame {frame}"
                );
                assert!(s.rounds > whole.rounds, "limit {limit} frame {frame}");
            }
        }
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
