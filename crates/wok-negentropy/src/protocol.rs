//! Negentropy protocol matching `external/negentropy/cpp/negentropy.h`.

use crate::encoding::{decode_varint, encode_varint, get_byte, get_bytes};
use crate::error::NegError;
use crate::storage::Storage;
use crate::types::{Bound, Item, Mode, FINGERPRINT_SIZE, ID_SIZE, MAX_U64, PROTOCOL_VERSION};

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
        let size = self.storage.size() as usize;
        output.extend(self.split_range(0, size, Bound::timestamp(MAX_U64)));
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

        let storage_size = self.storage.size() as usize;
        let mut prev_bound = Bound::default();
        let mut prev_index = 0usize;
        let mut skip = false;

        while !query.is_empty() {
            let mut o = Vec::new();
            let curr_bound = self.decode_bound(&mut query)?;
            let mode = Mode::try_from(decode_varint(&mut query)?)?;
            let lower = prev_index;
            let mut upper = self
                .storage
                .find_lower_bound(prev_index, storage_size, &curr_bound);

            if mode == Mode::Skip {
                skip = true;
            } else if mode == Mode::Fingerprint {
                let their_fp = get_bytes(&mut query, FINGERPRINT_SIZE)?;
                let our_fp = self.storage.fingerprint(lower, upper);
                if their_fp.as_slice() != our_fp.as_slice() {
                    if skip {
                        skip = false;
                        o.extend(self.encode_bound(&prev_bound));
                        o.extend(encode_varint(Mode::Skip as u64));
                    }
                    o.extend(self.split_range(lower, upper, curr_bound.clone()));
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
                    });
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
                    });
                    o.extend(self.encode_bound(&end_bound));
                    o.extend(encode_varint(Mode::IdList as u64));
                    o.extend(encode_varint(num_response_ids));
                    o.extend(response_ids);
                    full_output.extend(std::mem::take(&mut o));
                }
            }

            if self.exceeded_frame_size_limit(full_output.len() + o.len()) {
                let remaining = self.storage.fingerprint(upper, storage_size);
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

    fn split_range(&mut self, lower: usize, upper: usize, upper_bound: Bound) -> Vec<u8> {
        let mut o = Vec::new();
        let num_elems = (upper - lower) as u64;
        const BUCKETS: u64 = 16;
        if num_elems < BUCKETS * 2 {
            o.extend(self.encode_bound(&upper_bound));
            o.extend(encode_varint(Mode::IdList as u64));
            o.extend(encode_varint(num_elems));
            self.storage.iterate(lower, upper, |item, _| {
                o.extend_from_slice(item.get_id());
                true
            });
        } else {
            let items_per_bucket = num_elems / BUCKETS;
            let buckets_with_extra = num_elems % BUCKETS;
            let mut curr = lower;
            for i in 0..BUCKETS {
                let bucket_size = items_per_bucket + u64::from(i < buckets_with_extra);
                let our_fp = self.storage.fingerprint(curr, curr + bucket_size as usize);
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
                    });
                    get_minimal_bound(&prev_item, &curr_item)
                };
                o.extend(self.encode_bound(&next_bound));
                o.extend(encode_varint(Mode::Fingerprint as u64));
                o.extend_from_slice(&our_fp);
            }
        }
        o
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
        Bound::with_id_prefix(curr.timestamp, &curr.id[..shared + 1]).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
