//! LMDB-backed BTree matching `negentropy/storage/BTreeLMDB.h`.
//!
//! Keys are `tree_id.to_ne_bytes() || node_id.to_ne_bytes()`. The DBI is opened
//! with `MDB_REVERSEKEY` by the schema layer.

use crate::btree::{BTreeBackend, BTreeCore, Node, NodePtr, NODE_SIZE};
use crate::error::NegError;
use crate::types::Accumulator;
use std::collections::BTreeMap;
use wok_db::{RoTxn, RwTxn};

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct MetaData {
    root_node_id: u64,
    next_node_id: u64,
}

impl MetaData {
    fn from_bytes(b: &[u8]) -> Result<Self, NegError> {
        if b.len() < 16 {
            return Err(NegError::msg("negentropy metadata too short"));
        }
        Ok(Self {
            root_node_id: u64::from_ne_bytes(b[0..8].try_into().unwrap()),
            next_node_id: u64::from_ne_bytes(b[8..16].try_into().unwrap()),
        })
    }

    fn as_bytes(&self) -> [u8; 16] {
        let mut o = [0u8; 16];
        o[0..8].copy_from_slice(&self.root_node_id.to_ne_bytes());
        o[8..16].copy_from_slice(&self.next_node_id.to_ne_bytes());
        o
    }
}

fn tree_key(tree_id: u64, node_id: u64) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[0..8].copy_from_slice(&tree_id.to_ne_bytes());
    k[8..16].copy_from_slice(&node_id.to_ne_bytes());
    k
}

/// Slots in a read-only tree's cache of node summaries, 48 KiB in all. The
/// lookups of one message pass at most a few hundred siblings that later
/// ones pass again, on the path's left at each level.
const SUMMARY_SLOTS: usize = 1024;

pub struct LmdbRoBackend<'a, 'env> {
    txn: &'a RoTxn<'env>,
    tree_id: u64,
    meta: MetaData,
    /// Summaries read so far as (node id, accum_count, accum), each in the
    /// slot its node id selects; empty until the first. The snapshot never
    /// changes a node, and a message's lookups move left to right, so most
    /// siblings they pass are here: an LMDB lookup for each one again made
    /// up most of a crafted message's cost (#254).
    summaries: Vec<(u64, u64, Accumulator)>,
}

impl<'a, 'env> LmdbRoBackend<'a, 'env> {
    pub fn new(txn: &'a RoTxn<'env>, tree_id: u64) -> Result<Self, NegError> {
        let dbi = txn.env().dbis().negentropy;
        let meta = match txn.get(dbi, &tree_key(tree_id, 0))? {
            Some(v) => MetaData::from_bytes(v)?,
            None => MetaData {
                root_node_id: 0,
                next_node_id: 1,
            },
        };
        Ok(Self {
            txn,
            tree_id,
            meta,
            summaries: Vec::new(),
        })
    }

    /// Node `node_id`'s bytes, borrowed from the transaction's mmap.
    fn raw(&self, node_id: u64) -> Result<&[u8], NegError> {
        let dbi = self.txn.env().dbis().negentropy;
        self.txn
            .get(dbi, &tree_key(self.tree_id, node_id))?
            .ok_or_else(|| NegError::msg("couldn't find node"))
    }
}

impl BTreeBackend for LmdbRoBackend<'_, '_> {
    fn get_node_read(&mut self, node_id: u64) -> Result<NodePtr, NegError> {
        if node_id == 0 {
            return Ok(NodePtr {
                node: Node::default(),
                node_id: 0,
                exists: false,
            });
        }
        Ok(NodePtr {
            node: Node::from_bytes(self.raw(node_id)?)?,
            node_id,
            exists: true,
        })
    }

    fn get_node_summary(&mut self, node_id: u64) -> Result<(u64, Accumulator), NegError> {
        if node_id == 0 {
            return Ok((0, Accumulator::default()));
        }
        if self.summaries.is_empty() {
            self.summaries = vec![(0, 0, Accumulator::default()); SUMMARY_SLOTS];
        }
        let slot = node_id as usize % SUMMARY_SLOTS;
        if self.summaries[slot].0 != node_id {
            let (accum_count, accum) = Node::summary_from_bytes(self.raw(node_id)?)?;
            self.summaries[slot] = (node_id, accum_count, accum);
        }
        let (_, accum_count, accum) = self.summaries[slot];
        Ok((accum_count, accum))
    }

    fn get_node_write(&mut self, _node_id: u64) -> Result<NodePtr, NegError> {
        Err(NegError::msg("write on read-only negentropy tree"))
    }

    fn put_node(&mut self, _node_id: u64, _node: &Node) -> Result<(), NegError> {
        Err(NegError::msg("write on read-only negentropy tree"))
    }

    fn make_node(&mut self) -> Result<u64, NegError> {
        Err(NegError::msg("write on read-only negentropy tree"))
    }

    fn delete_node(&mut self, _node_id: u64) -> Result<(), NegError> {
        Err(NegError::msg("write on read-only negentropy tree"))
    }

    fn root_node_id(&self) -> u64 {
        self.meta.root_node_id
    }

    fn set_root_node_id(&mut self, _id: u64) {}
}

pub struct LmdbRwBackend<'a, 'env> {
    txn: &'a mut RwTxn<'env>,
    tree_id: u64,
    meta: MetaData,
    orig_meta: MetaData,
    dirty: BTreeMap<u64, Node>,
}

impl<'a, 'env> LmdbRwBackend<'a, 'env> {
    pub fn new(txn: &'a mut RwTxn<'env>, tree_id: u64) -> Result<Self, NegError> {
        let dbi = txn.env().dbis().negentropy;
        let meta = match txn.get(dbi, &tree_key(tree_id, 0))? {
            Some(v) => MetaData::from_bytes(v)?,
            None => MetaData {
                root_node_id: 0,
                next_node_id: 1,
            },
        };
        Ok(Self {
            txn,
            tree_id,
            orig_meta: meta,
            meta,
            dirty: BTreeMap::new(),
        })
    }

    pub fn flush(&mut self) -> Result<(), NegError> {
        let dbi = self.txn.env().dbis().negentropy;
        let dirty = std::mem::take(&mut self.dirty);
        for (node_id, node) in &dirty {
            self.txn.put(
                dbi,
                &tree_key(self.tree_id, *node_id),
                &node.encode_bytes(),
                0,
            )?;
        }
        if self.meta != self.orig_meta {
            self.txn
                .put(dbi, &tree_key(self.tree_id, 0), &self.meta.as_bytes(), 0)?;
            self.orig_meta = self.meta;
        }
        Ok(())
    }
}

impl Drop for LmdbRwBackend<'_, '_> {
    fn drop(&mut self) {
        // C++'s BTreeLMDB dtor flushes too; at least don't lose the error
        // silently when callers forgot the explicit flush.
        if let Err(e) = self.flush() {
            tracing::error!("negentropy store drop-flush failed: {e}");
        }
    }
}

impl BTreeBackend for LmdbRwBackend<'_, '_> {
    fn get_node_read(&mut self, node_id: u64) -> Result<NodePtr, NegError> {
        if node_id == 0 {
            return Ok(NodePtr {
                node: Node::default(),
                node_id: 0,
                exists: false,
            });
        }
        if let Some(n) = self.dirty.get(&node_id) {
            return Ok(NodePtr {
                node: *n,
                node_id,
                exists: true,
            });
        }
        let dbi = self.txn.env().dbis().negentropy;
        let Some(raw) = self.txn.get(dbi, &tree_key(self.tree_id, node_id))? else {
            return Err(NegError::msg("couldn't find node"));
        };
        if raw.len() != NODE_SIZE {
            return Err(NegError::msg("couldn't find node"));
        }
        Ok(NodePtr {
            node: Node::from_bytes(raw)?,
            node_id,
            exists: true,
        })
    }

    fn get_node_summary(&mut self, node_id: u64) -> Result<(u64, Accumulator), NegError> {
        if node_id == 0 {
            return Ok((0, Accumulator::default()));
        }
        if let Some(n) = self.dirty.get(&node_id) {
            return Ok((n.accum_count, n.accum));
        }
        let dbi = self.txn.env().dbis().negentropy;
        let Some(raw) = self.txn.get(dbi, &tree_key(self.tree_id, node_id))? else {
            return Err(NegError::msg("couldn't find node"));
        };
        Node::summary_from_bytes(raw)
    }

    fn get_node_write(&mut self, node_id: u64) -> Result<NodePtr, NegError> {
        if node_id == 0 {
            return Ok(NodePtr {
                node: Node::default(),
                node_id: 0,
                exists: false,
            });
        }
        if let Some(n) = self.dirty.get(&node_id) {
            return Ok(NodePtr {
                node: *n,
                node_id,
                exists: true,
            });
        }
        let dbi = self.txn.env().dbis().negentropy;
        let Some(raw) = self.txn.get(dbi, &tree_key(self.tree_id, node_id))? else {
            return Err(NegError::msg("couldn't find node"));
        };
        let node = Node::from_bytes(raw)?;
        self.dirty.insert(node_id, node);
        Ok(NodePtr {
            node,
            node_id,
            exists: true,
        })
    }

    fn put_node(&mut self, node_id: u64, node: &Node) -> Result<(), NegError> {
        self.dirty.insert(node_id, *node);
        Ok(())
    }

    fn make_node(&mut self) -> Result<u64, NegError> {
        let id = self.meta.next_node_id;
        self.meta.next_node_id += 1;
        self.dirty.insert(id, Node::default());
        Ok(id)
    }

    fn delete_node(&mut self, node_id: u64) -> Result<(), NegError> {
        if node_id == 0 {
            return Err(NegError::msg("can't delete metadata"));
        }
        self.dirty.remove(&node_id);
        let dbi = self.txn.env().dbis().negentropy;
        self.txn.del(dbi, &tree_key(self.tree_id, node_id), None)?;
        Ok(())
    }

    fn root_node_id(&self) -> u64 {
        self.meta.root_node_id
    }

    fn set_root_node_id(&mut self, id: u64) {
        self.meta.root_node_id = id;
    }
}

pub type BTreeLmdbRo<'a, 'env> = BTreeCore<LmdbRoBackend<'a, 'env>>;
pub type BTreeLmdbRw<'a, 'env> = BTreeCore<LmdbRwBackend<'a, 'env>>;

pub fn open_ro<'a, 'env>(
    txn: &'a RoTxn<'env>,
    tree_id: u64,
) -> Result<BTreeLmdbRo<'a, 'env>, NegError> {
    Ok(BTreeCore::new(LmdbRoBackend::new(txn, tree_id)?))
}

pub fn open_rw<'a, 'env>(
    txn: &'a mut RwTxn<'env>,
    tree_id: u64,
) -> Result<BTreeLmdbRw<'a, 'env>, NegError> {
    Ok(BTreeCore::new(LmdbRwBackend::new(txn, tree_id)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use crate::types::Bound;
    use crate::vector::Vector;
    use sha2::{Digest, Sha256};
    use wok_db::{Env, EnvOptions};

    fn item(i: u64) -> (u64, [u8; 32]) {
        let id = Sha256::digest(i.to_le_bytes()).into();
        (1_600_000_000 + (i * 7_919) % 5_000, id)
    }

    /// `tree` answers every read as `vector`, holding the same items, does.
    fn same_as(tree: &mut impl Storage, vector: &mut Vector) {
        let size = vector.size().unwrap() as usize;
        assert_eq!(tree.size().unwrap(), size as u64);
        for begin in (0..size).step_by(size / 200 + 1) {
            for end in [begin, begin + 1, begin + 45, begin + 3_001, size] {
                let end = end.min(size);
                assert_eq!(
                    tree.fingerprint(begin, end).unwrap(),
                    vector.fingerprint(begin, end).unwrap(),
                    "fingerprint {begin}..{end}"
                );
            }
            let item = vector.get_item(begin).unwrap();
            assert_eq!(tree.get_item(begin).unwrap(), item);
            for bound in [Bound::timestamp(item.timestamp), Bound::from_item(item)] {
                for lower in [0, begin / 2] {
                    assert_eq!(
                        tree.find_lower_bound(lower, size, &bound).unwrap(),
                        vector.find_lower_bound(lower, size, &bound).unwrap(),
                    );
                }
            }
            let end = (begin + 100).min(size);
            let mut seen = Vec::new();
            tree.iterate(begin, end, |item, i| {
                seen.push((*item, i));
                true
            })
            .unwrap();
            let mut expected = Vec::new();
            vector
                .iterate(begin, end, |item, i| {
                    expected.push((*item, i));
                    true
                })
                .unwrap();
            assert!(seen == expected, "iterate {begin}..{end}");
        }
    }

    /// Lookups read the summaries of the nodes they pass in place, and still
    /// answer as a `Vector` of the same items does: from a snapshot whose
    /// nodes outnumber the summary cache's slots, so summaries displace each
    /// other, and from nodes a write transaction changed but has not flushed.
    #[test]
    fn tree_reads_match_a_vector_of_the_same_items() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        let (committed, total) = (120_000, 124_000);
        let vector = |n: u64| {
            let mut vector = Vector::new();
            for i in 0..n {
                let (ts, id) = item(i);
                vector.insert(ts, &id).unwrap();
            }
            vector.seal().unwrap();
            vector
        };
        let mut txn = env.begin_rw().unwrap();
        {
            let mut tree = open_rw(&mut txn, 1).unwrap();
            for i in 0..committed {
                let (ts, id) = item(i);
                tree.insert(ts, &id).unwrap();
            }
            tree.backend.flush().unwrap();
        }
        txn.commit().unwrap();
        {
            let txn = env.begin_ro().unwrap();
            let mut tree = open_ro(&txn, 1).unwrap();
            assert!(tree.backend.meta.next_node_id > 2 * SUMMARY_SLOTS as u64);
            // Deep enough that lookups pass nodes on more than one level.
            let root = tree.backend.get_node_read(tree.backend.root_node_id());
            let child = root.unwrap().node.items[0].node_id;
            assert_ne!(
                tree.backend.get_node_read(child).unwrap().node.items[0].node_id,
                0
            );
            same_as(&mut tree, &mut vector(committed));
        }
        let mut txn = env.begin_rw().unwrap();
        let mut tree = open_rw(&mut txn, 1).unwrap();
        for i in committed..total {
            let (ts, id) = item(i);
            tree.insert(ts, &id).unwrap();
        }
        assert!(!tree.backend.dirty.is_empty());
        same_as(&mut tree, &mut vector(total));
    }
}
