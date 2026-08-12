//! LMDB-backed BTree matching `negentropy/storage/BTreeLMDB.h`.
//!
//! Keys are `tree_id.to_ne_bytes() || node_id.to_ne_bytes()`. The DBI is opened
//! with `MDB_REVERSEKEY` by the schema layer.

use crate::btree::{BTreeBackend, BTreeCore, Node, NodePtr, NODE_SIZE};
use crate::error::NegError;
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

pub struct LmdbRoBackend<'a, 'env> {
    txn: &'a RoTxn<'env>,
    tree_id: u64,
    meta: MetaData,
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
        Ok(Self { txn, tree_id, meta })
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
        let dbi = self.txn.env().dbis().negentropy;
        let Some(raw) = self.txn.get(dbi, &tree_key(self.tree_id, node_id))? else {
            return Err(NegError::msg("couldn't find node"));
        };
        Ok(NodePtr {
            node: Node::from_bytes(raw)?,
            node_id,
            exists: true,
        })
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
            self.txn
                .put(dbi, &tree_key(self.tree_id, *node_id), node.as_bytes(), 0)?;
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
        let _ = self.flush();
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
