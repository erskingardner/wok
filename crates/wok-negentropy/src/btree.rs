//! Persistent B-tree matching `negentropy/storage/btree/core.h`.
//!
//! Node encoding remains byte-compatible with C++ strfry on little-endian
//! hosts, but fields are encoded explicitly instead of copying Rust struct
//! memory. This removes layout, padding, alignment, and validity assumptions
//! from the persistent-data boundary.

#![allow(clippy::field_reassign_with_default)]

use crate::error::NegError;
use crate::storage::{Fingerprint, Storage};
use crate::types::{Accumulator, Bound, Item};

pub const MIN_ITEMS: usize = 30;
pub const REBALANCE_THRESHOLD: usize = 60;
pub const MAX_ITEMS: usize = 80;

#[derive(Clone, Copy, Default)]
pub struct Key {
    pub item: Item,
    pub node_id: u64,
}

impl Key {
    fn set_to_zero(&mut self) {
        *self = Self {
            item: Item::default(),
            node_id: 0,
        };
    }
}

#[derive(Clone, Copy)]
pub struct Node {
    pub num_items: u64,
    pub accum_count: u64,
    pub next_sibling: u64,
    pub prev_sibling: u64,
    pub accum: Accumulator,
    pub items: [Key; MAX_ITEMS + 1],
}

const HEADER_SIZE: usize = 4 * std::mem::size_of::<u64>();
const ACCUMULATOR_SIZE: usize = 32;
const ITEM_SIZE: usize = std::mem::size_of::<u64>() + 32;
const KEY_SIZE: usize = ITEM_SIZE + std::mem::size_of::<u64>();
pub const NODE_SIZE: usize = HEADER_SIZE + ACCUMULATOR_SIZE + (MAX_ITEMS + 1) * KEY_SIZE;

impl Default for Node {
    fn default() -> Self {
        Self {
            num_items: 0,
            accum_count: 0,
            next_sibling: 0,
            prev_sibling: 0,
            accum: Accumulator::default(),
            items: [Key::default(); MAX_ITEMS + 1],
        }
    }
}

impl Node {
    pub fn encode_bytes(&self) -> [u8; NODE_SIZE] {
        let mut bytes = [0u8; NODE_SIZE];
        let mut offset = 0;
        for value in [
            self.num_items,
            self.accum_count,
            self.next_sibling,
            self.prev_sibling,
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
            offset += 8;
        }
        bytes[offset..offset + ACCUMULATOR_SIZE].copy_from_slice(&self.accum.buf);
        offset += ACCUMULATOR_SIZE;
        for key in &self.items {
            bytes[offset..offset + 8].copy_from_slice(&key.item.timestamp.to_ne_bytes());
            offset += 8;
            bytes[offset..offset + 32].copy_from_slice(&key.item.id);
            offset += 32;
            bytes[offset..offset + 8].copy_from_slice(&key.node_id.to_ne_bytes());
            offset += 8;
        }
        debug_assert_eq!(offset, NODE_SIZE);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NegError> {
        if bytes.len() != NODE_SIZE {
            return Err(NegError::msg(format!(
                "negentropy node size {} != {NODE_SIZE}",
                bytes.len()
            )));
        }
        let mut offset = 0;
        let mut read_u64 = || {
            let value = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
            offset += 8;
            value
        };
        let num_items = read_u64();
        let accum_count = read_u64();
        let next_sibling = read_u64();
        let prev_sibling = read_u64();
        // Zero-item nodes are never persisted (erase deletes them) and larger
        // counts are impossible: both indicate crafted/corrupt data at rest.
        if num_items == 0 || num_items > MAX_ITEMS as u64 {
            return Err(NegError::msg(format!(
                "negentropy node item count {num_items} out of range 1..={MAX_ITEMS}"
            )));
        }
        let mut accum = crate::types::Accumulator::default();
        accum
            .buf
            .copy_from_slice(&bytes[offset..offset + ACCUMULATOR_SIZE]);
        offset += ACCUMULATOR_SIZE;
        let mut items = [Key::default(); MAX_ITEMS + 1];
        for key in &mut items {
            key.item.timestamp = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
            offset += 8;
            key.item.id.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;
            key.node_id = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
            offset += 8;
        }
        debug_assert_eq!(offset, NODE_SIZE);
        Ok(Node {
            num_items,
            accum_count,
            next_sibling,
            prev_sibling,
            accum,
            items,
        })
    }
}

#[cfg(test)]
mod encoding_tests {
    use super::*;

    #[test]
    fn explicit_node_encoding_roundtrips_and_keeps_cpp_size() {
        assert_eq!(NODE_SIZE, 3_952);
        let mut node = Node {
            num_items: 1,
            accum_count: 9,
            next_sibling: 12,
            prev_sibling: 4,
            ..Node::default()
        };
        node.accum.buf = [7; 32];
        node.items[0] = Key {
            item: Item::new(123, &[5; 32]).unwrap(),
            node_id: 456,
        };
        let decoded = Node::from_bytes(&node.encode_bytes()).unwrap();
        assert_eq!(decoded.num_items, node.num_items);
        assert_eq!(decoded.accum_count, node.accum_count);
        assert_eq!(decoded.next_sibling, node.next_sibling);
        assert_eq!(decoded.prev_sibling, node.prev_sibling);
        assert_eq!(decoded.accum.buf, node.accum.buf);
        assert_eq!(decoded.items[0].item, node.items[0].item);
        assert_eq!(decoded.items[0].node_id, node.items[0].node_id);
    }

    #[test]
    fn malformed_persisted_item_count_is_rejected() {
        let mut bytes = Node::default().encode_bytes();
        bytes[..8].copy_from_slice(&((MAX_ITEMS + 1) as u64).to_ne_bytes());
        assert!(Node::from_bytes(&bytes).is_err());
        // Zero-item nodes are never persisted and rejected at decode.
        let bytes = Node::default().encode_bytes();
        assert!(Node::from_bytes(&bytes).is_err());
    }
}

#[cfg(test)]
mod traversal_tests {
    use super::*;
    use std::collections::HashMap;

    pub struct MemBackend {
        nodes: HashMap<u64, Node>,
        root: u64,
        next_id: u64,
    }

    impl MemBackend {
        pub fn new() -> Self {
            Self {
                nodes: HashMap::new(),
                root: 0,
                next_id: 0,
            }
        }
    }

    impl BTreeBackend for MemBackend {
        fn get_node_read(&mut self, node_id: u64) -> Result<NodePtr, NegError> {
            Ok(match self.nodes.get(&node_id) {
                Some(&node) => NodePtr {
                    node,
                    node_id,
                    exists: true,
                },
                None => NodePtr {
                    node: Node::default(),
                    node_id,
                    exists: false,
                },
            })
        }
        fn get_node_write(&mut self, node_id: u64) -> Result<NodePtr, NegError> {
            self.get_node_read(node_id)
        }
        fn put_node(&mut self, node_id: u64, node: &Node) -> Result<(), NegError> {
            self.nodes.insert(node_id, *node);
            Ok(())
        }
        fn make_node(&mut self) -> Result<u64, NegError> {
            self.next_id += 1;
            Ok(self.next_id)
        }
        fn delete_node(&mut self, node_id: u64) -> Result<(), NegError> {
            self.nodes.remove(&node_id);
            Ok(())
        }
        fn root_node_id(&self) -> u64 {
            self.root
        }
        fn set_root_node_id(&mut self, id: u64) {
            self.root = id;
        }
    }

    #[test]
    fn zero_item_node_does_not_underflow_lower_bound() {
        let mut backend = MemBackend::new();
        backend.nodes.insert(1, Node::default()); // num_items == 0
        backend.root = 1;
        let mut tree = BTreeCore::new(backend);
        // Must return, not panic on `num_items - 1`.
        assert!(tree.find_lower_bound_mut(0, 0, &Bound::timestamp(5)).is_ok());
        assert!(tree.size_mut().is_ok());
        assert!(tree.iterate_mut(0, 0, |_, _| true).is_ok());
    }
}

#[derive(Clone, Copy)]
pub struct NodePtr {
    pub node: Node,
    pub node_id: u64,
    pub exists: bool,
}

impl NodePtr {
    #[allow(dead_code)]
    fn none() -> Self {
        Self {
            node: Node::default(),
            node_id: 0,
            exists: false,
        }
    }
}

struct Breadcrumb {
    index: usize,
    node_id: u64,
}

/// Backend for node persistence. Implementations must copy nodes out of LMDB
/// mmap; never return a borrow that could outlive the transaction.
pub trait BTreeBackend {
    fn get_node_read(&mut self, node_id: u64) -> Result<NodePtr, NegError>;
    fn get_node_write(&mut self, node_id: u64) -> Result<NodePtr, NegError>;
    fn put_node(&mut self, node_id: u64, node: &Node) -> Result<(), NegError>;
    fn make_node(&mut self) -> Result<u64, NegError>;
    fn delete_node(&mut self, node_id: u64) -> Result<(), NegError>;
    fn root_node_id(&self) -> u64;
    fn set_root_node_id(&mut self, id: u64);
}

pub struct BTreeCore<B> {
    pub backend: B,
}

impl<B: BTreeBackend> BTreeCore<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    fn search_item(
        &mut self,
        root: u64,
        new_item: &Item,
    ) -> Result<(Vec<Breadcrumb>, bool), NegError> {
        let mut found = false;
        let mut breadcrumbs = Vec::new();
        let mut found_node = self.backend.get_node_read(root)?;
        while found_node.exists {
            let node = found_node.node;
            let mut index = node.num_items.saturating_sub(1) as usize;
            if node.num_items > 1 {
                for i in 1..=node.num_items as usize {
                    if i == node.num_items as usize + 1 || *new_item < node.items[i].item {
                        index = i - 1;
                        break;
                    }
                }
            }
            if !found && *new_item == node.items[index].item {
                found = true;
            }
            breadcrumbs.push(Breadcrumb {
                index,
                node_id: found_node.node_id,
            });
            found_node = self.backend.get_node_read(node.items[index].node_id)?;
        }
        Ok((breadcrumbs, found))
    }

    pub fn insert(&mut self, created_at: u64, id: &[u8]) -> Result<bool, NegError> {
        self.insert_item(Item::new(created_at, id)?)
    }

    pub fn insert_item(&mut self, new_item: Item) -> Result<bool, NegError> {
        let mut root = self.backend.root_node_id();
        if root == 0 {
            let id = self.backend.make_node()?;
            let mut node = Node::default();
            node.items[0].item = new_item;
            node.num_items = 1;
            node.accum.add_item(&new_item);
            node.accum_count = 1;
            self.backend.put_node(id, &node)?;
            self.backend.set_root_node_id(id);
            return Ok(true);
        }
        let (mut breadcrumbs, found) = self.search_item(root, &new_item)?;
        if found {
            return Ok(false);
        }
        let mut new_key = Key {
            item: new_item,
            node_id: 0,
        };
        let mut needs_merge = true;
        while let Some(crumb) = breadcrumbs.pop() {
            let np = self.backend.get_node_write(crumb.node_id)?;
            let mut node = np.node;
            if !needs_merge {
                node.accum.add_item(&new_item);
                node.accum_count += 1;
            } else if node.num_items < MAX_ITEMS as u64 {
                node.items[node.num_items as usize] = new_key;
                let n = node.num_items as usize;
                node.items[..=n].sort_by_key(|a| a.item);
                node.num_items += 1;
                node.accum.add_item(&new_item);
                node.accum_count += 1;
                needs_merge = false;
            } else {
                let mut left = node;
                let right_id = self.backend.make_node()?;
                let mut right = Node::default();
                left.items[MAX_ITEMS] = new_key;
                left.items[..=MAX_ITEMS].sort_by_key(|a| a.item);
                left.accum.set_to_zero();
                left.accum_count = 0;
                if left.next_sibling == 0 {
                    left.num_items = MAX_ITEMS as u64;
                    right.num_items = 1;
                } else {
                    left.num_items = (MAX_ITEMS / 2 + 1) as u64;
                    right.num_items = (MAX_ITEMS / 2) as u64;
                }
                for i in 0..left.num_items as usize {
                    self.add_to_accum(left.items[i], &mut left)?;
                }
                for i in 0..right.num_items as usize {
                    right.items[i] = left.items[left.num_items as usize + i];
                    self.add_to_accum(right.items[i], &mut right)?;
                }
                for i in left.num_items as usize..=MAX_ITEMS {
                    left.items[i].set_to_zero();
                }
                right.next_sibling = left.next_sibling;
                left.next_sibling = right_id;
                right.prev_sibling = crumb.node_id;
                if right.next_sibling != 0 {
                    let mut rr = self.backend.get_node_write(right.next_sibling)?;
                    rr.node.prev_sibling = right_id;
                    self.backend.put_node(right.next_sibling, &rr.node)?;
                }
                self.backend.put_node(right_id, &right)?;
                new_key = Key {
                    item: right.items[0].item,
                    node_id: right_id,
                };
                node = left;
            }
            self.refresh_index(&mut node, 0)?;
            self.backend.put_node(crumb.node_id, &node)?;
        }
        if needs_merge {
            root = self.backend.root_node_id();
            let left = self.backend.get_node_read(root)?;
            let right = self.backend.get_node_read(new_key.node_id)?;
            let new_root_id = self.backend.make_node()?;
            let mut new_root = Node::default();
            new_root.num_items = 2;
            new_root.accum.add_acc(&left.node.accum);
            new_root.accum.add_acc(&right.node.accum);
            new_root.accum_count = left.node.accum_count + right.node.accum_count;
            new_root.items[0] = left.node.items[0];
            new_root.items[0].node_id = root;
            new_root.items[1] = right.node.items[0];
            new_root.items[1].node_id = new_key.node_id;
            self.backend.put_node(new_root_id, &new_root)?;
            self.backend.set_root_node_id(new_root_id);
        }
        Ok(true)
    }

    pub fn erase(&mut self, created_at: u64, id: &[u8]) -> Result<bool, NegError> {
        self.erase_item(Item::new(created_at, id)?)
    }

    pub fn erase_item(&mut self, old_item: Item) -> Result<bool, NegError> {
        let root = self.backend.root_node_id();
        if root == 0 {
            return Ok(false);
        }
        let (mut breadcrumbs, found) = self.search_item(root, &old_item)?;
        if !found {
            return Ok(false);
        }
        let mut needs_remove = true;
        let mut neighbour_refresh_needed = false;
        while let Some(crumb) = breadcrumbs.pop() {
            let np = self.backend.get_node_write(crumb.node_id)?;
            let mut node = np.node;
            if !needs_remove {
                node.accum.sub_item(&old_item);
                node.accum_count -= 1;
            } else {
                for i in crumb.index + 1..node.num_items as usize {
                    node.items[i - 1] = node.items[i];
                }
                node.num_items -= 1;
                node.items[node.num_items as usize].set_to_zero();
                node.accum.sub_item(&old_item);
                node.accum_count -= 1;
                needs_remove = false;
            }
            if crumb.index < node.num_items as usize {
                self.refresh_index(&mut node, crumb.index)?;
            }
            if neighbour_refresh_needed {
                self.refresh_index(&mut node, crumb.index + 1)?;
                neighbour_refresh_needed = false;
            }
            if node.num_items < MIN_ITEMS as u64 && !breadcrumbs.is_empty() {
                let parent = self
                    .backend
                    .get_node_read(breadcrumbs.last().unwrap().node_id)?;
                if parent.node.num_items > 1 {
                    neighbour_refresh_needed = self.rebalance_or_merge(
                        crumb.index,
                        &mut node,
                        breadcrumbs.last().unwrap().index,
                    )?;
                }
            }
            if node.num_items == 0 {
                if node.prev_sibling != 0 {
                    let mut p = self.backend.get_node_write(node.prev_sibling)?;
                    p.node.next_sibling = node.next_sibling;
                    self.backend.put_node(node.prev_sibling, &p.node)?;
                }
                if node.next_sibling != 0 {
                    let mut n = self.backend.get_node_write(node.next_sibling)?;
                    n.node.prev_sibling = node.prev_sibling;
                    self.backend.put_node(node.next_sibling, &n.node)?;
                }
                needs_remove = true;
                self.backend.delete_node(crumb.node_id)?;
            } else {
                self.backend.put_node(crumb.node_id, &node)?;
            }
        }
        if needs_remove {
            self.backend.set_root_node_id(0);
        } else {
            let root = self.backend.root_node_id();
            let node = self.backend.get_node_read(root)?;
            if node.node.num_items == 1 && node.node.items[0].node_id != 0 {
                self.backend.set_root_node_id(node.node.items[0].node_id);
                self.backend.delete_node(root)?;
            }
        }
        Ok(true)
    }

    fn rebalance_or_merge(
        &mut self,
        _crumb_index: usize,
        node: &mut Node,
        parent_index: usize,
    ) -> Result<bool, NegError> {
        let mut neighbour_refresh = false;
        if parent_index == 0 {
            let mut left = *node;
            let right_p = self.backend.get_node_write(node.next_sibling)?;
            let mut right = right_p.node;
            let total = left.num_items + right.num_items;
            if total <= REBALANCE_THRESHOLD as u64 {
                for i in (0..right.num_items as usize).rev() {
                    right.items[i + left.num_items as usize] = right.items[i];
                }
                for i in 0..left.num_items as usize {
                    right.items[i] = left.items[i];
                }
                right.num_items += left.num_items;
                right.accum_count += left.accum_count;
                right.accum.add_acc(&left.accum);
                if left.prev_sibling != 0 {
                    let mut p = self.backend.get_node_write(left.prev_sibling)?;
                    p.node.next_sibling = left.next_sibling;
                    self.backend.put_node(left.prev_sibling, &p.node)?;
                }
                right.prev_sibling = left.prev_sibling;
                left.num_items = 0;
                *node = left;
                self.backend.put_node(right_p.node_id, &right)?;
            } else {
                neighbour_refresh = self.rebalance(&mut left, &mut right)?;
                *node = left;
                self.backend.put_node(right_p.node_id, &right)?;
            }
        } else {
            let left_p = self.backend.get_node_write(node.prev_sibling)?;
            let mut left = left_p.node;
            let mut right = *node;
            let total = left.num_items + right.num_items;
            if total <= REBALANCE_THRESHOLD as u64 {
                for i in 0..right.num_items as usize {
                    left.items[left.num_items as usize + i] = right.items[i];
                }
                left.num_items += right.num_items;
                left.accum_count += right.accum_count;
                left.accum.add_acc(&right.accum);
                if right.next_sibling != 0 {
                    let mut n = self.backend.get_node_write(right.next_sibling)?;
                    n.node.prev_sibling = right.prev_sibling;
                    self.backend.put_node(right.next_sibling, &n.node)?;
                }
                left.next_sibling = right.next_sibling;
                right.num_items = 0;
                *node = right;
                self.backend.put_node(left_p.node_id, &left)?;
            } else {
                neighbour_refresh = self.rebalance(&mut left, &mut right)?;
                *node = right;
                self.backend.put_node(left_p.node_id, &left)?;
            }
        }
        Ok(neighbour_refresh)
    }

    fn rebalance(&mut self, left: &mut Node, right: &mut Node) -> Result<bool, NegError> {
        let total = (left.num_items + right.num_items) as usize;
        let num_left = total.div_ceil(2);
        let num_right = total - num_left;
        let mut accum = Accumulator::default();
        let mut accum_count = 0u64;
        if right.num_items as usize >= num_right {
            let num_move = right.num_items as usize - num_right;
            for i in 0..num_move {
                let item = right.items[i];
                self.accum_key(item, &mut accum, &mut accum_count)?;
                left.items[left.num_items as usize + i] = item;
            }
            for i in 0..num_right {
                right.items[i] = right.items[i + num_move];
            }
            for i in num_right..right.num_items as usize {
                right.items[i].set_to_zero();
            }
            left.accum.add_acc(&accum);
            right.accum.sub_acc(&accum);
            left.accum_count += accum_count;
            right.accum_count -= accum_count;
        } else {
            let num_move = left.num_items as usize - num_left;
            for i in (0..right.num_items as usize).rev() {
                right.items[i + num_move] = right.items[i];
            }
            for i in 0..num_move {
                let item = left.items[num_left + i];
                self.accum_key(item, &mut accum, &mut accum_count)?;
                right.items[i] = item;
            }
            for i in num_left..left.num_items as usize {
                left.items[i].set_to_zero();
            }
            left.accum.sub_acc(&accum);
            right.accum.add_acc(&accum);
            left.accum_count -= accum_count;
            right.accum_count += accum_count;
        }
        left.num_items = num_left as u64;
        right.num_items = num_right as u64;
        Ok(true)
    }

    fn accum_key(
        &mut self,
        k: Key,
        accum: &mut Accumulator,
        count: &mut u64,
    ) -> Result<(), NegError> {
        if k.node_id == 0 {
            accum.add_item(&k.item);
            *count += 1;
        } else {
            let n = self.backend.get_node_read(k.node_id)?;
            accum.add_acc(&n.node.accum);
            *count += n.node.accum_count;
        }
        Ok(())
    }

    fn refresh_index(&mut self, node: &mut Node, index: usize) -> Result<(), NegError> {
        let child = self.backend.get_node_read(node.items[index].node_id)?;
        if child.exists {
            node.items[index].item = child.node.items[0].item;
        }
        Ok(())
    }

    fn add_to_accum(&mut self, k: Key, node: &mut Node) -> Result<(), NegError> {
        if k.node_id == 0 {
            node.accum.add_item(&k.item);
            node.accum_count += 1;
        } else {
            let n = self.backend.get_node_read(k.node_id)?;
            node.accum.add_acc(&n.node.accum);
            node.accum_count += n.node.accum_count;
        }
        Ok(())
    }

    fn check_bounds(&mut self, begin: usize, end: usize) -> Result<(), NegError> {
        let size = self.size_mut()? as usize;
        if begin > end || end > size {
            return Err(NegError::msg("bad range"));
        }
        Ok(())
    }

    fn traverse_to_offset<F, C>(
        &mut self,
        index: usize,
        mut cb: F,
        mut custom: C,
    ) -> Result<(), NegError>
    where
        F: FnMut(&Node, usize),
        C: FnMut(&Node),
    {
        let root = self.backend.get_node_read(self.backend.root_node_id())?;
        if !root.exists {
            return Ok(());
        }
        if index as u64 > root.node.accum_count {
            return Err(NegError::msg("out of range"));
        }
        self.traverse_aux(index, root.node_id, &mut cb, &mut custom)
    }

    fn traverse_aux<F, C>(
        &mut self,
        mut index: usize,
        node_id: u64,
        cb: &mut F,
        custom: &mut C,
    ) -> Result<(), NegError>
    where
        F: FnMut(&Node, usize),
        C: FnMut(&Node),
    {
        let np = self.backend.get_node_read(node_id)?;
        let node = np.node;
        if node.num_items == node.accum_count {
            cb(&node, index);
            return Ok(());
        }
        for i in 0..node.num_items as usize {
            let child = self.backend.get_node_read(node.items[i].node_id)?;
            if (index as u64) < child.node.accum_count {
                return self.traverse_aux(index, child.node_id, cb, custom);
            }
            index -= child.node.accum_count as usize;
            custom(&child.node);
        }
        Ok(())
    }
}

impl<B: BTreeBackend> Storage for BTreeCore<B> {
    fn size(&mut self) -> u64 {
        self.size_mut().unwrap_or(0)
    }

    fn get_item(&mut self, i: usize) -> Item {
        self.get_item_mut(i).unwrap_or_default()
    }

    fn iterate<F: FnMut(&Item, usize) -> bool>(&mut self, begin: usize, end: usize, cb: F) {
        let _ = self.iterate_mut(begin, end, cb);
    }

    fn find_lower_bound(&mut self, begin: usize, end: usize, bound: &Bound) -> usize {
        self.find_lower_bound_mut(begin, end, bound).unwrap_or(end)
    }

    fn fingerprint(&mut self, begin: usize, end: usize) -> Fingerprint {
        self.fingerprint_mut(begin, end).unwrap_or([0u8; 16])
    }
}

impl<B: BTreeBackend> BTreeCore<B> {
    pub fn size_mut(&mut self) -> Result<u64, NegError> {
        let root = self.backend.get_node_read(self.backend.root_node_id())?;
        if !root.exists {
            return Ok(0);
        }
        Ok(root.node.accum_count)
    }

    pub fn get_item_mut(&mut self, index: usize) -> Result<Item, NegError> {
        if index as u64 >= self.size_mut()? {
            return Err(NegError::msg("out of range"));
        }
        let mut out = Item::default();
        self.traverse_to_offset(
            index,
            |node, idx| {
                out = node.items[idx].item;
            },
            |_| {},
        )?;
        Ok(out)
    }

    pub fn iterate_mut<F: FnMut(&Item, usize) -> bool>(
        &mut self,
        begin: usize,
        end: usize,
        mut cb: F,
    ) -> Result<(), NegError> {
        self.check_bounds(begin, end)?;
        let num = end - begin;
        let mut first_node = Node::default();
        let mut first_index = 0usize;
        let mut got = false;
        self.traverse_to_offset(
            begin,
            |node, index| {
                first_node = *node;
                first_index = index;
                got = true;
            },
            |_| {},
        )?;
        if !got {
            return Ok(());
        }
        let mut curr = first_node;
        let mut index = first_index;
        for i in 0..num {
            if !cb(&curr.items[index].item, begin + i) {
                return Ok(());
            }
            index += 1;
            if index >= curr.num_items as usize {
                if curr.next_sibling == 0 {
                    break;
                }
                curr = self.backend.get_node_read(curr.next_sibling)?.node;
                index = 0;
            }
        }
        Ok(())
    }

    pub fn find_lower_bound_mut(
        &mut self,
        begin: usize,
        end: usize,
        value: &Bound,
    ) -> Result<usize, NegError> {
        self.check_bounds(begin, end)?;
        let root = self.backend.get_node_read(self.backend.root_node_id())?;
        if !root.exists {
            return Ok(end);
        }
        if value.item <= root.node.items[0].item {
            return Ok(begin);
        }
        Ok(self.find_lower_bound_aux(value, root, 0)?.min(end))
    }

    fn find_lower_bound_aux(
        &mut self,
        value: &Bound,
        node_ptr: NodePtr,
        mut num_to_left: u64,
    ) -> Result<usize, NegError> {
        if !node_ptr.exists {
            return Ok(num_to_left as usize + 1);
        }
        let node = node_ptr.node;
        if node.num_items == 0 {
            // A corrupt-at-rest node with zero items has no child to descend
            // into; treating it like a missing child keeps the traversal
            // total instead of underflowing the items index.
            return Ok(num_to_left as usize + 1);
        }
        for i in 1..node.num_items as usize {
            if value.item <= node.items[i].item {
                let child = self.backend.get_node_read(node.items[i - 1].node_id)?;
                return self.find_lower_bound_aux(value, child, num_to_left);
            } else if node.items[i - 1].node_id != 0 {
                num_to_left += self
                    .backend
                    .get_node_read(node.items[i - 1].node_id)?
                    .node
                    .accum_count;
            } else {
                num_to_left += 1;
            }
        }
        let child = self
            .backend
            .get_node_read(node.items[node.num_items as usize - 1].node_id)?;
        self.find_lower_bound_aux(value, child, num_to_left)
    }

    pub fn fingerprint_mut(&mut self, begin: usize, end: usize) -> Result<Fingerprint, NegError> {
        self.check_bounds(begin, end)?;
        let accum1 = self.accum_left_of(begin)?;
        let mut accum2 = self.accum_left_of(end)?;
        let mut neg = accum1;
        neg.negate();
        accum2.add_acc(&neg);
        Ok(accum2.get_fingerprint((end - begin) as u64))
    }

    fn accum_left_of(&mut self, index: usize) -> Result<Accumulator, NegError> {
        let mut items: Vec<Item> = Vec::new();
        let mut accs: Vec<Accumulator> = Vec::new();
        self.traverse_to_offset(
            index,
            |node, idx| {
                for i in 0..idx {
                    items.push(node.items[i].item);
                }
            },
            |node| {
                accs.push(node.accum);
            },
        )?;
        let mut accum = Accumulator::default();
        for a in accs {
            accum.add_acc(&a);
        }
        for item in items {
            accum.add_item(&item);
        }
        Ok(accum)
    }
}
