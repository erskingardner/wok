#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use wok_negentropy::{BTreeBackend, BTreeCore, Negentropy, Node, NodePtr, Vector, NODE_SIZE};
use wok_relay::ClientCommand;
use wok_ws::frame::{InflateCtx, Role, WsParser};

/// In-memory BTreeBackend over attacker-controlled node bytes. Reads are
/// capped so cyclic/corrupt node graphs terminate instead of recursing
/// forever — the harness is here to find panics, not stack exhaustion.
struct FuzzBackend {
    nodes: HashMap<u64, Node>,
    root: u64,
    next_id: u64,
    reads: usize,
}

impl BTreeBackend for FuzzBackend {
    fn get_node_read(&mut self, node_id: u64) -> Result<NodePtr, wok_negentropy::NegError> {
        self.reads += 1;
        if self.reads > 10_000 {
            return Err(wok_negentropy::NegError::msg("fuzz read budget"));
        }
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
    fn get_node_write(&mut self, node_id: u64) -> Result<NodePtr, wok_negentropy::NegError> {
        self.get_node_read(node_id)
    }
    fn put_node(&mut self, node_id: u64, node: &Node) -> Result<(), wok_negentropy::NegError> {
        self.nodes.insert(node_id, *node);
        Ok(())
    }
    fn make_node(&mut self) -> Result<u64, wok_negentropy::NegError> {
        self.next_id += 1;
        Ok(self.next_id)
    }
    fn delete_node(&mut self, node_id: u64) -> Result<(), wok_negentropy::NegError> {
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

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = wok_event::json::parse_strict(text);
        let _ = ClientCommand::parse(text);
    }
    let _ = wok_event::PackedEventView::new(data);

    for role in [Role::Server, Role::Client] {
        let mut parser = WsParser::with_role(131_072, Some(InflateCtx::new(false)), role);
        for chunk in data.chunks(257) {
            if parser.feed(chunk).is_err() {
                break;
            }
        }
    }
    let _ = InflateCtx::new(false).decompress(data, 131_072);

    // fbs metadata decoders: Meta, CompressionDictionary, NegentropyFilter.
    let _ = wok_db::fbs::decode_meta(data);
    let _ = wok_db::fbs::decode_compression_dictionary(data);
    let _ = wok_db::fbs::decode_negentropy_filter(data);

    // B-tree node decode + traversal over arbitrary node bytes.
    let mut backend = FuzzBackend {
        nodes: HashMap::new(),
        root: 0,
        next_id: 0,
        reads: 0,
    };
    for (i, chunk) in data.chunks(NODE_SIZE).take(16).enumerate() {
        if let Ok(node) = Node::from_bytes(chunk) {
            backend.nodes.insert(i as u64 + 1, node);
        }
    }
    if !backend.nodes.is_empty() {
        backend.root = 1;
        backend.next_id = backend.nodes.len() as u64;
        let mut tree = BTreeCore::new(backend);
        let size = tree.size_mut().unwrap_or(0);
        let bound = wok_negentropy::Bound::timestamp(1_700_000_000);
        let _ = tree.find_lower_bound_mut(0, (size as usize).min(64), &bound);
        let _ = tree.iterate_mut(0, (size as usize).min(64), |_, _| true);
        let _ = tree.get_item_mut(0);
        let _ = tree.fingerprint_mut(0, (size as usize).min(64));
    }

    // Empty-vector reconciliation (responder and initiator roles).
    let mut vector = Vector::new();
    vector.seal().unwrap();
    let mut responder = Negentropy::new(vector.clone(), 0).unwrap();
    let _ = responder.reconcile(data);
    let mut initiator = Negentropy::new(vector, 0).unwrap();
    initiator.set_initiator();
    let _ = initiator.reconcile_with_ids(data, &mut Vec::new(), &mut Vec::new());

    // Non-empty vector reconciliation: items derived from the fuzz input,
    // then the whole input replayed as the peer's message.
    let mut vector = Vector::new();
    for chunk in data.chunks(40).take(64) {
        if chunk.len() == 40 {
            let timestamp = u64::from_ne_bytes(chunk[..8].try_into().unwrap());
            let _ = vector.insert(timestamp, &chunk[8..]);
        }
    }
    if vector.seal().is_ok() {
        if let Ok(mut ne) = Negentropy::new(vector, 0) {
            let _ = ne.reconcile(data);
        }
    }
});
