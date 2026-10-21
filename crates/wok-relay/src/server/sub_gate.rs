//! Per-connection subscription gate: the one place that decides which
//! subscription frames reach a connection.
//!
//! Replies for one subscription id come from three producers: the ingester
//! (a refusal's CLOSED), the req worker (history, COUNT results, its own
//! refusals) and the req monitor (EOSE, live events). The ingester gives every
//! REQ and COUNT a generation, in client order, and moves the gate as it
//! handles the client's REQ, COUNT and CLOSE. A producer's frame is queued only
//! while its generation is the id's current one, and that check runs under the
//! connection table's lock, the same lock every frame is queued under. So no
//! frame of a replaced or closed generation follows the change, and a CLOSED is
//! the last frame of its generation, whatever order the producers run in.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use wok_query::SubId;

/// REQ and COUNT ids are separate namespaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Ns {
    Req,
    Count,
}

/// The generation a subscription id is current at, zero once it is closed.
/// Frames queued for the id share it, so a transport can drop the ones that
/// went stale while they waited in the queue.
pub(crate) type Current = Arc<AtomicU64>;

#[derive(Default)]
pub(crate) struct SubGate {
    req: HashMap<SubId, Current>,
    count: HashMap<SubId, Current>,
}

impl SubGate {
    fn ids(&self, ns: Ns) -> &HashMap<SubId, Current> {
        match ns {
            Ns::Req => &self.req,
            Ns::Count => &self.count,
        }
    }

    fn ids_mut(&mut self, ns: Ns) -> &mut HashMap<SubId, Current> {
        match ns {
            Ns::Req => &mut self.req,
            Ns::Count => &mut self.count,
        }
    }

    /// A REQ or COUNT took the id at `generation` (never zero): only its
    /// frames pass from now on. Returns the generation it replaced.
    pub(crate) fn open(&mut self, ns: Ns, sub_id: &SubId, generation: u64) -> Option<u64> {
        debug_assert_ne!(generation, 0);
        let ids = self.ids_mut(ns);
        if let Some(current) = ids.get(sub_id) {
            return Some(current.swap(generation, Ordering::Relaxed));
        }
        ids.insert(sub_id.clone(), Arc::new(AtomicU64::new(generation)));
        None
    }

    /// Nothing for the id passes until it is opened again. Returns the
    /// generation that was current.
    pub(crate) fn close(&mut self, ns: Ns, sub_id: &SubId) -> Option<u64> {
        let current = self.ids_mut(ns).remove(sub_id)?;
        Some(current.swap(0, Ordering::Relaxed))
    }

    /// Whether a frame of this generation may be queued now, and the cell to
    /// tag it with.
    pub(crate) fn admit(&self, ns: Ns, sub_id: &SubId, generation: u64) -> Option<&Current> {
        self.ids(ns)
            .get(sub_id)
            .filter(|current| current.load(Ordering::Relaxed) == generation)
    }

    pub(crate) fn len(&self, ns: Ns) -> usize {
        self.ids(ns).len()
    }

    pub(crate) fn is_open(&self, ns: Ns, sub_id: &SubId) -> bool {
        self.ids(ns).contains_key(sub_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    #[derive(Clone, Copy, Debug)]
    enum Kind {
        /// EVENT or EOSE: the generation goes on.
        Frame,
        /// A producer's CLOSED or COUNT result: the generation ends.
        Last,
    }

    #[derive(Clone, Debug)]
    enum Op {
        /// An admitted REQ or COUNT, replacing whatever had the id.
        Open { ns: Ns, id: u8 },
        /// A refused REQ or COUNT: the id closes and its CLOSED is queued.
        Refuse { ns: Ns, id: u8 },
        /// CLOSE (REQ ids only).
        Close { id: u8 },
        /// A producer's frame for one of the id's generations, `age` back
        /// from the newest: producers lag, so any of them can still emit.
        Emit { ns: Ns, id: u8, age: u8, kind: Kind },
    }

    fn ns() -> impl Strategy<Value = Ns> {
        prop_oneof![Just(Ns::Req), Just(Ns::Count)]
    }

    fn op() -> impl Strategy<Value = Op> {
        let id = 0u8..3;
        prop_oneof![
            (ns(), id.clone()).prop_map(|(ns, id)| Op::Open { ns, id }),
            (ns(), id.clone()).prop_map(|(ns, id)| Op::Refuse { ns, id }),
            id.clone().prop_map(|id| Op::Close { id }),
            (
                ns(),
                id,
                0u8..4,
                prop_oneof![3 => Just(Kind::Frame), 1 => Just(Kind::Last)]
            )
                .prop_map(|(ns, id, age, kind)| Op::Emit { ns, id, age, kind }),
        ]
    }

    fn sid(id: u8) -> SubId {
        SubId::new(&format!("s{id}")).unwrap()
    }

    proptest! {
        /// Whatever order client operations and producers interleave in,
        /// per id: only the current generation's frames are queued, none of a
        /// generation the gate moved past, generations never go backwards,
        /// and a CLOSED is the last frame of its generation.
        #[test]
        fn frames_never_outlive_their_generation(ops in prop::collection::vec(op(), 1..300)) {
            let mut gate = SubGate::default();
            let mut next = 0u64;
            // Every generation handed out per id, oldest first.
            let mut handed: HashMap<(Ns, u8), Vec<u64>> = HashMap::new();
            // What the gate should hold, kept independently of it.
            let mut model: HashMap<(Ns, u8), u64> = HashMap::new();
            // Generations the gate has moved past (replaced, closed, ended).
            let mut over: HashSet<(Ns, u8, u64)> = HashSet::new();
            // Frames queued, in order; a CLOSED of no generation is 0.
            let mut queued: Vec<(Ns, u8, u64, Kind)> = Vec::new();
            for op in ops {
                match op {
                    Op::Open { ns, id } => {
                        next += 1;
                        let replaced = gate.open(ns, &sid(id), next);
                        prop_assert_eq!(replaced, model.insert((ns, id), next));
                        if let Some(old) = replaced {
                            over.insert((ns, id, old));
                        }
                        handed.entry((ns, id)).or_default().push(next);
                    }
                    Op::Refuse { ns, id } => {
                        let closed = gate.close(ns, &sid(id));
                        prop_assert_eq!(closed, model.remove(&(ns, id)));
                        if let Some(g) = closed {
                            over.insert((ns, id, g));
                        }
                        queued.push((ns, id, closed.unwrap_or(0), Kind::Last));
                    }
                    Op::Close { id } => {
                        let closed = gate.close(Ns::Req, &sid(id));
                        prop_assert_eq!(closed, model.remove(&(Ns::Req, id)));
                        if let Some(g) = closed {
                            over.insert((Ns::Req, id, g));
                        }
                    }
                    Op::Emit { ns, id, age, kind } => {
                        let Some(gens) = handed.get(&(ns, id)) else {
                            continue;
                        };
                        let g = gens[gens.len() - 1 - usize::from(age) % gens.len()];
                        let admitted = gate.admit(ns, &sid(id), g).is_some();
                        prop_assert_eq!(admitted, model.get(&(ns, id)) == Some(&g));
                        prop_assert!(!(admitted && over.contains(&(ns, id, g))));
                        if admitted {
                            queued.push((ns, id, g, kind));
                            if matches!(kind, Kind::Last) {
                                gate.close(ns, &sid(id));
                                model.remove(&(ns, id));
                                over.insert((ns, id, g));
                            }
                        }
                    }
                }
                for (&(ns, id), &g) in &model {
                    prop_assert!(gate.admit(ns, &sid(id), g).is_some());
                }
                prop_assert_eq!(
                    gate.len(Ns::Req) + gate.len(Ns::Count),
                    model.len()
                );
            }
            let mut newest: HashMap<(Ns, u8), u64> = HashMap::new();
            for (i, &(ns, id, g, kind)) in queued.iter().enumerate() {
                if g != 0 {
                    let seen = newest.entry((ns, id)).or_default();
                    prop_assert!(g >= *seen, "generations went backwards");
                    *seen = g;
                }
                if matches!(kind, Kind::Last) && g != 0 {
                    prop_assert!(
                        !queued[i + 1..]
                            .iter()
                            .any(|&(n, d, h, _)| (n, d, h) == (ns, id, g)),
                        "a frame followed the CLOSED of its generation"
                    );
                }
            }
        }
    }

    /// A frame keeps its id's cell, so it can tell in the queue that its
    /// generation was replaced or closed.
    #[test]
    fn queued_frames_see_their_generation_end() {
        let mut gate = SubGate::default();
        let x = SubId::new("x").unwrap();
        gate.open(Ns::Req, &x, 1);
        let cell = gate.admit(Ns::Req, &x, 1).unwrap().clone();
        assert_eq!(cell.load(Ordering::Relaxed), 1);
        gate.open(Ns::Req, &x, 2);
        assert_eq!(cell.load(Ordering::Relaxed), 2);
        assert!(gate.admit(Ns::Req, &x, 1).is_none());
        gate.close(Ns::Req, &x);
        assert_eq!(cell.load(Ordering::Relaxed), 0);
        assert!(!gate.is_open(Ns::Req, &x));
        // The COUNT namespace is separate.
        gate.open(Ns::Count, &x, 3);
        assert!(gate.admit(Ns::Req, &x, 3).is_none());
        assert!(gate.admit(Ns::Count, &x, 3).is_some());
    }
}
