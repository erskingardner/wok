//! Live matches held for a subscription while its history is being sent.
//!
//! A REQ's history covers what was stored when the REQ was admitted; the live
//! monitor covers everything after, starting before the history scan does, so
//! nothing published after the REQ is missed. Until the scan finishes,
//! matches wait here in arrival order: stored events as their local event id,
//! live-only (ephemeral) events in full, so their visibility can be checked
//! again when they are sent. The buffer is bounded. Past the bound, stored
//! events are dropped and later re-read from the database, and ephemeral
//! events, which cannot be re-read, are dropped oldest first.

use std::collections::VecDeque;
use std::sync::Arc;

/// Bytes charged for a buffered stored event.
pub const STORED_ENTRY_BYTES: usize = 16;
/// Bytes charged for a buffered ephemeral event on top of its payloads.
pub const EPHEMERAL_ENTRY_OVERHEAD: usize = 64;

/// A live-only event that never reaches the database.
#[derive(Debug, PartialEq, Eq)]
pub struct HeldEvent {
    /// PackedEvent bytes, to check visibility again before sending.
    pub packed: Vec<u8>,
    pub json: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingEvent {
    /// A stored event, by local event id.
    Stored(u64),
    /// A live-only event, shared by every subscription that holds it.
    Ephemeral(Arc<HeldEvent>),
}

impl PendingEvent {
    fn cost(&self) -> usize {
        match self {
            Self::Stored(_) => STORED_ENTRY_BYTES,
            Self::Ephemeral(event) => {
                (event.packed.len() + event.json.len()).saturating_add(EPHEMERAL_ENTRY_OVERHEAD)
            }
        }
    }
}

#[derive(Debug)]
pub struct PendingBuffer {
    events: VecDeque<PendingEvent>,
    bytes: usize,
    stored: usize,
    /// Zero is unbounded.
    limit: usize,
    live_from: u64,
    stored_overflowed: bool,
}

impl PendingBuffer {
    /// `live_from` is the local event id after which stored matches are the
    /// buffer's: the REQ's history snapshot, or the newest event the monitor
    /// had already matched when it registered the subscription, if later.
    pub fn new(live_from: u64, limit: usize) -> Self {
        Self {
            events: VecDeque::new(),
            bytes: 0,
            stored: 0,
            limit,
            live_from,
            stored_overflowed: false,
        }
    }

    pub fn live_from(&self) -> u64 {
        self.live_from
    }

    /// True once stored events no longer fit. The monitor then re-reads every
    /// stored match after the history snapshot from the database instead.
    pub fn stored_overflowed(&self) -> bool {
        self.stored_overflowed
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Buffer a stored match. True if this is the match that made stored
    /// events overflow.
    pub fn push_stored(&mut self, lev_id: u64) -> bool {
        if self.stored_overflowed {
            return false;
        }
        let event = PendingEvent::Stored(lev_id);
        if self.fits(event.cost()) {
            self.push(event);
            return false;
        }
        self.drop_stored();
        true
    }

    /// Buffer an ephemeral match. Returns how many ephemeral events were
    /// dropped, oldest first, to bound the buffer. An event larger than the
    /// whole bound is the only one dropped. Stored events give way first,
    /// since those can be re-read; the second value is true if this push made
    /// them overflow.
    pub fn push_ephemeral(&mut self, event: Arc<HeldEvent>) -> (u64, bool) {
        let event = PendingEvent::Ephemeral(event);
        let cost = event.cost();
        if self.limit != 0 && cost > self.limit {
            return (1, false);
        }
        let overflowed = !self.fits(cost) && self.stored != 0;
        if overflowed {
            self.drop_stored();
        }
        let mut dropped = 0;
        while !self.fits(cost) {
            // Only ephemeral events are left once stored ones overflowed, and
            // the event fits an empty buffer.
            let oldest = self.events.pop_front().expect("fits an empty buffer");
            self.bytes -= oldest.cost();
            dropped += 1;
        }
        self.push(event);
        (dropped, overflowed)
    }

    /// The buffered events in arrival order.
    pub fn into_events(self) -> VecDeque<PendingEvent> {
        self.events
    }

    fn fits(&self, cost: usize) -> bool {
        self.limit == 0 || self.bytes.saturating_add(cost) <= self.limit
    }

    fn push(&mut self, event: PendingEvent) {
        self.bytes += event.cost();
        self.stored += usize::from(matches!(event, PendingEvent::Stored(_)));
        self.events.push_back(event);
    }

    fn drop_stored(&mut self) {
        self.stored_overflowed = true;
        self.events
            .retain(|event| !matches!(event, PendingEvent::Stored(_)));
        self.bytes -= self.stored * STORED_ENTRY_BYTES;
        self.stored = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ephemeral(json: &str) -> Arc<HeldEvent> {
        Arc::new(HeldEvent {
            packed: Vec::new(),
            json: json.into(),
        })
    }

    fn sized(len: usize) -> Arc<HeldEvent> {
        ephemeral(&"x".repeat(len))
    }

    #[test]
    fn keeps_arrival_order() {
        let mut buffer = PendingBuffer::new(7, 0);
        assert!(!buffer.push_stored(8));
        assert_eq!(buffer.push_ephemeral(ephemeral("{}")), (0, false));
        assert!(!buffer.push_stored(9));
        assert_eq!(buffer.live_from(), 7);
        assert_eq!(
            buffer.into_events(),
            [
                PendingEvent::Stored(8),
                PendingEvent::Ephemeral(ephemeral("{}")),
                PendingEvent::Stored(9),
            ]
        );
    }

    #[test]
    fn stored_overflow_drops_every_stored_event_and_stops_buffering_them() {
        let mut buffer = PendingBuffer::new(0, 3 * STORED_ENTRY_BYTES);
        for lev in 1..=3 {
            assert!(!buffer.push_stored(lev));
        }
        assert!(buffer.push_stored(4));
        assert!(buffer.stored_overflowed());
        assert!(buffer.is_empty());
        // Later stored matches are left to the database catch-up.
        assert!(!buffer.push_stored(5));
        assert!(buffer.is_empty());
    }

    #[test]
    fn ephemeral_overflow_drops_stored_first_then_oldest_ephemeral() {
        let one = 100 + EPHEMERAL_ENTRY_OVERHEAD;
        let mut buffer = PendingBuffer::new(0, 2 * one + STORED_ENTRY_BYTES);
        assert_eq!(buffer.push_ephemeral(sized(100)), (0, false));
        assert!(!buffer.push_stored(1));
        assert_eq!(buffer.push_ephemeral(sized(100)), (0, false));
        // The third ephemeral first displaces the recoverable stored entry,
        // then the oldest ephemeral.
        let newest = ephemeral(&"y".repeat(100));
        assert_eq!(buffer.push_ephemeral(newest.clone()), (1, true));
        assert!(buffer.stored_overflowed());
        assert_eq!(
            buffer.into_events(),
            [
                PendingEvent::Ephemeral(sized(100)),
                PendingEvent::Ephemeral(newest),
            ]
        );
    }

    /// An event too large for the bound is dropped alone: what the buffer
    /// already holds stays, stored events included.
    #[test]
    fn an_ephemeral_larger_than_the_bound_is_dropped_alone() {
        let mut buffer = PendingBuffer::new(0, 128);
        assert_eq!(buffer.push_ephemeral(sized(10)), (0, false));
        assert!(!buffer.push_stored(1));
        assert_eq!(buffer.push_ephemeral(sized(1000)), (1, false));
        assert!(!buffer.stored_overflowed());
        assert_eq!(
            buffer.into_events(),
            [PendingEvent::Ephemeral(sized(10)), PendingEvent::Stored(1)]
        );
    }
}
