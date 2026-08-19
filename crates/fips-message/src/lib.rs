#![forbid(unsafe_code)]
//! Versioned logical-message framing for unreliable datagram transports.

use std::collections::{btree_map::Entry, BTreeMap};
use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

pub const MAGIC: [u8; 4] = *b"WFP1";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 38;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn from_u128(value: u128) -> Self {
        Self(value.to_be_bytes())
    }

    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Hello = 1,
    Ready = 2,
    Data = 3,
    Close = 4,
    Ping = 5,
    Pong = 6,
}

impl TryFrom<u8> for FrameKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Ready),
            3 => Ok(Self::Data),
            4 => Ok(Self::Close),
            5 => Ok(Self::Ping),
            6 => Ok(Self::Pong),
            other => Err(ProtocolError::UnknownKind(other)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: FrameKind,
    pub session: SessionId,
    pub message_id: u64,
    pub chunk_index: u16,
    pub chunk_count: u16,
    pub total_len: u32,
    pub payload: &'a [u8],
}

impl Frame<'_> {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        validate_fields(self)?;
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.session.0);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&self.chunk_index.to_be_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        out.extend_from_slice(&self.total_len.to_be_bytes());
        out.extend_from_slice(self.payload);
        Ok(out)
    }
}

pub fn decode(datagram: &[u8]) -> Result<Frame<'_>, ProtocolError> {
    if datagram.len() < HEADER_LEN {
        return Err(ProtocolError::TruncatedHeader {
            actual: datagram.len(),
        });
    }
    if datagram[..4] != MAGIC {
        return Err(ProtocolError::BadMagic);
    }
    if datagram[4] != VERSION {
        return Err(ProtocolError::UnknownVersion(datagram[4]));
    }
    let kind = FrameKind::try_from(datagram[5])?;
    let mut session = [0u8; 16];
    session.copy_from_slice(&datagram[6..22]);
    let frame = Frame {
        kind,
        session: SessionId::new(session),
        message_id: u64::from_be_bytes(datagram[22..30].try_into().expect("fixed slice")),
        chunk_index: u16::from_be_bytes(datagram[30..32].try_into().expect("fixed slice")),
        chunk_count: u16::from_be_bytes(datagram[32..34].try_into().expect("fixed slice")),
        total_len: u32::from_be_bytes(datagram[34..38].try_into().expect("fixed slice")),
        payload: &datagram[HEADER_LEN..],
    };
    validate_fields(&frame)?;
    Ok(frame)
}

fn validate_fields(frame: &Frame<'_>) -> Result<(), ProtocolError> {
    match frame.kind {
        FrameKind::Hello
        | FrameKind::Ready
        | FrameKind::Close
        | FrameKind::Ping
        | FrameKind::Pong => {
            if frame.message_id != 0
                || frame.chunk_index != 0
                || frame.chunk_count != 0
                || frame.total_len != 0
                || !frame.payload.is_empty()
            {
                return Err(ProtocolError::MalformedControl(frame.kind));
            }
        }
        FrameKind::Data => {
            if frame.chunk_count == 0 {
                return Err(ProtocolError::ZeroChunkCount);
            }
            if frame.chunk_index >= frame.chunk_count {
                return Err(ProtocolError::ChunkIndexOutOfRange {
                    index: frame.chunk_index,
                    count: frame.chunk_count,
                });
            }
            if frame.payload.len() > frame.total_len as usize {
                return Err(ProtocolError::PayloadExceedsTotal {
                    payload: frame.payload.len(),
                    total: frame.total_len,
                });
            }
            if frame.total_len == 0 && (frame.chunk_count != 1 || !frame.payload.is_empty()) {
                return Err(ProtocolError::InconsistentEmptyMessage);
            }
        }
    }
    Ok(())
}

pub fn control(kind: FrameKind, session: SessionId) -> Result<Vec<u8>, ProtocolError> {
    Frame {
        kind,
        session,
        message_id: 0,
        chunk_index: 0,
        chunk_count: 0,
        total_len: 0,
        payload: &[],
    }
    .encode()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_message_size: usize,
    pub max_chunks: u16,
    pub max_incomplete_messages: usize,
    pub max_reassembly_bytes: usize,
    pub max_completed_messages: usize,
    pub incomplete_timeout: Duration,
}

impl Limits {
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if self.max_message_size > u32::MAX as usize {
            return Err(ProtocolError::LimitTooLarge("max_message_size"));
        }
        if self.max_chunks == 0 {
            return Err(ProtocolError::InvalidLimit("max_chunks"));
        }
        if self.max_incomplete_messages == 0 {
            return Err(ProtocolError::InvalidLimit("max_incomplete_messages"));
        }
        if self.max_reassembly_bytes == 0 {
            return Err(ProtocolError::InvalidLimit("max_reassembly_bytes"));
        }
        if self.max_completed_messages == 0 {
            return Err(ProtocolError::InvalidLimit("max_completed_messages"));
        }
        if self.incomplete_timeout.is_zero() {
            return Err(ProtocolError::InvalidLimit("incomplete_timeout"));
        }
        Ok(self)
    }
}

pub fn chunk_message(
    session: SessionId,
    message_id: u64,
    message: &[u8],
    max_datagram: usize,
    limits: Limits,
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    let limits = limits.validate()?;
    if message.len() > limits.max_message_size || message.len() > u32::MAX as usize {
        return Err(ProtocolError::MessageTooLarge {
            actual: message.len(),
            limit: limits.max_message_size.min(u32::MAX as usize),
        });
    }
    let capacity = max_datagram
        .checked_sub(HEADER_LEN)
        .ok_or(ProtocolError::DatagramTooSmall {
            actual: max_datagram,
            required: HEADER_LEN,
        })?;
    if capacity == 0 && !message.is_empty() {
        return Err(ProtocolError::DatagramTooSmall {
            actual: max_datagram,
            required: HEADER_LEN + 1,
        });
    }
    let chunks = if message.is_empty() {
        1
    } else {
        message.len().div_ceil(capacity)
    };
    if chunks > limits.max_chunks as usize || chunks > u16::MAX as usize {
        return Err(ProtocolError::TooManyChunks {
            actual: chunks,
            limit: limits.max_chunks,
        });
    }
    let chunk_count = chunks as u16;
    let total_len = message.len() as u32;
    let mut out = Vec::with_capacity(chunks);
    if message.is_empty() {
        out.push(
            Frame {
                kind: FrameKind::Data,
                session,
                message_id,
                chunk_index: 0,
                chunk_count: 1,
                total_len: 0,
                payload: &[],
            }
            .encode()?,
        );
        return Ok(out);
    }
    for (index, payload) in message.chunks(capacity).enumerate() {
        out.push(
            Frame {
                kind: FrameKind::Data,
                session,
                message_id,
                chunk_index: index as u16,
                chunk_count,
                total_len,
                payload,
            }
            .encode()?,
        );
    }
    Ok(out)
}

#[derive(Debug)]
struct PartialMessage {
    chunk_count: u16,
    total_len: usize,
    chunks: Vec<Option<Vec<u8>>>,
    received_bytes: usize,
    deadline: Instant,
}

impl PartialMessage {
    fn new(frame: &Frame<'_>, deadline: Instant) -> Self {
        Self {
            chunk_count: frame.chunk_count,
            total_len: frame.total_len as usize,
            chunks: vec![None; frame.chunk_count as usize],
            received_bytes: 0,
            deadline,
        }
    }

    fn complete(&self) -> bool {
        self.chunks.iter().all(Option::is_some)
    }

    fn assemble(self) -> Result<Vec<u8>, ProtocolError> {
        if self.received_bytes != self.total_len {
            return Err(ProtocolError::InconsistentTotalLength {
                declared: self.total_len,
                received: self.received_bytes,
            });
        }
        let mut message = Vec::with_capacity(self.total_len);
        for payload in self.chunks {
            message.extend(payload.expect("complete checked"));
        }
        Ok(message)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedMessage {
    pub message_id: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct Reassembler {
    session: SessionId,
    limits: Limits,
    next_message_id: u64,
    incomplete: BTreeMap<u64, PartialMessage>,
    completed: BTreeMap<u64, Vec<u8>>,
    buffered_bytes: usize,
    gap_deadline: Option<Instant>,
    failed: bool,
}

impl Reassembler {
    pub fn new(session: SessionId, limits: Limits) -> Result<Self, ProtocolError> {
        Ok(Self {
            session,
            limits: limits.validate()?,
            next_message_id: 0,
            incomplete: BTreeMap::new(),
            completed: BTreeMap::new(),
            buffered_bytes: 0,
            gap_deadline: None,
            failed: false,
        })
    }

    pub const fn session(&self) -> SessionId {
        self.session
    }

    pub const fn next_message_id(&self) -> u64 {
        self.next_message_id
    }

    pub fn ingest(
        &mut self,
        datagram: &[u8],
        now: Instant,
    ) -> Result<Vec<CompletedMessage>, ProtocolError> {
        if self.failed {
            return Err(ProtocolError::SessionFailed);
        }
        self.expire(now)?;
        let frame = decode(datagram)?;
        if frame.kind != FrameKind::Data {
            return Err(ProtocolError::UnexpectedFrame(frame.kind));
        }
        if frame.session != self.session {
            return Err(ProtocolError::WrongSession);
        }
        if frame.message_id < self.next_message_id {
            return Ok(Vec::new());
        }
        if frame.total_len as usize > self.limits.max_message_size {
            return Err(ProtocolError::MessageTooLarge {
                actual: frame.total_len as usize,
                limit: self.limits.max_message_size,
            });
        }
        if frame.chunk_count > self.limits.max_chunks {
            return Err(ProtocolError::TooManyChunks {
                actual: frame.chunk_count as usize,
                limit: self.limits.max_chunks,
            });
        }
        if self.completed.contains_key(&frame.message_id) {
            return Ok(Vec::new());
        }

        if !self.incomplete.contains_key(&frame.message_id)
            && self.incomplete.len() >= self.limits.max_incomplete_messages
        {
            return Err(ProtocolError::TooManyIncompleteMessages {
                limit: self.limits.max_incomplete_messages,
            });
        }
        let deadline = now
            .checked_add(self.limits.incomplete_timeout)
            .ok_or(ProtocolError::InvalidLimit("incomplete_timeout"))?;
        let partial = match self.incomplete.entry(frame.message_id) {
            Entry::Vacant(entry) => entry.insert(PartialMessage::new(&frame, deadline)),
            Entry::Occupied(entry) => entry.into_mut(),
        };
        if partial.chunk_count != frame.chunk_count || partial.total_len != frame.total_len as usize
        {
            self.failed = true;
            return Err(ProtocolError::ConflictingMetadata {
                message_id: frame.message_id,
            });
        }
        let slot = &mut partial.chunks[frame.chunk_index as usize];
        if let Some(existing) = slot {
            if existing.as_slice() == frame.payload {
                return Ok(Vec::new());
            }
            self.failed = true;
            return Err(ProtocolError::ConflictingDuplicate {
                message_id: frame.message_id,
                chunk_index: frame.chunk_index,
            });
        }
        let new_total = self.buffered_bytes.checked_add(frame.payload.len()).ok_or(
            ProtocolError::ReassemblyBytesExceeded {
                limit: self.limits.max_reassembly_bytes,
            },
        )?;
        if new_total > self.limits.max_reassembly_bytes {
            return Err(ProtocolError::ReassemblyBytesExceeded {
                limit: self.limits.max_reassembly_bytes,
            });
        }
        *slot = Some(frame.payload.to_vec());
        partial.received_bytes += frame.payload.len();
        self.buffered_bytes = new_total;

        if partial.received_bytes > partial.total_len {
            self.failed = true;
            return Err(ProtocolError::PayloadExceedsTotal {
                payload: partial.received_bytes,
                total: partial.total_len as u32,
            });
        }
        if partial.complete() {
            let partial = self
                .incomplete
                .remove(&frame.message_id)
                .expect("present partial");
            let bytes = partial.received_bytes;
            let message = match partial.assemble() {
                Ok(message) => message,
                Err(error) => {
                    self.failed = true;
                    return Err(error);
                }
            };
            if frame.message_id != self.next_message_id
                && self.completed.len() >= self.limits.max_completed_messages
            {
                self.failed = true;
                return Err(ProtocolError::TooManyCompletedMessages {
                    limit: self.limits.max_completed_messages,
                });
            }
            self.completed.insert(frame.message_id, message);
            debug_assert_eq!(bytes, self.completed[&frame.message_id].len());
        }

        let delivered = self.drain_completed()?;
        self.refresh_gap_deadline(now)?;
        Ok(delivered)
    }

    pub fn expire(&mut self, now: Instant) -> Result<(), ProtocolError> {
        if self.failed {
            return Err(ProtocolError::SessionFailed);
        }
        let blocking_incomplete = self
            .incomplete
            .get(&self.next_message_id)
            .is_some_and(|message| message.deadline <= now);
        let blocking_gap = self.gap_deadline.is_some_and(|deadline| deadline <= now);
        if blocking_incomplete || blocking_gap {
            self.failed = true;
            return Err(ProtocolError::OrderedMessageExpired {
                message_id: self.next_message_id,
            });
        }

        let expired_later: Vec<u64> = self
            .incomplete
            .iter()
            .filter_map(|(id, message)| {
                (*id > self.next_message_id && message.deadline <= now).then_some(*id)
            })
            .collect();
        for id in expired_later {
            if let Some(message) = self.incomplete.remove(&id) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(message.received_bytes);
            }
        }
        Ok(())
    }

    fn drain_completed(&mut self) -> Result<Vec<CompletedMessage>, ProtocolError> {
        let mut delivered = Vec::new();
        while let Some(payload) = self.completed.remove(&self.next_message_id) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(payload.len());
            let message_id = self.next_message_id;
            self.next_message_id = self
                .next_message_id
                .checked_add(1)
                .ok_or(ProtocolError::MessageIdExhausted)?;
            delivered.push(CompletedMessage {
                message_id,
                payload,
            });
        }
        Ok(delivered)
    }

    fn refresh_gap_deadline(&mut self, now: Instant) -> Result<(), ProtocolError> {
        let has_later = self
            .incomplete
            .first_key_value()
            .is_some_and(|(id, _)| *id > self.next_message_id)
            || self
                .completed
                .first_key_value()
                .is_some_and(|(id, _)| *id > self.next_message_id);
        if has_later && !self.incomplete.contains_key(&self.next_message_id) {
            let deadline = now
                .checked_add(self.limits.incomplete_timeout)
                .ok_or(ProtocolError::InvalidLimit("incomplete_timeout"))?;
            self.gap_deadline.get_or_insert(deadline);
        } else {
            self.gap_deadline = None;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct HandshakeClient {
    session: SessionId,
    started: Instant,
    deadline: Instant,
    next_send: Instant,
    retry: Duration,
    max_retry: Duration,
    ready: bool,
}

impl HandshakeClient {
    pub fn new(
        session: SessionId,
        now: Instant,
        hello_retry: Duration,
        setup_timeout: Duration,
    ) -> Result<Self, ProtocolError> {
        if hello_retry.is_zero() {
            return Err(ProtocolError::InvalidLimit("hello_retry"));
        }
        if setup_timeout.is_zero() {
            return Err(ProtocolError::InvalidLimit("setup_timeout"));
        }
        let deadline = now
            .checked_add(setup_timeout)
            .ok_or(ProtocolError::InvalidLimit("setup_timeout"))?;
        Ok(Self {
            session,
            started: now,
            deadline,
            next_send: now,
            retry: hello_retry,
            max_retry: hello_retry.saturating_mul(8),
            ready: false,
        })
    }

    pub const fn session(&self) -> SessionId {
        self.session
    }

    pub const fn is_ready(&self) -> bool {
        self.ready
    }

    pub const fn started(&self) -> Instant {
        self.started
    }

    pub fn poll(&mut self, now: Instant) -> Result<Option<Vec<u8>>, ProtocolError> {
        if self.ready {
            return Ok(None);
        }
        if now >= self.deadline {
            return Err(ProtocolError::SetupTimeout);
        }
        if now < self.next_send {
            return Ok(None);
        }
        let hello = control(FrameKind::Hello, self.session)?;
        self.next_send = now
            .checked_add(self.retry)
            .ok_or(ProtocolError::InvalidLimit("hello_retry"))?;
        self.retry = self.retry.saturating_mul(2).min(self.max_retry);
        Ok(Some(hello))
    }

    pub fn receive(&mut self, datagram: &[u8]) -> Result<bool, ProtocolError> {
        let frame = decode(datagram)?;
        if frame.kind != FrameKind::Ready {
            return Err(ProtocolError::UnexpectedFrame(frame.kind));
        }
        if frame.session != self.session {
            return Ok(false);
        }
        self.ready = true;
        Ok(true)
    }
}

pub fn accept_hello(datagram: &[u8]) -> Result<SessionId, ProtocolError> {
    let frame = decode(datagram)?;
    if frame.kind != FrameKind::Hello {
        return Err(ProtocolError::UnexpectedFrame(frame.kind));
    }
    Ok(frame.session)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    TruncatedHeader { actual: usize },
    BadMagic,
    UnknownVersion(u8),
    UnknownKind(u8),
    MalformedControl(FrameKind),
    UnexpectedFrame(FrameKind),
    ZeroChunkCount,
    ChunkIndexOutOfRange { index: u16, count: u16 },
    PayloadExceedsTotal { payload: usize, total: u32 },
    InconsistentEmptyMessage,
    InconsistentTotalLength { declared: usize, received: usize },
    DatagramTooSmall { actual: usize, required: usize },
    MessageTooLarge { actual: usize, limit: usize },
    TooManyChunks { actual: usize, limit: u16 },
    TooManyIncompleteMessages { limit: usize },
    TooManyCompletedMessages { limit: usize },
    ReassemblyBytesExceeded { limit: usize },
    ConflictingMetadata { message_id: u64 },
    ConflictingDuplicate { message_id: u64, chunk_index: u16 },
    WrongSession,
    OrderedMessageExpired { message_id: u64 },
    SessionFailed,
    SetupTimeout,
    MessageIdExhausted,
    LimitTooLarge(&'static str),
    InvalidLimit(&'static str),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            max_message_size: 4096,
            max_chunks: 64,
            max_incomplete_messages: 4,
            max_reassembly_bytes: 8192,
            max_completed_messages: 4,
            incomplete_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn golden_hello_vector() {
        let session = SessionId::from_u128(0x000102030405060708090a0b0c0d0e0f);
        let encoded = control(FrameKind::Hello, session).unwrap();
        assert_eq!(
            hex(&encoded),
            "574650310101000102030405060708090a0b0c0d0e0f00000000000000000000000000000000"
        );
        assert_eq!(decode(&encoded).unwrap().kind, FrameKind::Hello);
    }

    #[test]
    fn golden_data_vector() {
        let session = SessionId::from_u128(0x000102030405060708090a0b0c0d0e0f);
        let encoded = Frame {
            kind: FrameKind::Data,
            session,
            message_id: 0x1011121314151617,
            chunk_index: 1,
            chunk_count: 3,
            total_len: 9,
            payload: b"def",
        }
        .encode()
        .unwrap();
        assert_eq!(
            hex(&encoded),
            "574650310103000102030405060708090a0b0c0d0e0f10111213141516170001000300000009646566"
        );
    }

    #[test]
    fn single_and_multi_chunk_round_trip_with_dynamic_capacity() {
        let session = SessionId::from_u128(7);
        let now = Instant::now();
        for max in [HEADER_LEN + 1, HEADER_LEN + 3, HEADER_LEN + 100] {
            let message = b"abcdefghij";
            let chunks = chunk_message(session, 0, message, max, limits()).unwrap();
            assert!(chunks.iter().all(|chunk| chunk.len() <= max));
            let mut reassembler = Reassembler::new(session, limits()).unwrap();
            let mut delivered = Vec::new();
            for chunk in chunks {
                delivered.extend(reassembler.ingest(&chunk, now).unwrap());
            }
            assert_eq!(delivered[0].payload, message);
        }
    }

    #[test]
    fn out_of_order_and_duplicate_chunks_are_idempotent() {
        let session = SessionId::from_u128(8);
        let now = Instant::now();
        let chunks = chunk_message(session, 0, b"abcdefghij", HEADER_LEN + 3, limits()).unwrap();
        let mut reassembler = Reassembler::new(session, limits()).unwrap();
        assert!(reassembler.ingest(&chunks[2], now).unwrap().is_empty());
        assert!(reassembler.ingest(&chunks[2], now).unwrap().is_empty());
        assert!(reassembler.ingest(&chunks[0], now).unwrap().is_empty());
        assert!(reassembler.ingest(&chunks[3], now).unwrap().is_empty());
        let delivered = reassembler.ingest(&chunks[1], now).unwrap();
        assert_eq!(delivered[0].payload, b"abcdefghij");
    }

    #[test]
    fn conflicting_duplicate_fails_session() {
        let session = SessionId::from_u128(9);
        let now = Instant::now();
        let chunks = chunk_message(session, 0, b"abcdef", HEADER_LEN + 3, limits()).unwrap();
        let mut bad = chunks[0].clone();
        *bad.last_mut().unwrap() ^= 1;
        let mut reassembler = Reassembler::new(session, limits()).unwrap();
        reassembler.ingest(&chunks[0], now).unwrap();
        assert!(matches!(
            reassembler.ingest(&bad, now),
            Err(ProtocolError::ConflictingDuplicate { .. })
        ));
        assert_eq!(
            reassembler.ingest(&chunks[1], now),
            Err(ProtocolError::SessionFailed)
        );
    }

    #[test]
    fn missing_earlier_message_blocks_then_expires() {
        let session = SessionId::from_u128(10);
        let now = Instant::now();
        let later = chunk_message(session, 1, b"later", HEADER_LEN + 100, limits()).unwrap();
        let mut reassembler = Reassembler::new(session, limits()).unwrap();
        assert!(reassembler.ingest(&later[0], now).unwrap().is_empty());
        assert_eq!(
            reassembler.expire(now + Duration::from_secs(5)),
            Err(ProtocolError::OrderedMessageExpired { message_id: 0 })
        );
    }

    #[test]
    fn ordered_delivery_waits_for_earlier_completion() {
        let session = SessionId::from_u128(11);
        let now = Instant::now();
        let first = chunk_message(session, 0, b"first", HEADER_LEN + 3, limits()).unwrap();
        let second = chunk_message(session, 1, b"second", HEADER_LEN + 100, limits()).unwrap();
        let mut reassembler = Reassembler::new(session, limits()).unwrap();
        assert!(reassembler.ingest(&first[0], now).unwrap().is_empty());
        assert!(reassembler.ingest(&second[0], now).unwrap().is_empty());
        let delivered = reassembler.ingest(&first[1], now).unwrap();
        assert_eq!(
            delivered
                .iter()
                .map(|message| message.payload.as_slice())
                .collect::<Vec<_>>(),
            vec![b"first".as_slice(), b"second".as_slice()]
        );
    }

    #[test]
    fn malformed_unknown_and_resource_limits_are_rejected() {
        assert!(matches!(
            decode(&[]),
            Err(ProtocolError::TruncatedHeader { .. })
        ));
        let mut hello = control(FrameKind::Hello, SessionId::from_u128(1)).unwrap();
        hello[4] = 2;
        assert_eq!(decode(&hello), Err(ProtocolError::UnknownVersion(2)));
        hello[4] = VERSION;
        hello[5] = 99;
        assert_eq!(decode(&hello), Err(ProtocolError::UnknownKind(99)));
        assert!(matches!(
            chunk_message(
                SessionId::from_u128(1),
                0,
                &[0; 4097],
                HEADER_LEN + 100,
                limits()
            ),
            Err(ProtocolError::MessageTooLarge { .. })
        ));
        assert!(matches!(
            chunk_message(SessionId::from_u128(1), 0, b"x", HEADER_LEN, limits()),
            Err(ProtocolError::DatagramTooSmall { .. })
        ));
    }

    #[test]
    fn inconsistent_headers_lengths_and_waiting_completions_are_rejected() {
        let session = SessionId::from_u128(15);
        let now = Instant::now();

        let mut hello = control(FrameKind::Hello, session).unwrap();
        hello[0] ^= 1;
        assert_eq!(decode(&hello), Err(ProtocolError::BadMagic));

        let malformed_control = Frame {
            kind: FrameKind::Ping,
            session,
            message_id: 1,
            chunk_index: 0,
            chunk_count: 0,
            total_len: 0,
            payload: &[],
        };
        assert_eq!(
            malformed_control.encode(),
            Err(ProtocolError::MalformedControl(FrameKind::Ping))
        );

        let zero_chunks = Frame {
            kind: FrameKind::Data,
            session,
            message_id: 0,
            chunk_index: 0,
            chunk_count: 0,
            total_len: 1,
            payload: b"x",
        };
        assert_eq!(zero_chunks.encode(), Err(ProtocolError::ZeroChunkCount));
        let bad_index = Frame {
            chunk_count: 1,
            chunk_index: 1,
            ..zero_chunks
        };
        assert!(matches!(
            bad_index.encode(),
            Err(ProtocolError::ChunkIndexOutOfRange { .. })
        ));

        let first = Frame {
            kind: FrameKind::Data,
            session,
            message_id: 0,
            chunk_index: 0,
            chunk_count: 2,
            total_len: 7,
            payload: b"abc",
        }
        .encode()
        .unwrap();
        let second = Frame {
            kind: FrameKind::Data,
            session,
            message_id: 0,
            chunk_index: 1,
            chunk_count: 2,
            total_len: 7,
            payload: b"def",
        }
        .encode()
        .unwrap();
        let mut reassembler = Reassembler::new(session, limits()).unwrap();
        reassembler.ingest(&first, now).unwrap();
        assert!(matches!(
            reassembler.ingest(&second, now),
            Err(ProtocolError::InconsistentTotalLength { .. })
        ));

        let mut constrained = limits();
        constrained.max_chunks = 1;
        let chunks = chunk_message(session, 0, b"ab", HEADER_LEN + 1, limits()).unwrap();
        assert!(matches!(
            Reassembler::new(session, constrained)
                .unwrap()
                .ingest(&chunks[0], now),
            Err(ProtocolError::TooManyChunks { .. })
        ));

        let mut constrained = limits();
        constrained.max_completed_messages = 1;
        let later = chunk_message(session, 1, b"one", HEADER_LEN + 10, limits()).unwrap();
        let latest = chunk_message(session, 2, b"two", HEADER_LEN + 10, limits()).unwrap();
        let mut reassembler = Reassembler::new(session, constrained).unwrap();
        reassembler.ingest(&later[0], now).unwrap();
        assert!(matches!(
            reassembler.ingest(&latest[0], now),
            Err(ProtocolError::TooManyCompletedMessages { .. })
        ));
    }

    #[test]
    fn reassembly_byte_and_incomplete_count_limits_are_enforced() {
        let session = SessionId::from_u128(12);
        let now = Instant::now();
        let mut constrained = limits();
        constrained.max_incomplete_messages = 1;
        constrained.max_reassembly_bytes = 3;
        let a = chunk_message(session, 0, b"abcdef", HEADER_LEN + 3, limits()).unwrap();
        let b = chunk_message(session, 1, b"ghijkl", HEADER_LEN + 3, limits()).unwrap();
        let mut reassembler = Reassembler::new(session, constrained).unwrap();
        reassembler.ingest(&a[0], now).unwrap();
        assert!(matches!(
            reassembler.ingest(&b[0], now),
            Err(ProtocolError::TooManyIncompleteMessages { .. })
        ));
        assert!(matches!(
            reassembler.ingest(&a[1], now),
            Err(ProtocolError::ReassemblyBytesExceeded { .. })
        ));
    }

    #[test]
    fn hello_retries_with_backoff_and_only_matching_ready_establishes() {
        let session = SessionId::from_u128(13);
        let now = Instant::now();
        let mut handshake = HandshakeClient::new(
            session,
            now,
            Duration::from_millis(100),
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(handshake.poll(now).unwrap().is_some());
        assert!(handshake
            .poll(now + Duration::from_millis(99))
            .unwrap()
            .is_none());
        assert!(handshake
            .poll(now + Duration::from_millis(100))
            .unwrap()
            .is_some());
        let stale = control(FrameKind::Ready, SessionId::from_u128(12)).unwrap();
        assert!(!handshake.receive(&stale).unwrap());
        assert!(!handshake.is_ready());
        let ready = control(FrameKind::Ready, session).unwrap();
        assert!(handshake.receive(&ready).unwrap());
        assert!(handshake.is_ready());
        assert!(handshake
            .poll(now + Duration::from_secs(1))
            .unwrap()
            .is_none());
    }

    #[test]
    fn setup_timeout_is_bounded() {
        let now = Instant::now();
        let mut handshake = HandshakeClient::new(
            SessionId::from_u128(14),
            now,
            Duration::from_millis(100),
            Duration::from_millis(500),
        )
        .unwrap();
        assert_eq!(
            handshake.poll(now + Duration::from_millis(500)),
            Err(ProtocolError::SetupTimeout)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
