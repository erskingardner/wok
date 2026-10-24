//! Minimal RFC 6455 frame codec plus RFC 7692 permessage-deflate.
//!
//! Server-side only: reads masked client frames, writes unmasked server
//! frames. Negotiation mirrors C++ uWS as configured by strfry: plain
//! `permessage-deflate` with context takeover (sliding window) by default,
//! `client_no_context_takeover` echoed when the client offers it.

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const OP_CONT: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

fn apply_mask(payload: &mut [u8], mask: [u8; 4]) {
    let mut chunks = payload.chunks_exact_mut(4);
    for chunk in &mut chunks {
        chunk[0] ^= mask[0];
        chunk[1] ^= mask[1];
        chunk[2] ^= mask[2];
        chunk[3] ^= mask[3];
    }
    for (byte, mask) in chunks.into_remainder().iter_mut().zip(mask) {
        *byte ^= mask;
    }
}

#[derive(Debug)]
pub enum WsError {
    Io(std::io::Error),
    Protocol(&'static str),
    MessageTooLarge,
    Inflate(String),
    Deflate(String),
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::MessageTooLarge => write!(f, "message too large"),
            Self::Inflate(e) => write!(f, "inflate: {e}"),
            Self::Deflate(e) => write!(f, "deflate: {e}"),
        }
    }
}

impl std::error::Error for WsError {}

impl From<std::io::Error> for WsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Text,
    Binary,
}

#[derive(Debug)]
pub enum WsEvent {
    Message(MessageKind, Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Vec<u8>),
}

/// Outbound compression level. Level 1 is what uWS uses for strfry. On Nostr
/// events it costs less than half the CPU of zlib's default level 6, for
/// 4–15% more bytes (wok-bench `--scenario ws_transport` measures both).
pub const DEFAULT_LEVEL: u32 = 1;

/// The farthest back a client's compressor may refer: RFC 7692 windows are
/// at most 2^15 bytes, and the server never asks for less.
const WINDOW: usize = 1 << 15;

/// RFC 7692 inflater for one connection. With `takeover` the client may refer
/// back into earlier messages, so their history is kept between messages.
///
/// The decompressor (about 40 KiB) is created by the first compressed message
/// rather than at upgrade, and [`InflateCtx::release_idle`] drops it again
/// once the client has gone quiet. A client using context takeover may still
/// refer back up to 32 KiB into what it sent before, so while takeover is on
/// the most recent output is copied aside and replayed into the next
/// decompressor, as one stored block, before the client's next message.
pub struct InflateCtx {
    takeover: bool,
    inner: Option<flate2::Decompress>,
    /// The last `WINDOW` bytes of output when `takeover`, oldest first from
    /// `head` once full.
    history: Vec<u8>,
    head: usize,
    used: bool,
}

impl InflateCtx {
    pub fn new(takeover: bool) -> Self {
        Self {
            takeover,
            inner: None,
            history: Vec::new(),
            head: 0,
            used: false,
        }
    }

    /// Inflate one message payload after re-appending the sync-flush marker.
    pub fn decompress(&mut self, payload: &[u8], max_out: usize) -> Result<Vec<u8>, WsError> {
        self.used = true;
        let inner = match &mut self.inner {
            Some(inner) => {
                if !self.takeover {
                    inner.reset(false);
                }
                inner
            }
            None => {
                let mut inner = flate2::Decompress::new(false);
                if !self.history.is_empty() {
                    let len = self.history.len() as u16;
                    let mut block = Vec::with_capacity(self.history.len() + 5);
                    // BFINAL 0, BTYPE 00 (stored), padded to a byte; LEN, NLEN.
                    block.push(0);
                    block.extend_from_slice(&len.to_le_bytes());
                    block.extend_from_slice(&(!len).to_le_bytes());
                    block.extend_from_slice(&self.history[self.head..]);
                    block.extend_from_slice(&self.history[..self.head]);
                    let mut replayed = Vec::with_capacity(self.history.len() + 64);
                    inflate_into(&mut inner, &block, &mut replayed, WINDOW)?;
                    if replayed.len() != self.history.len() {
                        return Err(WsError::Inflate("history replay".into()));
                    }
                }
                self.inner.insert(inner)
            }
        };
        let mut input = Vec::with_capacity(payload.len() + 4);
        input.extend_from_slice(payload);
        input.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
        let mut out = Vec::with_capacity(payload.len().saturating_mul(3).clamp(64, 1 << 20));
        inflate_into(inner, &input, &mut out, max_out)?;
        if self.takeover {
            self.remember(&out);
        }
        Ok(out)
    }

    /// Append to the history ring, which grows to at most `WINDOW` bytes.
    fn remember(&mut self, mut data: &[u8]) {
        if data.len() >= WINDOW {
            data = &data[data.len() - WINDOW..];
            self.history.clear();
            self.head = 0;
        }
        let fill = (WINDOW - self.history.len()).min(data.len());
        if fill > 0 {
            if self.history.len() + fill > self.history.capacity() {
                let want = (self.history.len() + fill)
                    .max(self.history.capacity() * 2)
                    .min(WINDOW);
                self.history.reserve_exact(want - self.history.len());
            }
            self.history.extend_from_slice(&data[..fill]);
            data = &data[fill..];
        }
        while !data.is_empty() {
            let n = (WINDOW - self.head).min(data.len());
            self.history[self.head..self.head + n].copy_from_slice(&data[..n]);
            self.head = (self.head + n) % WINDOW;
            data = &data[n..];
        }
    }

    /// Drop the decompressor if no message used it since the previous call,
    /// keeping only the history a client using takeover may refer back to.
    pub fn release_idle(&mut self) {
        if !std::mem::take(&mut self.used) && self.inner.take().is_some() {
            self.history.rotate_left(self.head);
            self.head = 0;
            self.history.shrink_to_fit();
        }
    }

    /// Whether the decompressor is currently allocated.
    pub fn is_allocated(&self) -> bool {
        self.inner.is_some()
    }
}

/// Inflate all of `input` into `out`, failing once it passes `max_out`.
fn inflate_into(
    inner: &mut flate2::Decompress,
    input: &[u8],
    out: &mut Vec<u8>,
    max_out: usize,
) -> Result<(), WsError> {
    let start_in = inner.total_in();
    loop {
        // Each call may write only up to one byte past `max_out`, whatever
        // the vector's capacity, so a refused message never costs more.
        let room = (max_out + 1).saturating_sub(out.len()).min(32 * 1024);
        let len = out.len();
        out.resize(len + room, 0);
        let consumed = (inner.total_in() - start_in) as usize;
        let in_before = inner.total_in();
        let out_before = inner.total_out();
        let result = inner.decompress(
            &input[consumed..],
            &mut out[len..],
            flate2::FlushDecompress::Sync,
        );
        out.truncate(len + (inner.total_out() - out_before) as usize);
        result.map_err(|e| WsError::Inflate(e.to_string()))?;
        if out.len() > max_out {
            return Err(WsError::MessageTooLarge);
        }
        let progressed = inner.total_in() != in_before || inner.total_out() != out_before;
        if !progressed {
            break;
        }
    }
    Ok(())
}

/// RFC 7692 deflater for one connection. With `takeover` (strfry's
/// `compression.slidingWindow`, default true) each message is compressed
/// against the history of the previous ones.
///
/// The compressor (about 300 KiB with miniz_oxide) is created by the first
/// message rather than at upgrade, and [`DeflateCtx::release_idle`] drops it
/// again once the connection has gone quiet. Dropping it is always safe:
/// takeover lets the server refer back into earlier messages but never
/// obliges it to, and the client keeps its own window either way, so the
/// next message simply starts from an empty history.
pub struct DeflateCtx {
    takeover: bool,
    level: flate2::Compression,
    inner: Option<flate2::Compress>,
    used: bool,
}

impl DeflateCtx {
    pub fn new(takeover: bool) -> Self {
        Self::with_level(takeover, DEFAULT_LEVEL)
    }

    pub fn with_level(takeover: bool, level: u32) -> Self {
        Self {
            takeover,
            level: flate2::Compression::new(level),
            inner: None,
            used: false,
        }
    }

    /// Compress with Z_SYNC_FLUSH and strip the trailing `00 00 ff ff`.
    pub fn compress(&mut self, msg: &[u8]) -> Result<Vec<u8>, WsError> {
        self.used = true;
        let inner = match &mut self.inner {
            Some(inner) => {
                if !self.takeover {
                    inner.reset();
                }
                inner
            }
            None => self.inner.insert(flate2::Compress::new(self.level, false)),
        };
        let mut out = Vec::with_capacity(msg.len() / 2 + 64);
        let start_in = inner.total_in();
        loop {
            if out.capacity() - out.len() < 64 {
                out.reserve(32 * 1024);
            }
            let consumed = (inner.total_in() - start_in) as usize;
            let in_before = inner.total_in();
            let out_before = inner.total_out();
            inner
                .compress_vec(&msg[consumed..], &mut out, flate2::FlushCompress::Sync)
                .map_err(|e| WsError::Deflate(e.to_string()))?;
            let all_consumed = (inner.total_in() - start_in) as usize == msg.len();
            if all_consumed && out.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
                break;
            }
            let progressed = inner.total_in() != in_before || inner.total_out() != out_before;
            if !progressed && all_consumed {
                break;
            }
        }
        if out.len() < 4 {
            return Err(WsError::Deflate("short compressed block".into()));
        }
        out.truncate(out.len() - 4);
        Ok(out)
    }

    /// Drop the compressor if no message used it since the previous call.
    pub fn release_idle(&mut self) {
        if !std::mem::take(&mut self.used) {
            self.inner = None;
        }
    }

    /// Whether the compressor is currently allocated.
    pub fn is_allocated(&self) -> bool {
        self.inner.is_some()
    }
}

/// Which side of the connection this endpoint is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Server: clients must mask; we don't.
    Server,
    /// Client: servers must not mask; we must.
    Client,
}

/// Read buffer a connection keeps between messages, which most client
/// messages fit. A read that fills the buffer grows it by `READ_CHUNK` for the
/// next, and once drained after a read that did not fill it (the client
/// paused) it shrinks back, so idle connections do not each pin 16 KiB.
const READ_IDLE: usize = 1024;
const READ_CHUNK: usize = 16 * 1024;

/// Incremental frame parser + message assembler (read half).
pub struct WsParser {
    max_message: usize,
    buf: BytesMut,
    /// The last socket read filled all the room the buffer had.
    read_filled: bool,
    /// The buffer may have grown past `READ_IDLE`.
    grown: bool,
    frag_opcode: Option<u8>,
    frag_rsv1: bool,
    frag: Vec<u8>,
    inflater: Option<InflateCtx>,
    role: Role,
}

impl WsParser {
    pub fn new(max_message: usize, inflater: Option<InflateCtx>) -> Self {
        Self::with_role(max_message, inflater, Role::Server)
    }

    pub fn with_role(max_message: usize, inflater: Option<InflateCtx>, role: Role) -> Self {
        Self {
            max_message,
            buf: BytesMut::with_capacity(READ_IDLE),
            read_filled: false,
            grown: false,
            frag_opcode: None,
            frag_rsv1: false,
            frag: Vec::new(),
            inflater,
            role,
        }
    }

    /// Drop an idle inflater (see [`InflateCtx::release_idle`]).
    pub fn release_idle(&mut self) {
        if let Some(inflater) = &mut self.inflater {
            inflater.release_idle();
        }
    }

    /// Feed read bytes; returns events for every complete message/control
    /// frame parsed.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<WsEvent>, WsError> {
        self.buf.extend_from_slice(data);
        let mut events = Vec::new();
        self.drain_events_into(&mut events, usize::MAX)?;
        Ok(events)
    }

    /// Decode buffered frames into `events` until about `budget` bytes of
    /// messages are decoded. Frames past it stay buffered, still compressed,
    /// for the next call, so a read full of small compressed frames is not
    /// all inflated before the caller can hold or refuse any of it.
    fn drain_events_into(
        &mut self,
        events: &mut Vec<WsEvent>,
        budget: usize,
    ) -> Result<(), WsError> {
        // At least one frame is parsed, so its limits are checked whatever
        // the budget.
        let mut decoded = 0usize;
        while let Some(frame) = self.try_parse_frame()? {
            if let Some(ev) = self.handle_frame(frame)? {
                if let WsEvent::Message(_, payload) = &ev {
                    decoded = decoded.saturating_add(payload.len());
                }
                events.push(ev);
            }
            if decoded >= budget {
                break;
            }
        }
        Ok(())
    }

    fn try_parse_frame(&mut self) -> Result<Option<RawFrame>, WsError> {
        let b = &self.buf[..];
        if b.len() < 2 {
            return Ok(None);
        }
        let b0 = b[0];
        let b1 = b[1];
        let fin = b0 & 0x80 != 0;
        let rsv1 = b0 & 0x40 != 0;
        let rsv2 = b0 & 0x20 != 0;
        let rsv3 = b0 & 0x10 != 0;
        let opcode = b0 & 0x0F;
        if rsv2 || rsv3 {
            return Err(WsError::Protocol("RSV2/RSV3 set"));
        }
        if rsv1 && self.inflater.is_none() {
            return Err(WsError::Protocol("RSV1 set without negotiated extension"));
        }
        let masked = b1 & 0x80 != 0;
        match self.role {
            Role::Server => {
                if !masked {
                    return Err(WsError::Protocol("client frame not masked"));
                }
            }
            Role::Client => {
                if masked {
                    return Err(WsError::Protocol("server frame masked"));
                }
            }
        }
        let mut len = (b1 & 0x7F) as u64;
        let mut off = 2;
        if len == 126 {
            if b.len() < off + 2 {
                return Ok(None);
            }
            len = u16::from_be_bytes([b[off], b[off + 1]]) as u64;
            off += 2;
        } else if len == 127 {
            if b.len() < off + 8 {
                return Ok(None);
            }
            len = u64::from_be_bytes(b[off..off + 8].try_into().unwrap());
            off += 8;
            if len & (1 << 63) != 0 {
                return Err(WsError::Protocol("2^63 length"));
            }
        }
        let is_control = opcode >= 0x8;
        if is_control {
            if !fin {
                return Err(WsError::Protocol("fragmented control frame"));
            }
            if len > 125 {
                return Err(WsError::Protocol("control frame too large"));
            }
        }
        if len as usize > self.max_message {
            return Err(WsError::MessageTooLarge);
        }
        let mask: Option<[u8; 4]> = if masked {
            if b.len() < off + 4 + len as usize {
                return Ok(None);
            }
            let m: [u8; 4] = b[off..off + 4].try_into().unwrap();
            off += 4;
            Some(m)
        } else {
            if b.len() < off + len as usize {
                return Ok(None);
            }
            None
        };
        let mut payload = b[off..off + len as usize].to_vec();
        if let Some(mask) = mask {
            apply_mask(&mut payload, mask);
        }
        self.buf.advance(off + len as usize);
        Ok(Some(RawFrame {
            fin,
            rsv1,
            opcode,
            payload,
        }))
    }

    fn handle_frame(&mut self, frame: RawFrame) -> Result<Option<WsEvent>, WsError> {
        match frame.opcode {
            OP_PING => Ok(Some(WsEvent::Ping(frame.payload))),
            OP_PONG => Ok(Some(WsEvent::Pong(frame.payload))),
            OP_CLOSE => Ok(Some(WsEvent::Close(frame.payload))),
            OP_TEXT | OP_BINARY => {
                if self.frag_opcode.is_some() {
                    return Err(WsError::Protocol("new message during fragmented message"));
                }
                if frame.fin {
                    let payload = self.maybe_inflate(frame.rsv1, frame.payload)?;
                    Ok(Some(WsEvent::Message(
                        if frame.opcode == OP_TEXT {
                            MessageKind::Text
                        } else {
                            MessageKind::Binary
                        },
                        payload,
                    )))
                } else {
                    self.frag_opcode = Some(frame.opcode);
                    self.frag_rsv1 = frame.rsv1;
                    self.frag = frame.payload;
                    if self.frag.len() > self.max_message {
                        return Err(WsError::MessageTooLarge);
                    }
                    Ok(None)
                }
            }
            OP_CONT => {
                if self.frag_opcode.is_none() {
                    return Err(WsError::Protocol("continuation without message"));
                }
                self.frag.extend_from_slice(&frame.payload);
                if self.frag.len() > self.max_message {
                    return Err(WsError::MessageTooLarge);
                }
                if frame.fin {
                    let opcode = self.frag_opcode.take().unwrap();
                    let rsv1 = self.frag_rsv1;
                    let frag = std::mem::take(&mut self.frag);
                    let payload = self.maybe_inflate(rsv1, frag)?;
                    Ok(Some(WsEvent::Message(
                        if opcode == OP_TEXT {
                            MessageKind::Text
                        } else {
                            MessageKind::Binary
                        },
                        payload,
                    )))
                } else {
                    Ok(None)
                }
            }
            _ => Err(WsError::Protocol("unknown opcode")),
        }
    }

    fn maybe_inflate(&mut self, rsv1: bool, payload: Vec<u8>) -> Result<Vec<u8>, WsError> {
        if rsv1 {
            let max = inflate_limit(payload.len(), self.max_message);
            match &mut self.inflater {
                Some(d) => d.decompress(&payload, max),
                None => Err(WsError::Protocol("RSV1 without extension")),
            }
        } else {
            Ok(payload)
        }
    }
}

/// How many times its compressed size a message may inflate to past
/// `inflate_allowance`.
const MAX_INFLATE_RATIO: usize = 32;

/// Room for a message's envelope around the largest event.
const INFLATE_ENVELOPE: usize = 64 * 1024;

/// What any compressed message may inflate to whatever its ratio: half the
/// maximum message size and an envelope, which by default holds the largest
/// event however repetitive its content.
fn inflate_allowance(max_message: usize) -> usize {
    max_message / 2 + INFLATE_ENVELOPE
}

/// The most a compressed message of `wire_len` bytes may inflate to: its
/// allowance, or 32 times its compressed size if more, up to the maximum.
fn inflate_limit(wire_len: usize, max_message: usize) -> usize {
    wire_len
        .saturating_mul(MAX_INFLATE_RATIO)
        .max(inflate_allowance(max_message))
        .min(max_message)
}

struct RawFrame {
    fin: bool,
    rsv1: bool,
    opcode: u8,
    payload: Vec<u8>,
}

/// Frame serializer (write half).
pub struct WsEncoder {
    deflater: Option<DeflateCtx>,
    role: Role,
    mask_counter: std::cell::Cell<u32>,
}

impl WsEncoder {
    pub fn new(deflater: Option<DeflateCtx>) -> Self {
        Self::with_role(deflater, Role::Server)
    }

    pub fn with_role(deflater: Option<DeflateCtx>, role: Role) -> Self {
        Self {
            deflater,
            role,
            mask_counter: std::cell::Cell::new(0x9e3779b9),
        }
    }

    /// Encode one frame. Servers never mask (RFC 6455); clients mask with a
    /// simple xorshift-generated mask (masking is not a security boundary
    /// here, it just needs to be present and varying).
    pub fn encode_frame(
        &self,
        fin: bool,
        rsv1: bool,
        opcode: u8,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) {
        let b0 = (if fin { 0x80 } else { 0 }) | (if rsv1 { 0x40 } else { 0 }) | opcode;
        out.push(b0);
        let mask_bit = match self.role {
            Role::Server => 0u8,
            Role::Client => 0x80,
        };
        let len = payload.len();
        if len < 126 {
            out.push(mask_bit | len as u8);
        } else if len <= 0xFFFF {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        if self.role == Role::Client {
            let mut x = self.mask_counter.get();
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.mask_counter.set(x);
            let mask = x.to_be_bytes();
            out.extend_from_slice(&mask);
            let start = out.len();
            out.extend_from_slice(payload);
            apply_mask(&mut out[start..], mask);
        } else {
            out.extend_from_slice(payload);
        }
    }

    /// Build a complete (unfragmented) message frame, compressing when
    /// permessage-deflate is active.
    pub fn encode_message(
        &mut self,
        kind: MessageKind,
        payload: &[u8],
    ) -> Result<Vec<u8>, WsError> {
        let mut out = Vec::with_capacity(payload.len() + 14);
        self.encode_message_into(kind, payload, &mut out)?;
        Ok(out)
    }

    /// [`WsEncoder::encode_message`], appending the frame to `out`.
    pub fn encode_message_into(
        &mut self,
        kind: MessageKind,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), WsError> {
        let opcode = match kind {
            MessageKind::Text => OP_TEXT,
            MessageKind::Binary => OP_BINARY,
        };
        if let Some(d) = &mut self.deflater {
            let compressed = d.compress(payload)?;
            self.encode_frame(true, true, opcode, &compressed, out);
        } else {
            out.reserve(payload.len() + 14);
            self.encode_frame(true, false, opcode, payload, out);
        }
        Ok(())
    }

    /// Drop an idle compressor (see [`DeflateCtx::release_idle`]).
    pub fn release_idle(&mut self) {
        if let Some(deflater) = &mut self.deflater {
            deflater.release_idle();
        }
    }

    pub fn encode_control(&self, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 14);
        self.encode_frame(true, false, opcode, payload, &mut out);
        out
    }
}

/// Read events from an async stream until at least one is available.
pub async fn read_events<S: AsyncRead + Unpin>(
    stream: &mut S,
    parser: &mut WsParser,
) -> Result<Vec<WsEvent>, WsError> {
    let mut events = Vec::new();
    let mut no_deadline = None;
    read_events_into(stream, parser, &mut events, None, &mut no_deadline).await?;
    Ok(events)
}

pub async fn read_events_into<S: AsyncRead + Unpin>(
    stream: &mut S,
    parser: &mut WsParser,
    events: &mut Vec<WsEvent>,
    frame_idle_timeout: Option<std::time::Duration>,
    frame_deadline: &mut Option<tokio::time::Instant>,
) -> Result<(), WsError> {
    events.clear();
    // Frames a previous call left buffered past its budget come first.
    parser.drain_events_into(events, parser.max_message)?;
    if !events.is_empty() {
        return Ok(());
    }
    loop {
        // Read directly into the parser's retained buffer. The previous
        // stack-buffer path copied every inbound WebSocket byte a second time
        // before masking and JSON parsing.
        //
        // While a partial frame or an unfinished fragmented message is
        // buffered, bound the idle gap between socket reads: a client may
        // otherwise declare a large frame and dribble its payload, pinning
        // the assembly buffer indefinitely. The deadline is owned by the
        // caller so it survives select! cancellation of this future, and it
        // advances only on an actual socket read — unrelated outbound
        // traffic waking the select must not restart the guard.
        let assembly_pending = !parser.buf.is_empty() || parser.frag_opcode.is_some();
        let want = if parser.read_filled {
            READ_CHUNK
        } else {
            READ_IDLE
        };
        if parser.buf.capacity() - parser.buf.len() < want / 2 {
            // An empty buffer reclaims its own allocation; otherwise it grows.
            parser.grown |= !parser.buf.is_empty() || want > READ_IDLE;
            parser.buf.reserve(want);
        }
        let room = parser.buf.capacity() - parser.buf.len();
        let n = match frame_idle_timeout.filter(|_| assembly_pending) {
            Some(gap) => {
                let deadline =
                    frame_deadline.get_or_insert_with(|| tokio::time::Instant::now() + gap);
                match tokio::time::timeout_at(*deadline, stream.read_buf(&mut parser.buf)).await {
                    Ok(res) => res?,
                    Err(_) => return Err(WsError::Protocol("frame read timeout")),
                }
            }
            None => stream.read_buf(&mut parser.buf).await?,
        };
        if n == 0 {
            return Err(WsError::Protocol("eof"));
        }
        parser.read_filled = n >= room;
        parser.drain_events_into(events, parser.max_message)?;
        if parser.buf.is_empty() && !parser.read_filled && parser.grown {
            parser.buf = BytesMut::with_capacity(READ_IDLE);
            parser.grown = false;
        }
        // Arm or advance the deadline after every read that leaves assembly
        // pending — including the empty-to-partial transition where this
        // same read also produced events — so the guard is armed before the
        // caller dispatches those events (dispatch can await backpressure).
        if let Some(gap) = frame_idle_timeout {
            *frame_deadline = (!parser.buf.is_empty() || parser.frag_opcode.is_some())
                .then(|| tokio::time::Instant::now() + gap);
        }
        if !events.is_empty() {
            return Ok(());
        }
    }
}

pub async fn write_bytes<S: AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> Result<(), WsError> {
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked_frame(fin: bool, rsv1: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let b0 = (if fin { 0x80 } else { 0 }) | (if rsv1 { 0x40 } else { 0 }) | opcode;
        out.push(b0);
        let mask = [1u8, 2, 3, 4];
        let len = payload.len();
        if len < 126 {
            out.push(0x80 | len as u8);
        } else {
            out.push(0x80 | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        out.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            out.push(b ^ mask[i % 4]);
        }
        out
    }

    #[test]
    fn parses_masked_text() {
        let mut c = WsParser::new(1 << 20, None);
        let events = c
            .feed(&masked_frame(true, false, OP_TEXT, b"hello"))
            .unwrap();
        match &events[0] {
            WsEvent::Message(MessageKind::Text, p) => assert_eq!(p, b"hello"),
            _ => panic!(),
        }
    }

    #[tokio::test]
    async fn a_zero_message_limit_still_refuses_a_frame() {
        let wire = masked_frame(true, false, OP_TEXT, b"hi");
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tx.write_all(&wire).await.unwrap();
        let mut parser = WsParser::new(0, None);
        let mut events = Vec::new();
        let mut deadline = None;
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            read_events_into(&mut rx, &mut parser, &mut events, None, &mut deadline),
        )
        .await
        .expect("the frame is parsed, not buffered forever");
        assert!(matches!(read, Err(WsError::MessageTooLarge)));
    }

    #[tokio::test]
    async fn one_read_is_decoded_a_message_at_a_time() {
        // One read carries four compressed messages, each half the maximum
        // when inflated. A call decodes about a maximum message's worth and
        // leaves the rest compressed; the next calls return it without
        // another read.
        let max = 64 * 1024;
        let message = vec![b'a'; max / 2];
        let mut client = DeflateCtx::new(false);
        let mut wire = Vec::new();
        for _ in 0..4 {
            let compressed = client.compress(&message).unwrap();
            wire.extend(masked_frame(true, true, OP_TEXT, &compressed));
        }
        let (mut tx, mut rx) = tokio::io::duplex(1 << 16);
        tx.write_all(&wire).await.unwrap();
        let mut parser = WsParser::new(max, Some(InflateCtx::new(false)));
        let mut events = Vec::new();
        let mut deadline = None;
        let mut decoded = Vec::new();
        for _ in 0..2 {
            read_events_into(&mut rx, &mut parser, &mut events, None, &mut deadline)
                .await
                .unwrap();
            decoded.push(events.len());
        }
        assert_eq!(decoded, [2, 2]);
    }

    #[tokio::test]
    async fn read_events_into_arms_deadline_when_read_leaves_partial_frame() {
        // One TCP read carries a complete text frame followed by the first
        // byte of the next frame's header. The parser starts empty, the
        // complete event is returned, and the partial successor stays
        // buffered: the idle deadline must be armed for it before the
        // caller dispatches the event (dispatch can await backpressure).
        let mut wire = masked_frame(true, false, OP_TEXT, b"hi");
        wire.push(0x81); // lone FIN+text opcode byte: partial next frame
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tx.write_all(&wire).await.unwrap();

        let mut parser = WsParser::new(1 << 20, None);
        let mut events = Vec::new();
        let mut deadline = None;
        read_events_into(
            &mut rx,
            &mut parser,
            &mut events,
            Some(std::time::Duration::from_secs(30)),
            &mut deadline,
        )
        .await
        .unwrap();

        assert_eq!(events.len(), 1);
        assert!(
            deadline.is_some(),
            "deadline must be armed for the retained partial frame"
        );
    }

    async fn read_all(
        rx: &mut tokio::io::DuplexStream,
        parser: &mut WsParser,
        n: usize,
    ) -> Vec<WsEvent> {
        let mut all = Vec::new();
        let mut events = Vec::new();
        let mut deadline = None;
        while all.len() < n {
            read_events_into(rx, parser, &mut events, None, &mut deadline)
                .await
                .unwrap();
            all.append(&mut events);
        }
        all
    }

    #[tokio::test]
    async fn read_buffer_stays_small_for_small_messages() {
        let (mut tx, mut rx) = tokio::io::duplex(1 << 20);
        let mut parser = WsParser::new(1 << 20, None);
        for i in 0..50 {
            let msg = format!("[\"REQ\",\"s{i}\",{{\"kinds\":[1],\"limit\":20}}]").repeat(6);
            tx.write_all(&masked_frame(true, false, OP_TEXT, msg.as_bytes()))
                .await
                .unwrap();
            let events = read_all(&mut rx, &mut parser, 1).await;
            assert!(matches!(&events[..], [WsEvent::Message(_, p)] if p == msg.as_bytes()));
            assert!(!parser.grown, "message {i} grew the buffer");
            assert!(parser.buf.capacity() <= READ_IDLE);
        }
    }

    #[tokio::test]
    async fn read_buffer_grows_for_large_or_streamed_input_then_shrinks() {
        let (mut tx, mut rx) = tokio::io::duplex(1 << 20);
        let mut parser = WsParser::new(1 << 20, None);
        let big = vec![b'x'; 40_000];
        tx.write_all(&masked_frame(true, false, OP_TEXT, &big))
            .await
            .unwrap();
        let events = read_all(&mut rx, &mut parser, 1).await;
        assert!(matches!(&events[..], [WsEvent::Message(_, p)] if p == &big));
        assert!(!parser.grown, "drained after a short read: shrunk");
        assert_eq!(parser.buf.capacity(), READ_IDLE);

        let mut burst = Vec::new();
        for i in 0..200 {
            let msg = format!("[\"CLOSE\",\"subscription-{i:04}\"]").repeat(4);
            burst.extend(masked_frame(true, false, OP_TEXT, msg.as_bytes()));
        }
        tx.write_all(&burst).await.unwrap();
        let events = read_all(&mut rx, &mut parser, 200).await;
        assert_eq!(events.len(), 200);
        assert!(!parser.grown);
        assert_eq!(parser.buf.capacity(), READ_IDLE);
    }

    #[test]
    fn rejects_unmasked() {
        let mut c = WsParser::new(1 << 20, None);
        let mut f = Vec::new();
        WsEncoder::new(None).encode_frame(true, false, OP_TEXT, b"x", &mut f);
        assert!(c.feed(&f).is_err());
    }

    #[test]
    fn fragmented_message() {
        let mut c = WsParser::new(1 << 20, None);
        assert!(c
            .feed(&masked_frame(false, false, OP_TEXT, b"hel"))
            .unwrap()
            .is_empty());
        let events = c.feed(&masked_frame(true, false, OP_CONT, b"lo")).unwrap();
        match &events[0] {
            WsEvent::Message(MessageKind::Text, p) => assert_eq!(p, b"hello"),
            _ => panic!(),
        }
    }

    #[test]
    fn deflate_roundtrip() {
        let mut d = DeflateCtx::new(true);
        let msg = b"hello hello hello hello deflate me".repeat(10);
        let compressed = d.compress(&msg).unwrap();
        assert!(compressed.len() < msg.len());
        let mut d2 = InflateCtx::new(true);
        let back = d2.decompress(&compressed, 1 << 20).unwrap();
        assert_eq!(back, msg);
        // Context takeover: second message compresses against the first.
        let c2 = d.compress(b"hello hello hello hello deflate me").unwrap();
        let back2 = d2.decompress(&c2, 1 << 20).unwrap();
        assert_eq!(back2, b"hello hello hello hello deflate me");
    }

    /// Deterministic incompressible bytes, so only back-references to
    /// earlier messages can shrink them.
    fn noise(seed: u32, len: usize) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    #[test]
    fn deflater_is_created_on_use_and_released_when_idle() {
        let msg = b"[\"EOSE\",\"a-subscription-id\"]";
        let mut server = DeflateCtx::new(true);
        let mut client = InflateCtx::new(true);
        assert!(!server.is_allocated());
        let fresh = server.compress(msg).unwrap();
        assert!(server.is_allocated());
        let with_history = server.compress(msg).unwrap();
        assert!(with_history.len() < fresh.len(), "second copy refers back");
        assert_eq!(client.decompress(&fresh, 1 << 20).unwrap(), msg);
        assert_eq!(client.decompress(&with_history, 1 << 20).unwrap(), msg);

        server.release_idle(); // used since the last check: kept
        assert!(server.is_allocated());
        server.release_idle();
        assert!(!server.is_allocated());
        // A fresh compressor's output is valid in the client's ongoing
        // stream: takeover permits references back, it never requires them.
        let after = server.compress(msg).unwrap();
        assert_eq!(after, fresh);
        assert_eq!(client.decompress(&after, 1 << 20).unwrap(), msg);
    }

    #[test]
    fn inflater_replays_client_history_after_release() {
        let msg = br#"["REQ","feed",{"kinds":[1,6,7],"limit":100}]"#;
        let mut client = DeflateCtx::new(true);
        let mut server = InflateCtx::new(true);
        assert!(!server.is_allocated());
        let first = client.compress(msg).unwrap();
        assert_eq!(server.decompress(&first, 1 << 20).unwrap(), msg);
        assert!(server.is_allocated());
        server.release_idle();
        server.release_idle();
        assert!(!server.is_allocated());
        assert_eq!(server.history, msg);

        // The client still holds its context: the repeat is a back-reference
        // into the previous message, which only the replayed history resolves.
        let repeat = client.compress(msg).unwrap();
        assert!(repeat.len() < 12, "expected a back-reference: {repeat:?}");
        assert_eq!(server.decompress(&repeat, 1 << 20).unwrap(), msg);
    }

    #[test]
    fn inflater_history_wraps_at_the_window() {
        let msgs: Vec<Vec<u8>> = (1..=5).map(|seed| noise(seed, 12_000)).collect();
        let mut client = DeflateCtx::new(true);
        let mut server = InflateCtx::new(true);
        for msg in &msgs {
            let wire = client.compress(msg).unwrap();
            assert_eq!(&server.decompress(&wire, 1 << 20).unwrap(), msg);
        }
        assert_eq!(server.history.len(), WINDOW);
        server.release_idle();
        server.release_idle();
        // msgs[3] now starts 24,000 bytes back, across the ring's wrap point.
        for msg in [&msgs[3], &msgs[4]] {
            let wire = client.compress(msg).unwrap();
            assert!(wire.len() < 1_000, "expected back-references");
            assert_eq!(&server.decompress(&wire, 1 << 20).unwrap(), msg);
        }
    }

    #[test]
    fn inflater_history_is_the_latest_window() {
        let mut server = InflateCtx::new(true);
        let mut all = Vec::new();
        for (i, len) in [1, 100, 5_000, 40_000, 3, 32_767, 2, 32_768, 7_001]
            .into_iter()
            .enumerate()
        {
            let chunk = noise(i as u32 + 1, len);
            server.remember(&chunk);
            all.extend_from_slice(&chunk);
            let tail = &all[all.len().saturating_sub(WINDOW)..];
            let ring = [
                &server.history[server.head..],
                &server.history[..server.head],
            ]
            .concat();
            assert_eq!(ring, tail, "after chunk {i}");
            assert!(server.history.capacity() <= WINDOW);
        }
    }

    #[test]
    fn inflater_without_takeover_keeps_no_history() {
        let msg = br#"["CLOSE","feed"]"#;
        let mut client = DeflateCtx::new(false);
        let mut server = InflateCtx::new(false);
        for _ in 0..3 {
            let wire = client.compress(msg).unwrap();
            assert_eq!(server.decompress(&wire, 1 << 20).unwrap(), msg);
        }
        assert!(server.history.is_empty());
        server.release_idle();
        server.release_idle();
        assert!(!server.is_allocated());
        let wire = client.compress(msg).unwrap();
        assert_eq!(server.decompress(&wire, 1 << 20).unwrap(), msg);
    }

    #[test]
    fn inflate_limit_scales_with_the_wire_size() {
        let max = 2 * 1024 * 1024;
        // Any message may inflate to its allowance.
        assert_eq!(inflate_limit(10, max), inflate_allowance(max));
        // Past that, to its ratio, and never past the maximum.
        assert_eq!(inflate_limit(40_000, max), 40_000 * MAX_INFLATE_RATIO);
        assert_eq!(inflate_limit(1 << 20, max), max);
    }

    /// Compress `message` as a client would and frame it for the server.
    fn compressed_frame(message: &[u8]) -> Vec<u8> {
        let compressed = DeflateCtx::new(true).compress(message).unwrap();
        masked_frame(true, true, OP_TEXT, &compressed)
    }

    #[test]
    fn inflating_stops_one_byte_past_the_limit() {
        let compressed = DeflateCtx::new(false)
            .compress(&vec![b'a'; 1 << 20])
            .unwrap();
        let mut input = compressed;
        input.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
        let mut inner = flate2::Decompress::new(false);
        // Spare capacity far past the limit must not be filled.
        let mut out = Vec::with_capacity(1 << 20);
        let max_out = 100_000;
        let refused = inflate_into(&mut inner, &input, &mut out, max_out);
        assert!(matches!(refused, Err(WsError::MessageTooLarge)));
        assert_eq!(out.len(), max_out + 1);
    }

    #[test]
    fn the_largest_event_inflates_however_repetitive() {
        let max = 2 * 1024 * 1024;
        let mut server = WsParser::new(max, Some(InflateCtx::new(true)));
        let content = "a".repeat(1 << 20);
        let message = format!(r#"["EVENT",{{"content":"{content}"}}]"#);
        assert!(message.len() > max / 2 && message.len() <= inflate_allowance(max));
        let frame = compressed_frame(message.as_bytes());
        let event = server.feed(&frame).unwrap().pop();
        assert!(
            matches!(event, Some(WsEvent::Message(MessageKind::Text, body)) if body.len() == message.len())
        );
    }

    #[test]
    fn a_message_past_its_inflate_limit_is_refused() {
        let max = 2 * 1024 * 1024;
        let mut server = WsParser::new(max, Some(InflateCtx::new(true)));
        let message = vec![b'a'; max - 1];
        let frame = compressed_frame(&message);
        assert!(frame.len() * MAX_INFLATE_RATIO < max - 1);
        assert!(matches!(server.feed(&frame), Err(WsError::MessageTooLarge)));
    }

    #[test]
    fn deflate_via_codec() {
        let mut server = WsParser::new(1 << 20, Some(InflateCtx::new(true)));
        let mut client = WsEncoder::new(Some(DeflateCtx::new(true)));
        let wire = client
            .encode_message(MessageKind::Text, b"compressed payload")
            .unwrap();
        // Re-mask the wire payload for the server parser.
        let payload = wire[2..].to_vec();
        let mask = [9u8, 8, 7, 6];
        let mut masked = Vec::new();
        masked.push(0x80 | 0x40 | OP_TEXT);
        masked.push(0x80 | payload.len() as u8);
        masked.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            masked.push(b ^ mask[i % 4]);
        }
        let events = server.feed(&masked).unwrap();
        match &events[0] {
            WsEvent::Message(MessageKind::Text, p) => assert_eq!(p, b"compressed payload"),
            _ => panic!(),
        }
    }
}
