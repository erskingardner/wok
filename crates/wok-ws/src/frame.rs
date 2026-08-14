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

/// RFC 7692 inflater for one connection. Context is kept across messages
/// when `sliding` (strfry's `compression.slidingWindow`, default true).
pub struct InflateCtx {
    sliding: bool,
    inner: flate2::Decompress,
}

impl InflateCtx {
    pub fn new(sliding: bool) -> Self {
        Self {
            sliding,
            inner: flate2::Decompress::new(false),
        }
    }

    /// Inflate one message payload after re-appending the sync-flush marker.
    pub fn decompress(&mut self, payload: &[u8], max_out: usize) -> Result<Vec<u8>, WsError> {
        if !self.sliding {
            self.inner.reset(false);
        }
        let mut input = Vec::with_capacity(payload.len() + 4);
        input.extend_from_slice(payload);
        input.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
        let mut out = Vec::with_capacity(payload.len().saturating_mul(3).clamp(64, 1 << 20));
        let start_in = self.inner.total_in();
        loop {
            // Keep spare output capacity so "no progress" reliably means done.
            if out.capacity() - out.len() < 64 {
                out.reserve(32 * 1024);
            }
            let consumed = (self.inner.total_in() - start_in) as usize;
            let in_before = self.inner.total_in();
            let out_before = self.inner.total_out();
            self.inner
                .decompress_vec(&input[consumed..], &mut out, flate2::FlushDecompress::Sync)
                .map_err(|e| WsError::Inflate(e.to_string()))?;
            if out.len() > max_out {
                return Err(WsError::MessageTooLarge);
            }
            let progressed =
                self.inner.total_in() != in_before || self.inner.total_out() != out_before;
            if !progressed {
                break;
            }
        }
        Ok(out)
    }
}

/// RFC 7692 deflater for one connection.
pub struct DeflateCtx {
    sliding: bool,
    inner: flate2::Compress,
}

impl DeflateCtx {
    pub fn new(sliding: bool) -> Self {
        Self {
            sliding,
            inner: flate2::Compress::new(flate2::Compression::default(), false),
        }
    }

    /// Compress with Z_SYNC_FLUSH and strip the trailing `00 00 ff ff`.
    pub fn compress(&mut self, msg: &[u8]) -> Result<Vec<u8>, WsError> {
        if !self.sliding {
            self.inner.reset();
        }
        let mut out = Vec::with_capacity(msg.len() / 2 + 64);
        let start_in = self.inner.total_in();
        loop {
            if out.capacity() - out.len() < 64 {
                out.reserve(32 * 1024);
            }
            let consumed = (self.inner.total_in() - start_in) as usize;
            let in_before = self.inner.total_in();
            let out_before = self.inner.total_out();
            self.inner
                .compress_vec(&msg[consumed..], &mut out, flate2::FlushCompress::Sync)
                .map_err(|e| WsError::Deflate(e.to_string()))?;
            let all_consumed = (self.inner.total_in() - start_in) as usize == msg.len();
            if all_consumed && out.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
                break;
            }
            let progressed =
                self.inner.total_in() != in_before || self.inner.total_out() != out_before;
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
}

/// Which side of the connection this endpoint is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Server: clients must mask; we don't.
    Server,
    /// Client: servers must not mask; we must.
    Client,
}

/// Incremental frame parser + message assembler (read half).
pub struct WsParser {
    max_message: usize,
    buf: BytesMut,
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
            buf: BytesMut::with_capacity(16 * 1024),
            frag_opcode: None,
            frag_rsv1: false,
            frag: Vec::new(),
            inflater,
            role,
        }
    }

    /// Feed read bytes; returns events for every complete message/control
    /// frame parsed.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<WsEvent>, WsError> {
        self.buf.extend_from_slice(data);
        let mut events = Vec::new();
        self.drain_events_into(&mut events)?;
        Ok(events)
    }

    fn drain_events_into(&mut self, events: &mut Vec<WsEvent>) -> Result<(), WsError> {
        while let Some(frame) = self.try_parse_frame()? {
            if let Some(ev) = self.handle_frame(frame)? {
                events.push(ev);
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
            let max = self.max_message;
            match &mut self.inflater {
                Some(d) => d.decompress(&payload, max),
                None => Err(WsError::Protocol("RSV1 without extension")),
            }
        } else {
            Ok(payload)
        }
    }
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
        let opcode = match kind {
            MessageKind::Text => OP_TEXT,
            MessageKind::Binary => OP_BINARY,
        };
        let mut out = Vec::with_capacity(payload.len() + 14);
        if let Some(d) = &mut self.deflater {
            let compressed = d.compress(payload)?;
            self.encode_frame(true, true, opcode, &compressed, &mut out);
        } else {
            self.encode_frame(true, false, opcode, payload, &mut out);
        }
        Ok(out)
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
    read_events_into(stream, parser, &mut events).await?;
    Ok(events)
}

pub async fn read_events_into<S: AsyncRead + Unpin>(
    stream: &mut S,
    parser: &mut WsParser,
    events: &mut Vec<WsEvent>,
) -> Result<(), WsError> {
    events.clear();
    loop {
        // Read directly into the parser's retained buffer. The previous
        // stack-buffer path copied every inbound WebSocket byte a second time
        // before masking and JSON parsing.
        let n = stream.read_buf(&mut parser.buf).await?;
        if n == 0 {
            return Err(WsError::Protocol("eof"));
        }
        parser.drain_events_into(events)?;
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
