//! EventPayload encoding: type-byte prefix + optional zstd dictionary compression.

use crate::fbs::decode_compression_dictionary;
use crate::txn::{RoTxn, RwTxn};
use crate::DbError;
use std::collections::HashMap;
use zstd::dict::DecoderDictionary;

pub const PAYLOAD_RAW: u8 = 0x00;
pub const PAYLOAD_ZSTD: u8 = 0x01;

pub fn encode_raw_payload(json: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + json.len());
    v.push(PAYLOAD_RAW);
    v.extend_from_slice(json.as_bytes());
    v
}

pub fn encode_zstd_payload(dict_id: u32, compressed: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + compressed.len());
    v.push(PAYLOAD_ZSTD);
    v.extend_from_slice(&dict_id.to_ne_bytes());
    v.extend_from_slice(compressed);
    v
}

#[derive(Debug, Clone)]
pub enum PayloadView<'a> {
    Raw(&'a [u8]),
    Zstd { dict_id: u32, compressed: &'a [u8] },
}

pub fn parse_payload(raw: &[u8]) -> Result<PayloadView<'_>, DbError> {
    if raw.is_empty() {
        return Err(DbError::msg("empty event in EventPayload"));
    }
    match raw[0] {
        PAYLOAD_RAW => Ok(PayloadView::Raw(&raw[1..])),
        PAYLOAD_ZSTD => {
            if raw.len() < 5 {
                return Err(DbError::msg("EventPayload record too short to read dictId"));
            }
            let dict_id = u32::from_ne_bytes(raw[1..5].try_into().unwrap());
            Ok(PayloadView::Zstd {
                dict_id,
                compressed: &raw[5..],
            })
        }
        _ => Err(DbError::msg("Unexpected first byte in EventPayload")),
    }
}

pub struct Decompressor {
    dicts: HashMap<u32, DecoderDictionary<'static>>,
    buffer: Vec<u8>,
}

impl Default for Decompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Decompressor {
    pub fn new() -> Self {
        Self {
            dicts: HashMap::new(),
            buffer: Vec::new(),
        }
    }

    /// Grow the buffer to at least `n` bytes. It is zeroed as it grows, not
    /// before each decode, which with a 16 MiB bound cost more than verifying
    /// a signature.
    pub fn reserve(&mut self, n: usize) {
        if self.buffer.len() < n {
            self.buffer.resize(n, 0);
        }
    }

    pub fn decode<'a>(
        &'a mut self,
        txn: &RoTxn<'_>,
        raw: &'a [u8],
        max_event_size: usize,
    ) -> Result<&'a str, DbError> {
        match parse_payload(raw)? {
            PayloadView::Raw(json) => {
                std::str::from_utf8(json).map_err(|_| DbError::msg("payload not utf-8"))
            }
            PayloadView::Zstd {
                dict_id,
                compressed,
            } => self.decompress(txn, dict_id, compressed, max_event_size),
        }
    }

    pub fn decode_rw<'a>(
        &'a mut self,
        txn: &RwTxn<'_>,
        raw: &'a [u8],
        max_event_size: usize,
    ) -> Result<&'a str, DbError> {
        match parse_payload(raw)? {
            PayloadView::Raw(json) => {
                std::str::from_utf8(json).map_err(|_| DbError::msg("payload not utf-8"))
            }
            PayloadView::Zstd {
                dict_id,
                compressed,
            } => self.decompress_rw(txn, dict_id, compressed, max_event_size),
        }
    }

    fn load_dict_ro(&mut self, txn: &RoTxn<'_>, dict_id: u32) -> Result<(), DbError> {
        if self.dicts.contains_key(&dict_id) {
            return Ok(());
        }
        let raw = txn
            .get_u64(txn.env().dbis().compression_dictionary, dict_id as u64)?
            .ok_or_else(|| DbError::msg(format!("couldn't find dictId {dict_id}")))?;
        let rec = decode_compression_dictionary(raw)?;
        let dict = DecoderDictionary::copy(&rec.dict);
        self.dicts.insert(dict_id, dict);
        Ok(())
    }

    fn load_dict_rw(&mut self, txn: &RwTxn<'_>, dict_id: u32) -> Result<(), DbError> {
        if self.dicts.contains_key(&dict_id) {
            return Ok(());
        }
        let raw = txn
            .get_u64(txn.env().dbis().compression_dictionary, dict_id as u64)?
            .ok_or_else(|| DbError::msg(format!("couldn't find dictId {dict_id}")))?;
        let rec = decode_compression_dictionary(raw)?;
        let dict = DecoderDictionary::copy(&rec.dict);
        self.dicts.insert(dict_id, dict);
        Ok(())
    }

    fn decompress<'a>(
        &'a mut self,
        txn: &RoTxn<'_>,
        dict_id: u32,
        src: &[u8],
        max_event_size: usize,
    ) -> Result<&'a str, DbError> {
        self.load_dict_ro(txn, dict_id)?;
        self.reserve(max_event_size);
        let dict = self.dicts.get(&dict_id).unwrap();
        let mut decoder = zstd::bulk::Decompressor::with_prepared_dictionary(dict)
            .map_err(|e| DbError::msg(e.to_string()))?;
        let n = decoder
            .decompress_to_buffer(src, &mut self.buffer[..max_event_size])
            .map_err(|e| DbError::msg(format!("zstd decompression failed: {e}")))?;
        std::str::from_utf8(&self.buffer[..n]).map_err(|_| DbError::msg("payload not utf-8"))
    }

    fn decompress_rw<'a>(
        &'a mut self,
        txn: &RwTxn<'_>,
        dict_id: u32,
        src: &[u8],
        max_event_size: usize,
    ) -> Result<&'a str, DbError> {
        self.load_dict_rw(txn, dict_id)?;
        self.reserve(max_event_size);
        let dict = self.dicts.get(&dict_id).unwrap();
        let mut decoder = zstd::bulk::Decompressor::with_prepared_dictionary(dict)
            .map_err(|e| DbError::msg(e.to_string()))?;
        let n = decoder
            .decompress_to_buffer(src, &mut self.buffer[..max_event_size])
            .map_err(|e| DbError::msg(format!("zstd decompression failed: {e}")))?;
        std::str::from_utf8(&self.buffer[..n]).map_err(|_| DbError::msg("payload not utf-8"))
    }
}

pub fn get_event_json<'a>(
    txn: &'a RoTxn<'_>,
    decomp: &'a mut Decompressor,
    lev_id: u64,
    max_event_size: usize,
) -> Result<&'a str, DbError> {
    let raw = txn
        .get_u64(txn.env().dbis().event_payload, lev_id)?
        .ok_or_else(|| DbError::msg("couldn't find event in EventPayload"))?;
    decomp.decode(txn, raw, max_event_size)
}

pub fn event_json_owned(
    txn: &RoTxn<'_>,
    decomp: &mut Decompressor,
    lev_id: u64,
    max_event_size: usize,
) -> Result<String, DbError> {
    Ok(get_event_json(txn, decomp, lev_id, max_event_size)?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{insert_compression_dictionary, Env, EnvOptions};

    #[test]
    fn decoding_reuses_the_buffer_within_its_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let dict = br#"{"content":"xxxxxxxxxxxxxxxx","kind":1,"tags":[]}"#.repeat(32);
        let mut txn = env.begin_rw().unwrap();
        let dict_id =
            u32::try_from(insert_compression_dictionary(&mut txn, &dict).unwrap()).unwrap();
        txn.commit().unwrap();
        let payload = |json: &str| {
            let compressed = zstd::bulk::Compressor::with_dictionary(3, &dict)
                .unwrap()
                .compress(json.as_bytes())
                .unwrap();
            encode_zstd_payload(dict_id, &compressed)
        };
        let long = format!(r#"{{"content":"{}"}}"#, "y".repeat(1000));
        let short = r#"{"content":"short"}"#;

        let txn = env.begin_ro().unwrap();
        let mut decompressor = Decompressor::new();
        assert_eq!(
            decompressor.decode(&txn, &payload(&long), 4096).unwrap(),
            long
        );
        // A shorter payload after a longer one is only its own bytes.
        assert_eq!(
            decompressor.decode(&txn, &payload(short), 4096).unwrap(),
            short
        );
        // The bound holds after the buffer has grown past it.
        let err = decompressor.decode(&txn, &payload(&long), 512).unwrap_err();
        assert!(
            err.to_string().contains("zstd decompression failed"),
            "{err}"
        );
        assert_eq!(
            decompressor.decode(&txn, &payload(short), 512).unwrap(),
            short
        );
    }
}
